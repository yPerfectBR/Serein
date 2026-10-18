"""Offline checks for the serein-vpn parser and command handling (no root, no network changes)."""
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest

loader = importlib.machinery.SourceFileLoader("serein_vpn", os.path.join(os.path.dirname(__file__), "serein-vpn"))
spec = importlib.util.spec_from_loader("serein_vpn", loader)
vpn = importlib.util.module_from_spec(spec)
loader.exec_module(vpn)

KEY = "A" * 43 + "="
SAMPLE = f"""[Interface]
PrivateKey = {KEY}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = {KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.107.56.22:51820
PersistentKeepalive = 25
"""


class Parse(unittest.TestCase):
    def test_provider_file(self):
        parsed = vpn.parse(SAMPLE)
        self.assertEqual(parsed["peer"]["endpoint"], "185.107.56.22:51820")
        self.assertEqual(len(parsed["allowed"]), 2)

    def test_rejections(self):
        for bad in (
            SAMPLE + "[Socks5]\nBindAddress = 0.0.0.0:1\n",
            SAMPLE.replace("DNS = 10.2.0.1", "PostUp = curl evil"),
            SAMPLE.replace("PrivateKey", "Table"),
            SAMPLE.replace(KEY, "short"),
            SAMPLE.replace("51820", "0"),
            SAMPLE.replace("0.0.0.0/0, ::/0", "nonsense"),
            SAMPLE + "[Peer]\nPublicKey = x\n",
            SAMPLE.replace("Address = 10.2.0.2/32\n", ""),
            SAMPLE.replace("10.2.0.1", "10.2.0.1\x07"),
            "PrivateKey = x\n",
        ):
            with self.assertRaises(vpn.Fail, msg=bad):
                vpn.parse(bad)

    def test_hostname_endpoint_allowed_only_when_plain(self):
        self.assertTrue(vpn.parse(SAMPLE.replace("185.107.56.22", "node.example.com")))
        with self.assertRaises(vpn.Fail):
            vpn.parse(SAMPLE.replace("185.107.56.22", "bad host;rm"))


class Files(unittest.TestCase):
    def test_reading_refuses_symlinks_oversize_and_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "a.conf")
            open(real, "w").write(SAMPLE)
            self.assertEqual(vpn.read_config(real, os.getuid()), SAMPLE)
            link = os.path.join(directory, "link.conf")
            os.symlink(real, link)
            with self.assertRaises(vpn.Fail):
                vpn.read_config(link, os.getuid())
            big = os.path.join(directory, "big.conf")
            open(big, "w").write("a" * (vpn.MAX_CONFIG + 1))
            with self.assertRaises(vpn.Fail):
                vpn.read_config(big, os.getuid())
            binary = os.path.join(directory, "bin.conf")
            open(binary, "wb").write(b"\xff\xfe\x00")
            with self.assertRaises(vpn.Fail):
                vpn.read_config(binary, os.getuid())
            with self.assertRaises(vpn.Fail):
                vpn.read_config(real, os.getuid() + 1)  # owned by someone else


class Commands(unittest.TestCase):
    def test_env_split(self):
        env, command = vpn.split_command(["--env", "A=1", "--env", "B=x=y", "--", "serein", "-x"])
        self.assertEqual(env, {"A": "1", "B": "x=y"})
        self.assertEqual(command, ["serein", "-x"])
        for bad in (["--env", "LD_PRELOAD=/x", "--", "a"], ["--env", "SEREIN_VPN_ACTIVE=0", "--", "a"],
                    ["--env", "1BAD=x", "--", "a"], ["--env", "A=1"], ["--"], []):
            with self.assertRaises(vpn.Fail, msg=bad):
                vpn.split_command(bad)

    def test_caller_must_come_from_sudo_or_pkexec(self):
        saved = {k: os.environ.pop(k, None) for k in ("PKEXEC_UID", "SUDO_UID")}
        try:
            with self.assertRaises(vpn.Fail):
                vpn.caller()
            os.environ["SUDO_UID"] = "0"
            with self.assertRaises(vpn.Fail):
                vpn.caller()
            os.environ["SUDO_UID"] = str(os.getuid())
            self.assertEqual(vpn.caller().pw_uid, os.getuid())
        finally:
            for key, value in saved.items():
                os.environ.pop(key, None)
                if value is not None:
                    os.environ[key] = value


agent_loader = importlib.machinery.SourceFileLoader("serein_vpn_agent", os.path.join(os.path.dirname(__file__), "serein-vpn-agent"))
agent_spec = importlib.util.spec_from_loader("serein_vpn_agent", agent_loader)
agent = importlib.util.module_from_spec(agent_spec)
agent_loader.exec_module(agent)


class Agent(unittest.TestCase):
    def test_environment_is_filtered(self):
        base = {"HOME": "/h", "AWS_SECRET_ACCESS_KEY": "x", "LD_PRELOAD": "/x", "SEREIN_VPN_ACTIVE": "1",
                "SEREIN_VPN_ENDPOINT": "1.2.3.4:5", "WAYLAND_DISPLAY": "wayland-0"}
        env = agent.filter_env({"XDG_RUNTIME_DIR": "/run/user/1", "GITHUB_TOKEN": "t",
                                "SEREIN_VPN_ACTIVE": "0", "LANG": "x\ny"}, base)
        self.assertEqual(env["HOME"], "/h")
        self.assertEqual(env["WAYLAND_DISPLAY"], "wayland-0")
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1")
        self.assertEqual(env["SEREIN_VPN_ACTIVE"], "1", "the tunnel markers come from the agent only")
        for key in ("AWS_SECRET_ACCESS_KEY", "LD_PRELOAD", "GITHUB_TOKEN", "LANG"):
            self.assertNotIn(key, env)

    def test_only_the_serein_executable_can_be_served(self):
        with tempfile.TemporaryDirectory() as directory:
            other = os.path.join(directory, "other")
            open(other, "w").write("#!/bin/sh\n")
            os.chmod(other, 0o755)
            for bad in (other, "serein", os.path.join(directory, "missing", "serein")):
                with self.assertRaises(SystemExit):
                    agent.check_executable(bad)

    def test_a_request_starts_the_program_and_quit_stops_the_agent(self):
        import json, socket, subprocess, sys, time
        with tempfile.TemporaryDirectory() as directory:
            runtime = os.path.join(directory, "run")
            os.mkdir(runtime, 0o700)
            marker = os.path.join(directory, "started")
            exe = os.path.join(directory, "serein")
            open(exe, "w").write("#!/bin/sh\necho \"$WAYLAND_DISPLAY|$AWS_KEY|$SEREIN_VPN_ACTIVE\" > " + marker + "\n")
            os.chmod(exe, 0o755)
            env = dict(os.environ, XDG_RUNTIME_DIR=runtime, XDG_STATE_HOME=os.path.join(directory, "state"),
                       SEREIN_VPN_AGENT_NO_TUNNEL_CHECK="1", SEREIN_VPN_ACTIVE="1")
            process = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "serein-vpn-agent"), exe], env=env)
            path = os.path.join(runtime, "serein-vpn-agent.sock")
            try:
                for _ in range(50):
                    if os.path.exists(path):
                        break
                    time.sleep(0.1)
                self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

                def ask(message):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(5)
                        client.connect(path)
                        client.sendall(json.dumps(message).encode() + b"\n")
                        return client.recv(64)

                self.assertEqual(ask({"ping": True}), b"ok\n")
                self.assertEqual(ask("not an object"), b"error\n")
                self.assertEqual(ask({"env": {"WAYLAND_DISPLAY": "wayland-9", "AWS_KEY": "secret"}}), b"ok\n")
                for _ in range(50):
                    if os.path.exists(marker):
                        break
                    time.sleep(0.1)
                self.assertEqual(open(marker).read().strip(), "wayland-9||1")
                self.assertEqual(ask({"quit": True}), b"ok\n")
                process.wait(timeout=10)
                self.assertFalse(os.path.exists(path), "the socket is removed on exit")
            finally:
                if process.poll() is None:
                    process.kill()


if __name__ == "__main__":
    unittest.main()
