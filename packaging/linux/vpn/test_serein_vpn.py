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


if __name__ == "__main__":
    unittest.main()
