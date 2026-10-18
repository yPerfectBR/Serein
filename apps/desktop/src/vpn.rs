//! Moves the whole Serein process into (or out of) a private WireGuard network namespace by
//! restarting it through the privileged `serein-vpn` helper. Voice and video UDP leave through the
//! same tunnel as the gateway, so Discord sees one address. The administrator password is asked once
//! per login, by `pkexec`, to start a small per-login agent (`serein-vpn-agent`) inside the tunnel's
//! namespace; later launches ask that agent to start Serein there. Serein itself never runs as root.
use std::{
	ffi::OsString,
	path::{Path, PathBuf},
	process::{Command, Stdio},
};

pub const HELPER: &str = "/usr/local/libexec/serein-vpn";
pub const AGENT: &str = "/usr/local/libexec/serein-vpn-agent";
const AGENT_SOCKET: &str = "serein-vpn-agent.sock";
/// How long the password prompt may stay open before giving up.
const AGENT_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// Why the last start-up attempt to enter the tunnel failed (shown on the Network page).
static STARTUP_FAILURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn startup_failure() -> Option<String> {
	STARTUP_FAILURE
		.lock()
		.ok()
		.and_then(|reason| reason.clone())
}

pub fn helper_present() -> bool {
	Path::new(HELPER).is_file()
}

pub fn tool_path(name: &str) -> Option<PathBuf> {
	let path = std::env::var_os("PATH")?;
	std::env::split_paths(&path)
		.chain(["/usr/sbin", "/usr/bin"].map(PathBuf::from))
		.map(|dir| dir.join(name))
		.find(|candidate| candidate.is_file())
}

pub fn wireguard_tools_present() -> bool {
	tool_path("wg").is_some()
}

/// This process was started inside the tunnel's namespace by the helper.
pub fn active() -> bool {
	std::env::var_os("SEREIN_VPN_ACTIVE").is_some_and(|value| value == "1")
}

/// Environment worth carrying across the restart. The list is an allow-list because these values
/// pass through `pkexec` on the command line, where other local users could read them.
fn forwarded(key: &str, value: &str) -> bool {
	const PREFIXES: &[&str] = &[
		"XDG_",
		"WAYLAND_",
		"DBUS_",
		"LC_",
		"GDK_",
		"GTK_",
		"QT_",
		"WGPU_",
		"VK_",
		"MESA_",
		"__GL",
		"__NV",
		"__VK",
		"DRI_",
		"LIBVA_",
		"PULSE_",
		"PIPEWIRE_",
		"XCURSOR_",
		"RUST_",
		"SEREIN_",
	];
	const NAMES: &[&str] = &["DISPLAY", "LANG", "LANGUAGE", "TERM", "SHELL"];
	!key.starts_with("SEREIN_VPN_")
		&& (NAMES.contains(&key) || PREFIXES.iter().any(|prefix| key.starts_with(prefix)))
		&& value.len() <= 4096
		&& !value.contains(['\n', '\0'])
}

fn env_args() -> Vec<OsString> {
	let mut args = Vec::new();
	for (key, value) in std::env::vars() {
		if forwarded(&key, &value) {
			args.push(OsString::from("--env"));
			args.push(OsString::from(format!("{key}={value}")));
		}
	}
	args
}

/// Asks for permission before Serein closes (to leave the tunnel), so a cancelled or failed
/// prompt leaves the running app untouched.
pub fn authorize() -> Result<(), String> {
	if !helper_present() {
		return Err("the serein-vpn helper is not installed".to_owned());
	}
	let output = Command::new("pkexec")
		.arg(HELPER)
		.arg("ping")
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped())
		.output()
		.map_err(|error| format!("pkexec: {error}"))?;
	if output.status.success() {
		return Ok(());
	}
	// pkexec exits 126 when the prompt is dismissed or the password is wrong, 127 without an agent.
	Err(pkexec_failure(
		output.status.code(),
		&String::from_utf8_lossy(&output.stderr),
	))
}

fn pkexec_failure(code: Option<i32>, stderr: &str) -> String {
	if matches!(code, Some(126 | 127)) {
		return "administrator permission was not granted".to_owned();
	}
	let line = stderr
		.lines()
		.map(str::trim)
		.rfind(|line| !line.is_empty())
		.unwrap_or("the tunnel could not be created");
	line.trim_start_matches("serein-vpn: ").to_owned()
}

/// The command that starts Serein outside the tunnel (leaving it).
pub fn host_launch_args(exe: &Path) -> Vec<OsString> {
	let mut args = vec![
		OsString::from("pkexec"),
		OsString::from(HELPER),
		"host".into(),
	];
	args.extend(env_args());
	args.push("--".into());
	args.push(exe.as_os_str().to_owned());
	args
}

pub fn agent_present() -> bool {
	Path::new(AGENT).is_file()
}

fn agent_socket() -> Option<PathBuf> {
	std::env::var_os("XDG_RUNTIME_DIR").map(|runtime| PathBuf::from(runtime).join(AGENT_SOCKET))
}

#[cfg(unix)]
fn ask_agent_at(socket: &Path, message: &str) -> std::io::Result<String> {
	use std::io::{Read, Write};
	let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
	stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
	stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
	stream.write_all(message.as_bytes())?;
	stream.write_all(b"\n")?;
	let mut reply = String::new();
	stream.take(64).read_to_string(&mut reply)?;
	Ok(reply.trim().to_owned())
}
#[cfg(not(unix))]
fn ask_agent_at(_: &Path, _: &str) -> std::io::Result<String> {
	Err(std::io::Error::other("unsupported"))
}

fn ask_agent(message: &str) -> std::io::Result<String> {
	let socket = agent_socket().ok_or_else(|| std::io::Error::other("no runtime directory"))?;
	ask_agent_at(&socket, message)
}

fn ping_at(socket: &Path) -> bool {
	ask_agent_at(socket, "{\"ping\":true}").is_ok_and(|reply| reply == "ok")
}

pub fn agent_running() -> bool {
	agent_socket().is_some_and(|socket| ping_at(&socket))
}

/// Ends the per-login agent (its namespace is about to be replaced). Best effort.
pub fn stop_agent() {
	let _ = ask_agent("{\"quit\":true}");
}

/// Makes sure the per-login agent runs inside the tunnel for `config`. Starting it is the only step
/// that asks for the administrator password.
#[cfg(unix)]
pub fn ensure_agent(config: &Path, exe: &Path) -> Result<(), String> {
	use std::os::unix::process::CommandExt;
	if agent_running() {
		return Ok(());
	}
	if !helper_present() || !agent_present() {
		return Err("the serein-vpn helper is not installed".to_owned());
	}
	let mut command = Command::new("pkexec");
	command.arg(HELPER).arg("run").arg(config);
	command.args(env_args());
	command.arg("--").arg(AGENT).arg(exe);
	let mut child = command
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped())
		.process_group(0)
		.spawn()
		.map_err(|error| format!("pkexec: {error}"))?;
	let deadline = std::time::Instant::now() + AGENT_WAIT;
	while std::time::Instant::now() < deadline {
		if agent_running() {
			return Ok(());
		}
		if let Ok(Some(status)) = child.try_wait() {
			let mut stderr = String::new();
			if let Some(mut pipe) = child.stderr.take() {
				use std::io::Read;
				let _ = pipe.read_to_string(&mut stderr);
			}
			return Err(pkexec_failure(status.code(), &stderr));
		}
		std::thread::sleep(std::time::Duration::from_millis(200));
	}
	let _ = child.kill();
	Err("timed out waiting for administrator permission".to_owned())
}
#[cfg(not(unix))]
pub fn ensure_agent(_: &Path, _: &Path) -> Result<(), String> {
	Err("the tunnel is only supported on Linux".to_owned())
}

/// The one-line request that asks the agent to start Serein with this process's display and locale
/// environment (the same allow-list as for the restart helper).
fn spawn_message() -> String {
	let environment: std::collections::BTreeMap<String, String> = std::env::vars()
		.filter(|(key, value)| forwarded(key, value))
		.collect();
	serde_json::json!({ "env": environment }).to_string()
}

fn spawn_at(socket: &Path) -> Result<(), String> {
	match ask_agent_at(socket, &spawn_message()) {
		Ok(reply) if reply == "ok" => Ok(()),
		Ok(_) => Err("the tunnel agent refused to start Serein".to_owned()),
		Err(error) => Err(format!("the tunnel agent is not reachable ({error})")),
	}
}

/// Asks the agent to start Serein inside the tunnel.
pub fn request_spawn() -> Result<(), String> {
	let socket = agent_socket().ok_or("no runtime directory")?;
	spawn_at(&socket)
}

/// At startup, with a WireGuard configuration saved: hand over to a Serein that runs inside the
/// tunnel (asking for the administrator password only if no agent exists yet for this login) and
/// exit. If that fails, Serein keeps starting directly and the Network page says why.
pub fn enter_tunnel_at_startup() {
	if active()
		|| std::env::var_os("SEREIN_NO_VPN").is_some()
		|| net_route::env_overrides()
		|| std::env::args_os().count() != 1
		|| !helper_present()
		|| !agent_present()
		|| tool_path("pkexec").is_none()
		|| !wireguard_tools_present()
	{
		return;
	}
	let Some(config) = net_route::tunnel::config_path().filter(|path| path.is_file()) else {
		return;
	};
	let Ok(exe) = std::env::current_exe() else {
		return;
	};
	match ensure_agent(&config, &exe).and_then(|()| request_spawn()) {
		Ok(()) => std::process::exit(0),
		Err(reason) => {
			eprintln!("Serein: not entering the WireGuard tunnel: {reason}");
			if let Ok(mut failure) = STARTUP_FAILURE.lock() {
				*failure = Some(reason);
			}
		}
	}
}

/// Installs `wireguard-tools` with the system package manager; the system asks for permission.
pub fn install_wireguard_tools() -> Result<(), String> {
	if wireguard_tools_present() {
		return Ok(());
	}
	if !Path::new("/usr/bin/pacman").exists() || !Path::new("/usr/bin/pkexec").exists() {
		return Err("install wireguard-tools with your package manager".to_owned());
	}
	let status = Command::new("pkexec")
		.args(["pacman", "-S", "--needed", "--noconfirm", "wireguard-tools"])
		.stdin(Stdio::null())
		.status()
		.map_err(|error| error.to_string())?;
	if status.success() && wireguard_tools_present() {
		Ok(())
	} else {
		Err("the installation was cancelled or failed".to_owned())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_display_and_locale_style_variables_are_forwarded() {
		for key in [
			"WAYLAND_DISPLAY",
			"XDG_RUNTIME_DIR",
			"DBUS_SESSION_BUS_ADDRESS",
			"LANG",
			"DISPLAY",
			"WGPU_BACKEND",
		] {
			assert!(forwarded(key, "x"), "{key}");
		}
		for key in [
			"AWS_SECRET_ACCESS_KEY",
			"GITHUB_TOKEN",
			"LD_PRELOAD",
			"SEREIN_VPN_ACTIVE",
			"PATH",
			"HOME",
		] {
			assert!(!forwarded(key, "x"), "{key}");
		}
		assert!(!forwarded("LANG", "a\nb") && !forwarded("LANG", &"x".repeat(5000)));
	}

	#[test]
	fn leaving_the_tunnel_runs_the_host_command_with_the_executable_last() {
		let args = host_launch_args(Path::new("/usr/local/bin/serein"));
		assert_eq!(&args[..3], ["pkexec", HELPER, "host"]);
		assert_eq!(args[args.len() - 2..], ["--", "/usr/local/bin/serein"]);
	}

	#[test]
	fn pkexec_failures_are_explained() {
		for code in [126, 127] {
			assert_eq!(
				pkexec_failure(Some(code), ""),
				"administrator permission was not granted"
			);
		}
		assert_eq!(
			pkexec_failure(Some(2), "x\nserein-vpn: invalid endpoint\n"),
			"invalid endpoint"
		);
		assert_eq!(pkexec_failure(None, ""), "the tunnel could not be created");
	}

	#[cfg(unix)]
	#[test]
	fn the_agent_protocol_is_one_json_line_answered_with_ok() {
		use std::io::{BufRead, BufReader, Write};
		let dir = std::env::temp_dir().join(format!("serein-agent-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let listener = std::os::unix::net::UnixListener::bind(dir.join(AGENT_SOCKET)).unwrap();
		let server = std::thread::spawn(move || {
			let mut received = Vec::new();
			for _ in 0..3 {
				let (stream, _) = listener.accept().unwrap();
				let mut line = String::new();
				BufReader::new(&stream).read_line(&mut line).unwrap();
				received.push(line);
				(&stream).write_all(b"ok\n").unwrap();
			}
			received
		});
		let socket = dir.join(AGENT_SOCKET);
		assert!(ping_at(&socket));
		assert!(spawn_at(&socket).is_ok());
		assert_eq!(ask_agent_at(&socket, "{\"quit\":true}").unwrap(), "ok");
		let received = server.join().unwrap();
		assert_eq!(received[0].trim(), "{\"ping\":true}");
		assert!(received[1].starts_with("{\"env\":{") && received[1].ends_with("}}\n"));
		assert_eq!(received[2].trim(), "{\"quit\":true}");
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn authorising_without_the_helper_reports_it() {
		if !helper_present() {
			assert!(authorize().unwrap_err().contains("not installed"));
		}
	}
}
