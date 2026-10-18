//! Moves the whole Serein process into (or out of) a private WireGuard network namespace by
//! restarting it through the privileged `serein-vpn` helper. Voice and video UDP leave through the
//! same tunnel as the gateway, so Discord sees one address. The helper is started with `pkexec`,
//! which asks for the administrator password; Serein itself never runs as root.
use std::{
	ffi::OsString,
	path::{Path, PathBuf},
	process::{Command, Stdio},
};

pub const HELPER: &str = "/usr/local/libexec/serein-vpn";

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

/// Asks for permission (and builds the tunnel) before Serein closes, so a cancelled or failed
/// prompt leaves the running app untouched. `None` only authorises leaving the tunnel.
pub fn authorize(config: Option<&Path>) -> Result<(), String> {
	if !helper_present() {
		return Err("the serein-vpn helper is not installed".to_owned());
	}
	let mut command = Command::new("pkexec");
	command.arg(HELPER);
	match config {
		Some(path) => command.arg("up").arg(path),
		None => command.arg("ping"),
	};
	let output = command
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped())
		.output()
		.map_err(|error| format!("pkexec: {error}"))?;
	if output.status.success() {
		return Ok(());
	}
	// pkexec exits 126 when the prompt is dismissed or the password is wrong.
	if matches!(output.status.code(), Some(126 | 127)) {
		return Err("administrator permission was not granted".to_owned());
	}
	let message = String::from_utf8_lossy(&output.stderr);
	let line = message
		.lines()
		.map(str::trim)
		.rfind(|line| !line.is_empty())
		.unwrap_or("the tunnel could not be created");
	Err(line.trim_start_matches("serein-vpn: ").to_owned())
}

/// The command that starts the new Serein: inside the tunnel for `Some(config)`, outside for `None`.
pub fn launch_args(config: Option<&Path>, exe: &Path) -> Vec<OsString> {
	let mut args = vec![OsString::from("pkexec"), OsString::from(HELPER)];
	match config {
		Some(path) => {
			args.push("run".into());
			args.push(path.as_os_str().to_owned());
		}
		None => args.push("host".into()),
	}
	args.extend(env_args());
	args.push("--".into());
	args.push(exe.as_os_str().to_owned());
	args
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
	fn launch_commands_run_the_helper_with_the_executable_last() {
		let exe = Path::new("/usr/local/bin/serein");
		let inside = launch_args(
			Some(Path::new("/home/u/.config/serein/wireguard.conf")),
			exe,
		);
		assert_eq!(
			&inside[..4],
			[
				"pkexec",
				HELPER,
				"run",
				"/home/u/.config/serein/wireguard.conf"
			]
		);
		assert_eq!(inside[inside.len() - 2..], ["--", "/usr/local/bin/serein"]);
		let outside = launch_args(None, exe);
		assert_eq!(&outside[..3], ["pkexec", HELPER, "host"]);
		assert_eq!(outside.last().unwrap(), "/usr/local/bin/serein");
	}

	#[test]
	fn authorising_without_the_helper_reports_it() {
		if !helper_present() {
			assert!(authorize(None).unwrap_err().contains("not installed"));
		}
	}
}
