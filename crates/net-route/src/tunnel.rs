//! Importing a WireGuard configuration for the whole-process tunnel: Serein restarts inside a
//! private network namespace (see `packaging/linux/vpn/serein-vpn`) whose only route is this
//! tunnel, so gateway, REST, voice and video all leave through the same address. The provider's
//! file is validated against a small allow-list and rewritten privately (0600) in Serein's
//! configuration directory; the privileged helper validates it again before using it.
use std::{
	io::{Error, ErrorKind, Read},
	path::{Path, PathBuf},
};

/// Largest configuration accepted; real provider files are well under 2 KiB.
pub const MAX_CONFIG: u64 = 16 * 1024;
const INTERFACE_KEYS: &[&str] = &["privatekey", "address", "dns", "mtu", "listenport"];
const PEER_KEYS: &[&str] = &[
	"publickey",
	"presharedkey",
	"endpoint",
	"allowedips",
	"persistentkeepalive",
];

#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
	TooLarge,
	NotText,
	/// A section other than `[Interface]` and `[Peer]`, such as a tunnel or `PostUp` hook.
	UnsupportedSection(String),
	UnsupportedKey(String),
	Missing(&'static str),
	BadValue(&'static str),
	Io(ErrorKind),
}
impl std::fmt::Display for ImportError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::TooLarge => f.write_str("the file is larger than 16 KiB"),
			Self::NotText => f.write_str("the file is not text"),
			Self::UnsupportedSection(name) => write!(f, "unsupported section [{name}]"),
			Self::UnsupportedKey(name) => write!(f, "unsupported setting {name}"),
			Self::Missing(what) => write!(f, "missing {what}"),
			Self::BadValue(what) => write!(f, "invalid {what}"),
			Self::Io(kind) => write!(f, "could not read or write the file ({kind})"),
		}
	}
}

/// What the page shows about an imported configuration. Never includes the private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
	pub endpoint: String,
}

/// WireGuard keys are 32 bytes in standard base64: 43 characters and one `=`.
fn valid_key(value: &str) -> bool {
	value.len() == 44
		&& value.ends_with('=')
		&& value[..43]
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn clean_value(value: &str) -> bool {
	!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

/// Validates `text` and returns the sanitized configuration (without the SOCKS5 section) with a
/// summary. Comments and blank lines are dropped; only allow-listed keys survive.
pub fn sanitize(text: &str) -> Result<(String, Summary), ImportError> {
	#[derive(PartialEq, Clone, Copy)]
	enum Section {
		None,
		Interface,
		Peer,
	}
	let mut section = Section::None;
	let (mut interface, mut peers) = (0_u32, 0_u32);
	let (mut private_key, mut address, mut public_key, mut allowed) = (false, false, false, false);
	let mut endpoint: Option<String> = None;
	let mut out = String::new();
	for raw in text.lines() {
		let line = raw.trim();
		if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
			continue;
		}
		if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
			match name.trim().to_ascii_lowercase().as_str() {
				"interface" => {
					interface += 1;
					section = Section::Interface;
					out.push_str("[Interface]\n");
				}
				"peer" => {
					peers += 1;
					section = Section::Peer;
					out.push_str("\n[Peer]\n");
				}
				other => {
					return Err(ImportError::UnsupportedSection(
						other.chars().take(32).collect(),
					));
				}
			}
			continue;
		}
		let (key, value) = line.split_once('=').ok_or(ImportError::BadValue("line"))?;
		let (key, value) = (key.trim(), value.trim());
		let lower = key.to_ascii_lowercase();
		let allowed_keys = match section {
			Section::None => return Err(ImportError::BadValue("line outside a section")),
			Section::Interface => INTERFACE_KEYS,
			Section::Peer => PEER_KEYS,
		};
		if !allowed_keys.contains(&lower.as_str()) {
			return Err(ImportError::UnsupportedKey(key.chars().take(32).collect()));
		}
		if !clean_value(value) {
			return Err(ImportError::BadValue("value"));
		}
		match (section, lower.as_str()) {
			(Section::Interface, "privatekey") => {
				if !valid_key(value) {
					return Err(ImportError::BadValue("PrivateKey"));
				}
				private_key = true;
			}
			(Section::Interface, "address") => address = true,
			(Section::Peer, "publickey") => {
				if !valid_key(value) {
					return Err(ImportError::BadValue("PublicKey"));
				}
				public_key = true;
			}
			(Section::Peer, "presharedkey") if !valid_key(value) => {
				return Err(ImportError::BadValue("PresharedKey"));
			}
			(Section::Peer, "endpoint") => {
				if !value.contains(':') {
					return Err(ImportError::BadValue("Endpoint"));
				}
				endpoint = Some(value.to_owned());
			}
			(Section::Peer, "allowedips") => allowed = true,
			_ => {}
		}
		out.push_str(&format!("{key} = {value}\n"));
	}
	if interface != 1 {
		return Err(ImportError::Missing("[Interface]"));
	}
	if peers != 1 {
		return Err(ImportError::Missing("a single [Peer]"));
	}
	if !private_key {
		return Err(ImportError::Missing("PrivateKey"));
	}
	if !address {
		return Err(ImportError::Missing("Address"));
	}
	if !public_key {
		return Err(ImportError::Missing("PublicKey"));
	}
	if !allowed {
		return Err(ImportError::Missing("AllowedIPs"));
	}
	let endpoint = endpoint.ok_or(ImportError::Missing("Endpoint"))?;
	Ok((out, Summary { endpoint }))
}

/// Reads and validates `source`, then writes the private tunnel configuration to `destination`.
pub fn import(source: &Path, destination: &Path) -> Result<Summary, ImportError> {
	let mut file = std::fs::File::open(source).map_err(|e| ImportError::Io(e.kind()))?;
	let meta = file.metadata().map_err(|e| ImportError::Io(e.kind()))?;
	if !meta.is_file() || meta.len() > MAX_CONFIG {
		return Err(ImportError::TooLarge);
	}
	let mut bytes = Vec::new();
	(&mut file)
		.take(MAX_CONFIG + 1)
		.read_to_end(&mut bytes)
		.map_err(|e| ImportError::Io(e.kind()))?;
	if bytes.len() as u64 > MAX_CONFIG {
		return Err(ImportError::TooLarge);
	}
	let text = String::from_utf8(bytes).map_err(|_| ImportError::NotText)?;
	let (sanitized, summary) = sanitize(&text)?;
	crate::write_private_file(destination, sanitized.as_bytes())
		.map_err(|e| ImportError::Io(e.kind()))?;
	Ok(summary)
}

/// The imported configuration's peer endpoint, for display.
pub fn summarize(path: &Path) -> Option<Summary> {
	let text = std::fs::read_to_string(path).ok()?;
	let mut in_peer = false;
	for line in text.lines().map(str::trim) {
		if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
			in_peer = name.trim().eq_ignore_ascii_case("peer");
		} else if in_peer && line.to_ascii_lowercase().starts_with("endpoint") {
			return line.split_once('=').map(|(_, v)| Summary {
				endpoint: v.trim().to_owned(),
			});
		}
	}
	None
}

/// Where the tunnel configuration lives: next to the proxy file.
pub fn config_path() -> Option<PathBuf> {
	crate::config_dir().map(|dir| dir.join("wireguard.conf"))
}

/// Removes the imported configuration (it holds the private key). Missing is fine.
pub fn remove_config() -> std::io::Result<()> {
	match config_path() {
		Some(path) => match std::fs::remove_file(path) {
			Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
			_ => Ok(()),
		},
		None => Err(Error::new(
			ErrorKind::NotFound,
			"no configuration directory",
		)),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	fn sample() -> String {
		format!(
			"# Bouncing = 0\n# NAT-PMP (Port Forwarding) = off\n[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n# NL-FREE#1\nPublicKey = {KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 185.107.56.22:51820\n"
		)
	}

	#[test]
	fn a_provider_file_is_accepted_and_reduced_to_allow_listed_settings() {
		let (clean, summary) = sanitize(&sample()).unwrap();
		assert_eq!(summary.endpoint, "185.107.56.22:51820");
		assert!(clean.starts_with("[Interface]\n") && clean.contains("\n[Peer]\n"));
		assert!(!clean.contains('#'), "comments are dropped: {clean}");
		for key in [
			"PrivateKey",
			"Address",
			"DNS",
			"PublicKey",
			"AllowedIPs",
			"Endpoint",
		] {
			assert!(clean.contains(key), "{key} kept");
		}
	}

	#[test]
	fn unsupported_sections_keys_and_values_are_rejected() {
		let with = |extra: &str| sample() + extra;
		assert!(matches!(
			sanitize(&with("[Socks5]\nBindAddress = 0.0.0.0:1080\n")),
			Err(ImportError::UnsupportedSection(_))
		));
		assert!(matches!(
			sanitize(&with("[TCPClientTunnel]\nBindAddress = 127.0.0.1:1\n")),
			Err(ImportError::UnsupportedSection(_))
		));
		assert!(matches!(
			sanitize(&sample().replace("DNS = 10.2.0.1", "PostUp = curl evil")),
			Err(ImportError::UnsupportedKey(_))
		));
		assert!(matches!(
			sanitize(&sample().replace("Endpoint = 185.107.56.22:51820", "Endpoint = nohost")),
			Err(ImportError::BadValue("Endpoint"))
		));
		assert!(matches!(
			sanitize(&sample().replace(KEY, "short")),
			Err(ImportError::BadValue(_))
		));
		assert!(matches!(
			sanitize(&sample().replace("10.2.0.1", "10.2.0.1\u{7}")),
			Err(ImportError::BadValue("value"))
		));
		assert!(matches!(
			sanitize("PrivateKey = x\n"),
			Err(ImportError::BadValue(_))
		));
		assert!(
			sanitize(&with("[Peer]\nPublicKey = x\n")).is_err(),
			"second peer"
		);
		assert!(matches!(
			sanitize(&sample().replace("[Peer]", "[Peer]\nbroken")),
			Err(ImportError::BadValue("line"))
		));
	}

	#[test]
	fn required_settings_are_reported_by_name() {
		for (needle, expected) in [
			("PrivateKey", "PrivateKey"),
			("Address", "Address"),
			("AllowedIPs", "AllowedIPs"),
			("Endpoint", "Endpoint"),
		] {
			let broken: String = sample()
				.lines()
				.filter(|line| !line.trim_start().starts_with(needle))
				.collect::<Vec<_>>()
				.join("\n");
			let error = sanitize(&broken).unwrap_err();
			assert!(error.to_string().contains(expected), "{needle}: {error}");
		}
		assert_eq!(
			sanitize("").unwrap_err(),
			ImportError::Missing("[Interface]")
		);
	}

	#[test]
	fn import_writes_a_private_configuration_that_can_be_summarised() {
		let dir = std::env::temp_dir().join(format!("net-route-import-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let source = dir.join("provider.conf");
		std::fs::write(&source, sample()).unwrap();
		let destination = dir.join("serein").join("wireguard.conf");

		let summary = import(&source, &destination).unwrap();
		assert_eq!(summary.endpoint, "185.107.56.22:51820");
		let written = std::fs::read_to_string(&destination).unwrap();
		assert!(
			!written.contains("Socks5") && !written.contains('#'),
			"{written}"
		);
		assert_eq!(
			summarize(&destination).unwrap().endpoint,
			"185.107.56.22:51820"
		);
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			assert_eq!(
				std::fs::metadata(&destination)
					.unwrap()
					.permissions()
					.mode() & 0o777,
				0o600
			);
		}
		// Importing again replaces the file.
		import(&source, &destination).unwrap();

		// Oversized and non-text sources are refused before anything is written.
		let big = dir.join("big.conf");
		std::fs::write(&big, vec![b'a'; MAX_CONFIG as usize + 1]).unwrap();
		assert_eq!(
			import(&big, &dir.join("x.conf")).unwrap_err(),
			ImportError::TooLarge
		);
		let binary = dir.join("binary.conf");
		std::fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
		assert_eq!(
			import(&binary, &dir.join("x.conf")).unwrap_err(),
			ImportError::NotText
		);
		assert!(!dir.join("x.conf").exists());
		assert!(import(&dir.join("missing.conf"), &dir.join("x.conf")).is_err());
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_dual_stack_provider_file_is_accepted() {
		let text = sample().replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
		assert!(sanitize(&text).is_ok());
	}
}
