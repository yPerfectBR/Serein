//! Network-route proxy credentials live only in the OS credential store, never in the proxy file.
use crate::{ACCOUNT, CredentialError, entry, forget_entry};
use zeroize::Zeroizing;

pub struct Credentials {
	/// `socks5://host:port` or `http://host:port`; credentials are only used for this endpoint.
	pub endpoint: String,
	pub username: Zeroizing<String>,
	pub password: Zeroizing<String>,
}
impl std::fmt::Debug for Credentials {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("RouteCredentials([redacted])")
	}
}
impl Credentials {
	pub fn validate(&self) -> Result<(), CredentialError> {
		let url = url::Url::parse(&self.endpoint).map_err(|_| CredentialError::Invalid)?;
		if self.endpoint.len() > 2048
			|| !matches!(url.scheme(), "http" | "socks5")
			|| url.host_str().is_none()
			|| url.port().is_none()
			|| !url.username().is_empty()
			|| url.password().is_some()
			// Non-special schemes such as socks5 report an empty path, http reports "/".
			|| !(url.path().is_empty() || url.path() == "/")
			|| url.query().is_some()
			|| url.fragment().is_some()
			|| self.username.is_empty()
			|| self.username.len() > 255
			|| self.password.len() > 255
			|| self.username.contains(':')
			|| self
				.username
				.chars()
				.chain(self.password.chars())
				.any(char::is_control)
		{
			return Err(CredentialError::Invalid);
		}
		Ok(())
	}
}
fn name() -> String {
	format!("{ACCOUNT}.network-route")
}
pub fn load() -> Result<Option<Credentials>, CredentialError> {
	let raw = match entry(&name())?.get_password() {
		Ok(value) => Zeroizing::new(value),
		Err(keyring_core::Error::NoEntry) => return Ok(None),
		Err(_) => return Err(CredentialError::Unavailable),
	};
	if raw.len() > 4096 {
		return Err(CredentialError::Invalid);
	}
	let (endpoint, username, password): (String, String, String) =
		serde_json::from_str(&raw).map_err(|_| CredentialError::Invalid)?;
	let credentials = Credentials {
		endpoint,
		username: Zeroizing::new(username),
		password: Zeroizing::new(password),
	};
	credentials.validate()?;
	Ok(Some(credentials))
}
pub fn save(credentials: &Credentials) -> Result<(), CredentialError> {
	credentials.validate()?;
	let raw = Zeroizing::new(
		serde_json::to_string(&(
			&credentials.endpoint,
			credentials.username.as_str(),
			credentials.password.as_str(),
		))
		.map_err(|_| CredentialError::Invalid)?,
	);
	entry(&name())?
		.set_password(&raw)
		.map_err(|_| CredentialError::Unavailable)
}
pub fn forget() -> Result<(), CredentialError> {
	forget_entry(&name())
}

#[cfg(test)]
mod tests {
	use super::*;
	fn value(endpoint: &str, user: &str, pass: &str) -> Credentials {
		Credentials {
			endpoint: endpoint.into(),
			username: Zeroizing::new(user.into()),
			password: Zeroizing::new(pass.into()),
		}
	}
	#[test]
	fn credentials_are_bounded_endpoint_bound_and_debug_is_redacted() {
		let ok = value("socks5://127.0.0.1:1080", "owner", "synthetic-password");
		assert!(ok.validate().is_ok());
		assert!(
			value("http://proxy.example:8080", "owner", "x")
				.validate()
				.is_ok()
		);
		assert!(!format!("{ok:?}").contains("synthetic-password"));
		for bad in [
			value("socks5://127.0.0.1", "owner", "x"),
			value("https://proxy.example:443", "owner", "x"),
			value("socks5://u:p@127.0.0.1:1080", "owner", "x"),
			value("socks5://127.0.0.1:1080/path", "owner", "x"),
			value("socks5://127.0.0.1:1080", "", "x"),
			value("socks5://127.0.0.1:1080", "bad:name", "x"),
			value("socks5://127.0.0.1:1080", "owner", &"x".repeat(256)),
			value("socks5://127.0.0.1:1080", "owner", "bad\u{7}"),
		] {
			assert_eq!(bad.validate(), Err(CredentialError::Invalid));
		}
	}
}
