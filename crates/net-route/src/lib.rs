//! One configurable network route for every Discord transport.
//!
//! `SEREIN_PROXY` (or `~/.config/serein/proxy`; an `http://` or `socks5://` URL) sends the gateway, voice signalling, REST and
//! CDN traffic through a proxy; unset or `direct` keeps the normal connection. The route is read
//! once at startup and never falls back to a direct connection: an invalid setting makes every
//! connection fail instead. Hostnames are resolved by the proxy, so DNS does not leak.
//! Voice media (UDP) is not proxied.
use std::{
	fmt,
	io::{Error, ErrorKind, Result as IoResult},
	net::IpAddr,
	sync::{Arc, RwLock},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
	net::TcpStream,
};
use tokio_tungstenite::{
	MaybeTlsStream, WebSocketStream, client_async_tls_with_config, connect_async_with_config,
	tungstenite::{Error as WsError, client::IntoClientRequest, protocol::WebSocketConfig},
};
use url::Url;
use zeroize::Zeroizing;

/// Environment variable that selects the route.
pub const ENV: &str = "SEREIN_PROXY";
const MAX_URL: usize = 2048;
const MAX_CREDENTIAL: usize = 255;
const MAX_HEADERS: usize = 8 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
	Socks5,
	HttpConnect,
}

#[derive(Clone)]
pub struct Proxy {
	kind: Kind,
	host: String,
	port: u16,
	auth: Option<Arc<(Zeroizing<String>, Zeroizing<String>)>>,
}

// Never print credentials, even in debug output.
impl fmt::Debug for Proxy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Proxy")
			.field("kind", &self.kind)
			.field("host", &self.host)
			.field("port", &self.port)
			.field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
			.finish()
	}
}

impl PartialEq for Proxy {
	fn eq(&self, other: &Self) -> bool {
		self.kind == other.kind
			&& self.host == other.host
			&& self.port == other.port
			&& self.auth.as_deref().map(|a| (a.0.as_str(), a.1.as_str()))
				== other.auth.as_deref().map(|a| (a.0.as_str(), a.1.as_str()))
	}
}
impl Eq for Proxy {}

impl Proxy {
	/// Builds a proxy from separate fields, validating them like [`Proxy::parse`].
	pub fn new(
		kind: Kind,
		host: &str,
		port: u16,
		credentials: Option<(&str, &str)>,
	) -> Result<Self, &'static str> {
		const REJECTED: &str = "Proxy address rejected";
		let host = host.trim().trim_start_matches('[').trim_end_matches(']');
		if host.is_empty()
			|| host.len() > 253
			|| port == 0
			|| host.chars().any(|c| {
				c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '\\' | '?' | '#')
			}) {
			return Err(REJECTED);
		}
		let auth = match credentials {
			None => None,
			Some((user, pass)) => {
				if user.is_empty()
					|| user.len() > MAX_CREDENTIAL
					|| pass.len() > MAX_CREDENTIAL
					|| user.contains(':')
					|| user.chars().chain(pass.chars()).any(char::is_control)
				{
					return Err("Proxy credentials rejected");
				}
				Some(Arc::new((
					Zeroizing::new(user.into()),
					Zeroizing::new(pass.into()),
				)))
			}
		};
		Ok(Self {
			kind,
			host: host.to_owned(),
			port,
			auth,
		})
	}

	/// The same proxy with credentials attached (used when they come from the OS credential store).
	pub fn with_credentials(&self, user: &str, pass: &str) -> Result<Self, &'static str> {
		Self::new(self.kind, &self.host, self.port, Some((user, pass)))
	}

	/// `socks5://host:port` or `http://host:port`, never including credentials.
	pub fn endpoint(&self) -> String {
		let scheme = match self.kind {
			Kind::Socks5 => "socks5",
			Kind::HttpConnect => "http",
		};
		format!("{scheme}://{}:{}", self.host_for_url(), self.port)
	}

	pub fn kind(&self) -> Kind {
		self.kind
	}
	pub fn host(&self) -> &str {
		&self.host
	}
	pub fn port(&self) -> u16 {
		self.port
	}
	pub fn has_credentials(&self) -> bool {
		self.auth.is_some()
	}

	/// Parses `socks5://`, `socks5h://` or `http://` with a mandatory host and port.
	pub fn parse(value: &str) -> Result<Self, &'static str> {
		const REJECTED: &str = "Proxy URL rejected: use socks5://host:port or http://host:port";
		if value.len() > MAX_URL || value.bytes().any(|b| b.is_ascii_control() || b == b' ') {
			return Err(REJECTED);
		}
		let url = Url::parse(value).map_err(|_| REJECTED)?;
		let kind = match url.scheme() {
			"socks5" | "socks5h" => Kind::Socks5,
			"http" => Kind::HttpConnect,
			_ => return Err(REJECTED),
		};
		let host = url.host_str().filter(|h| !h.is_empty()).ok_or(REJECTED)?;
		let host = host
			.trim_start_matches('[')
			.trim_end_matches(']')
			.to_owned();
		// `Url::port` hides a scheme-default port, so require it to be written explicitly.
		let port = url.port().ok_or(REJECTED)?;
		if (url.path() != "/" && !url.path().is_empty())
			|| url.query().is_some()
			|| url.fragment().is_some()
		{
			return Err(REJECTED);
		}
		let auth = if url.username().is_empty() && url.password().is_none() {
			None
		} else {
			let decode = |raw: &str| {
				percent_decode_str(raw)
					.decode_utf8()
					.map(|s| Zeroizing::new(s.into_owned()))
					.map_err(|_| "Proxy credentials rejected")
			};
			let user = decode(url.username())?;
			let pass = decode(url.password().unwrap_or(""))?;
			if user.is_empty()
				|| user.len() > MAX_CREDENTIAL
				|| pass.len() > MAX_CREDENTIAL
				|| user.contains(':')
				|| user.chars().chain(pass.chars()).any(char::is_control)
			{
				return Err("Proxy credentials rejected");
			}
			Some(Arc::new((user, pass)))
		};
		Ok(Self {
			kind,
			host,
			port,
			auth,
		})
	}

	/// The proxy as a `reqwest` URL (`socks5h` so the proxy resolves names).
	fn reqwest_url(&self) -> Option<Url> {
		let scheme = match self.kind {
			Kind::Socks5 => "socks5h",
			Kind::HttpConnect => "http",
		};
		let mut url = Url::parse(&format!("{scheme}://placeholder:{}", self.port)).ok()?;
		url.set_host(Some(&self.host_for_url())).ok()?;
		if let Some(auth) = &self.auth {
			url.set_username(&auth.0).ok()?;
			url.set_password(Some(&auth.1)).ok()?;
		}
		Some(url)
	}

	fn host_for_url(&self) -> String {
		if self.host.contains(':') {
			format!("[{}]", self.host)
		} else {
			self.host.clone()
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum State {
	Direct,
	Proxy(Proxy),
	/// The setting could not be parsed. Connections fail rather than leak directly.
	Invalid(&'static str),
}

impl State {
	/// `None`/empty/`direct` keeps the normal connection.
	pub fn parse(value: Option<&str>) -> Self {
		match value.map(str::trim) {
			None | Some("") => Self::Direct,
			Some(v) if v.eq_ignore_ascii_case("direct") => Self::Direct,
			Some(v) => match Proxy::parse(v) {
				Ok(proxy) => Self::Proxy(proxy),
				Err(reason) => Self::Invalid(reason),
			},
		}
	}
}

impl State {
	/// A one-line, credential-free description for logs and diagnostics.
	pub fn describe(&self) -> String {
		match self {
			Self::Direct => "direct".into(),
			Self::Proxy(p) => format!(
				"{} {}:{}{}",
				match p.kind {
					Kind::Socks5 => "socks5",
					Kind::HttpConnect => "http-connect",
				},
				p.host,
				p.port,
				if p.auth.is_some() {
					" (with credentials)"
				} else {
					""
				}
			),
			Self::Invalid(reason) => format!("invalid: {reason}"),
		}
	}

	/// The first non-empty, non-comment line of a proxy file. A file holding credentials must be
	/// private (`mode & 0o077 == 0`) when the platform reports a mode.
	pub fn from_file_contents(contents: &str, mode: Option<u32>) -> Self {
		if contents.len() > MAX_URL * 2 {
			return Self::Invalid("Proxy file is too large");
		}
		let line = contents
			.lines()
			.map(str::trim)
			.find(|line| !line.is_empty() && !line.starts_with('#'));
		match line {
			None => Self::Direct,
			Some(line) => {
				if line.contains('@') && mode.is_some_and(|mode| mode & 0o077 != 0) {
					return Self::Invalid(
						"Proxy file holds credentials: make it private (chmod 600)",
					);
				}
				Self::parse(Some(line))
			}
		}
	}
}

pub fn config_dir() -> Option<std::path::PathBuf> {
	config_file().and_then(|p| p.parent().map(std::path::Path::to_path_buf))
}

/// `$XDG_CONFIG_HOME/serein/proxy`, else `$HOME/.config/serein/proxy`.
pub fn config_file() -> Option<std::path::PathBuf> {
	let base = std::env::var_os("XDG_CONFIG_HOME")
		.filter(|v| !v.is_empty())
		.map(std::path::PathBuf::from)
		.or_else(|| {
			std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
		})?;
	Some(base.join("serein").join("proxy"))
}

/// Environment first, then the proxy file; no setting means direct. Call before any connection.
pub fn init() -> State {
	if std::env::var_os(ENV).is_some() {
		return init_from_env();
	}
	let Some(path) = config_file() else {
		set(State::Direct);
		return state();
	};
	let resolved = match std::fs::metadata(&path) {
		Err(error) if error.kind() == ErrorKind::NotFound => State::Direct,
		Err(_) => State::Invalid("Proxy file could not be read"),
		Ok(meta) if !meta.is_file() || meta.len() > (MAX_URL as u64) * 2 => {
			State::Invalid("Proxy file is not a small regular file")
		}
		Ok(meta) => {
			#[cfg(unix)]
			let mode = {
				use std::os::unix::fs::PermissionsExt;
				Some(meta.permissions().mode())
			};
			#[cfg(not(unix))]
			let mode = None;
			match std::fs::read_to_string(&path) {
				Ok(contents) => {
					KEYRING_WANTED.store(
						contents.lines().any(|line| line.trim() == KEYRING_MARKER),
						std::sync::atomic::Ordering::Relaxed,
					);
					State::from_file_contents(&contents, mode)
				}
				Err(_) => State::Invalid("Proxy file could not be read"),
			}
		}
	};
	set(resolved);
	state()
}

/// Marker line: the proxy's username and password live in the OS credential store, not in the file.
pub const KEYRING_MARKER: &str = "# credentials: keyring";
static KEYRING_WANTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when the proxy file asked for credentials from the OS credential store (set by [`init`]).
pub fn keyring_credentials_wanted() -> bool {
	KEYRING_WANTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// True when `SEREIN_PROXY` is set, which overrides the proxy file and the settings page.
pub fn env_overrides() -> bool {
	std::env::var_os(ENV).is_some()
}

/// Writes the proxy file (private directory and file, replaced atomically). The file never holds
/// credentials: with `keyring` it carries [`KEYRING_MARKER`] so the app loads them from the OS
/// credential store. `None` removes the file (direct connection).
pub fn write_config_file(proxy: Option<&Proxy>, keyring: bool) -> IoResult<()> {
	let path = config_file()
		.ok_or_else(|| Error::new(ErrorKind::NotFound, "no configuration directory"))?;
	write_config_file_at(&path, proxy, keyring)
}

/// [`write_config_file`] for an explicit path.
pub fn write_config_file_at(
	path: &std::path::Path,
	proxy: Option<&Proxy>,
	keyring: bool,
) -> IoResult<()> {
	let Some(proxy) = proxy else {
		return match std::fs::remove_file(path) {
			Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
			_ => Ok(()),
		};
	};
	let mut contents = String::from("# Serein network route (written by Settings > Network)\n");
	contents.push_str(&proxy.endpoint());
	contents.push('\n');
	if keyring {
		contents.push_str(KEYRING_MARKER);
		contents.push('\n');
	}
	write_private_file(path, contents.as_bytes())
}

/// Replaces `path` atomically with `contents`, creating a private (0700) parent directory and a
/// private (0600) file.
pub fn write_private_file(path: &std::path::Path, contents: &[u8]) -> IoResult<()> {
	let dir = path
		.parent()
		.ok_or_else(|| Error::new(ErrorKind::NotFound, "no configuration directory"))?;
	std::fs::create_dir_all(dir)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
	}
	let temporary = dir.join(format!(
		".{}.tmp",
		path.file_name().and_then(|n| n.to_str()).unwrap_or("route")
	));
	{
		use std::io::Write;
		#[cfg(unix)]
		let mut file = {
			use std::os::unix::fs::OpenOptionsExt;
			std::fs::OpenOptions::new()
				.write(true)
				.create(true)
				.truncate(true)
				.mode(0o600)
				.open(&temporary)?
		};
		#[cfg(not(unix))]
		let mut file = std::fs::File::create(&temporary)?;
		file.write_all(contents)?;
		file.sync_all()?;
	}
	std::fs::rename(&temporary, path)
}

static ROUTE: RwLock<State> = RwLock::new(State::Direct);

/// Reads `SEREIN_PROXY` and makes it the process route. Call before any connection is opened.
pub fn init_from_env() -> State {
	let value = match std::env::var(ENV) {
		Ok(value) => Some(value),
		Err(std::env::VarError::NotPresent) => None,
		// Never echo the value: it may contain credentials.
		Err(std::env::VarError::NotUnicode(_)) => {
			set(State::Invalid("SEREIN_PROXY is not valid Unicode"));
			return state();
		}
	};
	set(State::parse(value.as_deref()));
	state()
}

pub fn set(state: State) {
	*ROUTE.write().unwrap_or_else(|e| e.into_inner()) = state;
}

pub fn state() -> State {
	ROUTE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Applies the route to a `reqwest` client: nothing when direct, the proxy when set, and a
/// refused local address when the setting is invalid so requests can never go out directly.
pub fn apply(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
	match state() {
		State::Direct => builder,
		State::Proxy(proxy) => match proxy
			.reqwest_url()
			.and_then(|u| reqwest::Proxy::all(u).ok())
		{
			Some(p) => builder.no_proxy().proxy(p),
			None => blackhole(builder),
		},
		State::Invalid(_) => blackhole(builder),
	}
}

fn blackhole(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
	match reqwest::Proxy::all("http://127.0.0.1:1") {
		Ok(p) => builder.no_proxy().proxy(p),
		Err(_) => builder.no_proxy(),
	}
}

/// Opens a TCP stream to `host:port` through the current route.
pub async fn connect_tcp(host: &str, port: u16) -> IoResult<TcpStream> {
	match state() {
		State::Direct => TcpStream::connect((host, port)).await,
		State::Proxy(proxy) => connect_tcp_via(&proxy, host, port).await,
		State::Invalid(reason) => Err(Error::other(reason)),
	}
}

pub async fn connect_tcp_via(proxy: &Proxy, host: &str, port: u16) -> IoResult<TcpStream> {
	let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await?;
	stream.set_nodelay(true)?;
	match proxy.kind {
		Kind::Socks5 => socks5(&mut stream, host, port, proxy.auth.as_deref()).await?,
		Kind::HttpConnect => http_connect(&mut stream, host, port, proxy.auth.as_deref()).await?,
	}
	Ok(stream)
}

/// Drop-in for `connect_async_with_config` that honours the route.
pub async fn connect_ws(
	url: &str,
	config: Option<WebSocketConfig>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WsError> {
	connect_ws_with(&state(), url, config).await
}

/// Like [`connect_ws`] for an explicit route, so a candidate setting can be tested before it is saved.
pub async fn connect_ws_with(
	route: &State,
	url: &str,
	config: Option<WebSocketConfig>,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WsError> {
	let proxy = match route.clone() {
		State::Direct => {
			return connect_async_with_config(url, config, false)
				.await
				.map(|(socket, _)| socket);
		}
		State::Proxy(proxy) => proxy,
		State::Invalid(reason) => return Err(WsError::Io(Error::other(reason))),
	};
	let parsed = Url::parse(url)
		.map_err(|_| WsError::Url(tokio_tungstenite::tungstenite::error::UrlError::NoHostName))?;
	let host = parsed
		.host_str()
		.ok_or(WsError::Url(
			tokio_tungstenite::tungstenite::error::UrlError::NoHostName,
		))?
		.trim_start_matches('[')
		.trim_end_matches(']')
		.to_owned();
	let port = parsed.port_or_known_default().ok_or(WsError::Url(
		tokio_tungstenite::tungstenite::error::UrlError::UnsupportedUrlScheme,
	))?;
	let stream = connect_tcp_via(&proxy, &host, port)
		.await
		.map_err(WsError::Io)?;
	let request = url.into_client_request()?;
	client_async_tls_with_config(request, stream, config, None)
		.await
		.map(|(socket, _)| socket)
}

/// Where [`probe_gateway`] connects.
pub const GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

/// Opens the Discord gateway through `route` and waits for its first frame (opcode 10, Hello).
/// It sends no credentials and signs in to nothing. Returns the time to the Hello frame.
pub async fn probe_gateway(route: &State) -> Result<std::time::Duration, String> {
	use futures_util::StreamExt;
	use std::time::Duration;
	use tokio_tungstenite::tungstenite::Message;

	let started = std::time::Instant::now();
	let short =
		|text: String| -> String { text.chars().filter(|c| !c.is_control()).take(160).collect() };
	let mut socket = tokio::time::timeout(
		Duration::from_secs(15),
		connect_ws_with(route, GATEWAY_URL, None),
	)
	.await
	.map_err(|_| "timed out".to_owned())?
	.map_err(|error| short(error.to_string()))?;
	match tokio::time::timeout(Duration::from_secs(10), socket.next()).await {
		Ok(Some(Ok(Message::Text(text)))) if text.contains("\"op\":10") => Ok(started.elapsed()),
		Ok(Some(Ok(_))) => Err("unexpected first frame".to_owned()),
		Ok(Some(Err(error))) => Err(short(error.to_string())),
		Ok(None) => Err("closed before the first frame".to_owned()),
		Err(_) => Err("no answer from the gateway".to_owned()),
	}
}

type Credentials = (Zeroizing<String>, Zeroizing<String>);

async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
	stream: &mut S,
	host: &str,
	port: u16,
	auth: Option<&Credentials>,
) -> IoResult<()> {
	let bad = |message: &str| Error::new(ErrorKind::InvalidData, message.to_owned());
	if host.is_empty() || host.len() > 255 {
		return Err(bad("SOCKS5 target host is not valid"));
	}
	let methods: &[u8] = if auth.is_some() {
		&[0x00, 0x02]
	} else {
		&[0x00]
	};
	let mut hello = vec![0x05, methods.len() as u8];
	hello.extend_from_slice(methods);
	stream.write_all(&hello).await?;
	let mut choice = [0_u8; 2];
	stream.read_exact(&mut choice).await?;
	if choice[0] != 0x05 {
		return Err(bad("Proxy did not answer as SOCKS5"));
	}
	match choice[1] {
		0x00 => {}
		0x02 => {
			let (user, pass) = auth.ok_or_else(|| bad("SOCKS5 proxy requires credentials"))?;
			let mut request = vec![0x01, user.len() as u8];
			request.extend_from_slice(user.as_bytes());
			request.push(pass.len() as u8);
			request.extend_from_slice(pass.as_bytes());
			stream.write_all(&request).await?;
			let mut status = [0_u8; 2];
			stream.read_exact(&mut status).await?;
			if status[1] != 0x00 {
				return Err(Error::new(
					ErrorKind::PermissionDenied,
					"SOCKS5 login rejected",
				));
			}
		}
		_ => return Err(bad("SOCKS5 proxy rejected the offered authentication")),
	}
	let mut request = vec![0x05, 0x01, 0x00];
	match host.parse::<IpAddr>() {
		Ok(IpAddr::V4(ip)) => {
			request.push(0x01);
			request.extend_from_slice(&ip.octets());
		}
		Ok(IpAddr::V6(ip)) => {
			request.push(0x04);
			request.extend_from_slice(&ip.octets());
		}
		Err(_) => {
			request.push(0x03);
			request.push(host.len() as u8);
			request.extend_from_slice(host.as_bytes());
		}
	}
	request.extend_from_slice(&port.to_be_bytes());
	stream.write_all(&request).await?;
	let mut reply = [0_u8; 4];
	stream.read_exact(&mut reply).await?;
	if reply[0] != 0x05 {
		return Err(bad("Proxy did not answer as SOCKS5"));
	}
	if reply[1] != 0x00 {
		return Err(Error::new(
			ErrorKind::ConnectionRefused,
			format!("SOCKS5 connect failed (code {})", reply[1]),
		));
	}
	let tail = match reply[3] {
		0x01 => 4 + 2,
		0x04 => 16 + 2,
		0x03 => {
			let mut len = [0_u8; 1];
			stream.read_exact(&mut len).await?;
			len[0] as usize + 2
		}
		_ => return Err(bad("SOCKS5 reply has an unknown address type")),
	};
	let mut rest = vec![0_u8; tail];
	stream.read_exact(&mut rest).await?;
	Ok(())
}

async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
	stream: &mut S,
	host: &str,
	port: u16,
	auth: Option<&Credentials>,
) -> IoResult<()> {
	if host.is_empty() || host.bytes().any(|b| b.is_ascii_control() || b == b' ') {
		return Err(Error::new(
			ErrorKind::InvalidInput,
			"CONNECT target host is not valid",
		));
	}
	let target = if host.contains(':') {
		format!("[{host}]:{port}")
	} else {
		format!("{host}:{port}")
	};
	let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
	if let Some((user, pass)) = auth {
		let token = Zeroizing::new(STANDARD.encode(format!("{}:{}", user.as_str(), pass.as_str())));
		request.push_str(&format!(
			"Proxy-Authorization: Basic {}\r\n",
			token.as_str()
		));
	}
	request.push_str("\r\n");
	stream.write_all(request.as_bytes()).await?;
	// Read byte by byte: anything past the header block belongs to the tunnel.
	let mut head = Vec::with_capacity(256);
	let mut byte = [0_u8; 1];
	while !head.ends_with(b"\r\n\r\n") {
		if head.len() >= MAX_HEADERS {
			return Err(Error::new(
				ErrorKind::InvalidData,
				"Proxy response headers too large",
			));
		}
		if stream.read(&mut byte).await? == 0 {
			return Err(Error::new(
				ErrorKind::UnexpectedEof,
				"Proxy closed the connection",
			));
		}
		head.push(byte[0]);
	}
	let status = head
		.split(|b| *b == b'\r')
		.next()
		.and_then(|line| std::str::from_utf8(line).ok())
		.and_then(|line| line.split_whitespace().nth(1))
		.and_then(|code| code.parse::<u16>().ok());
	match status {
		Some(200..=299) => Ok(()),
		Some(407) => Err(Error::new(
			ErrorKind::PermissionDenied,
			"Proxy authentication required",
		)),
		Some(code) => Err(Error::new(
			ErrorKind::ConnectionRefused,
			format!("Proxy refused CONNECT (HTTP {code})"),
		)),
		None => Err(Error::new(
			ErrorKind::InvalidData,
			"Proxy sent an invalid response",
		)),
	}
}

pub mod tunnel;

#[cfg(test)]
mod tests;
