use super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::OnceLock;
use tokio::{
	io::{AsyncReadExt, AsyncWriteExt, duplex},
	net::TcpListener,
	sync::Mutex,
};
use tokio_tungstenite::tungstenite::Message;

// The route is process-wide; tests that change it run one at a time.
fn route_lock() -> &'static Mutex<()> {
	static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
	LOCK.get_or_init(|| Mutex::const_new(()))
}

fn creds(user: &str, pass: &str) -> Credentials {
	(Zeroizing::new(user.into()), Zeroizing::new(pass.into()))
}

#[test]
fn parses_socks5_and_http_proxies_with_an_explicit_port() {
	let socks = Proxy::parse("socks5://127.0.0.1:9050").unwrap();
	assert_eq!(
		(
			socks.kind(),
			socks.host(),
			socks.port(),
			socks.has_credentials()
		),
		(Kind::Socks5, "127.0.0.1", 9050, false)
	);
	assert_eq!(
		Proxy::parse("socks5h://localhost:1080").unwrap().kind(),
		Kind::Socks5
	);
	let http = Proxy::parse("http://proxy.example:8080/").unwrap();
	assert_eq!((http.kind(), http.port()), (Kind::HttpConnect, 8080));
	assert_eq!(Proxy::parse("socks5://[::1]:1080").unwrap().host(), "::1");
}

#[test]
fn rejects_unusable_proxy_urls() {
	for value in [
		"",
		"socks5://127.0.0.1",
		"http://proxy.example",
		"https://proxy.example:443",
		"socks4://127.0.0.1:1080",
		"ftp://proxy.example:21",
		"socks5://127.0.0.1:1080/path",
		"socks5://127.0.0.1:1080?x=1",
		"socks5://127.0.0.1:1080#frag",
		"socks5://127.0.0.1:1080 ",
		"socks5://127.0.0.1:1080\n",
		"not a url",
	] {
		assert!(Proxy::parse(value).is_err(), "{value:?} must be rejected");
	}
	assert!(Proxy::parse(&format!("socks5://{}:1080", "x".repeat(MAX_URL))).is_err());
}

#[test]
fn credentials_are_decoded_bounded_and_never_printed() {
	let proxy = Proxy::parse("socks5://us%40er:p%3Ass@127.0.0.1:1080").unwrap();
	assert!(proxy.has_credentials());
	let auth = proxy.auth.as_deref().unwrap();
	assert_eq!((auth.0.as_str(), auth.1.as_str()), ("us@er", "p:ss"));
	let debug = format!("{proxy:?} {:?}", State::Proxy(proxy.clone()));
	assert!(
		!debug.contains("us@er") && !debug.contains("p:ss"),
		"{debug}"
	);
	assert!(debug.contains("<redacted>"));
	assert!(Proxy::parse("socks5://:secret@127.0.0.1:1080").is_err());
	assert!(Proxy::parse(&format!("socks5://{}:x@127.0.0.1:1080", "u".repeat(256))).is_err());
	assert!(Proxy::parse("socks5://us%3Aer:x@127.0.0.1:1080").is_err());
	assert!(Proxy::parse("socks5://us%00er:x@127.0.0.1:1080").is_err());
}

#[test]
fn state_defaults_to_direct_and_fails_closed_on_bad_input() {
	assert_eq!(State::parse(None), State::Direct);
	assert_eq!(State::parse(Some("")), State::Direct);
	assert_eq!(State::parse(Some("  Direct ")), State::Direct);
	assert!(matches!(
		State::parse(Some("socks5://127.0.0.1:1")),
		State::Proxy(_)
	));
	assert!(matches!(State::parse(Some("garbage")), State::Invalid(_)));
}

#[tokio::test]
async fn socks5_sends_the_hostname_to_the_proxy_without_authentication() {
	let (mut client, mut server) = duplex(1024);
	let proxy = tokio::spawn(async move {
		let mut hello = [0_u8; 3];
		server.read_exact(&mut hello).await.unwrap();
		assert_eq!(hello, [0x05, 0x01, 0x00]);
		server.write_all(&[0x05, 0x00]).await.unwrap();
		let mut head = [0_u8; 5];
		server.read_exact(&mut head).await.unwrap();
		assert_eq!(
			&head[..4],
			&[0x05, 0x01, 0x00, 0x03],
			"domain addressing, so the proxy resolves"
		);
		let mut rest = vec![0_u8; head[4] as usize + 2];
		server.read_exact(&mut rest).await.unwrap();
		assert_eq!(&rest[..head[4] as usize], b"gateway.discord.gg");
		assert_eq!(&rest[head[4] as usize..], &443_u16.to_be_bytes());
		server
			.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
			.await
			.unwrap();
		server.write_all(b"tunnel").await.unwrap();
	});
	socks5(&mut client, "gateway.discord.gg", 443, None)
		.await
		.unwrap();
	let mut payload = [0_u8; 6];
	client.read_exact(&mut payload).await.unwrap();
	assert_eq!(
		&payload, b"tunnel",
		"bytes after the reply belong to the tunnel"
	);
	proxy.await.unwrap();
}

#[tokio::test]
async fn socks5_username_password_and_ip_literals() {
	let (mut client, mut server) = duplex(1024);
	let proxy = tokio::spawn(async move {
		let mut hello = [0_u8; 4];
		server.read_exact(&mut hello).await.unwrap();
		assert_eq!(hello, [0x05, 0x02, 0x00, 0x02]);
		server.write_all(&[0x05, 0x02]).await.unwrap();
		let mut auth = [0_u8; 1 + 1 + 3 + 1 + 4];
		server.read_exact(&mut auth).await.unwrap();
		assert_eq!(&auth, b"\x01\x03bob\x04pass");
		server.write_all(&[0x01, 0x00]).await.unwrap();
		let mut request = [0_u8; 4 + 4 + 2];
		server.read_exact(&mut request).await.unwrap();
		assert_eq!(
			&request[..8],
			&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7],
			"IPv4 literal"
		);
		server
			.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
			.await
			.unwrap();
	});
	let auth = creds("bob", "pass");
	socks5(&mut client, "203.0.113.7", 80, Some(&auth))
		.await
		.unwrap();
	proxy.await.unwrap();

	let (mut client, mut server) = duplex(1024);
	let proxy = tokio::spawn(async move {
		let mut buffer = [0_u8; 3 + 4 + 16 + 2];
		server.read_exact(&mut buffer[..3]).await.unwrap();
		server.write_all(&[0x05, 0x00]).await.unwrap();
		server.read_exact(&mut buffer[3..]).await.unwrap();
		assert_eq!(buffer[6], 0x04, "IPv6 literal");
		server.write_all(&[0x05, 0x00, 0x00, 0x04]).await.unwrap();
		server.write_all(&[0_u8; 18]).await.unwrap();
	});
	socks5(&mut client, "2001:db8::1", 80, None).await.unwrap();
	proxy.await.unwrap();
}

#[tokio::test]
async fn socks5_reports_refusals_and_bad_logins() {
	let (mut client, mut server) = duplex(1024);
	tokio::spawn(async move {
		let mut sink = [0_u8; 64];
		let _ = server.read(&mut sink).await;
		server.write_all(&[0x05, 0x00]).await.unwrap();
		let _ = server.read(&mut sink).await;
		server
			.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
			.await
			.unwrap();
	});
	let error = socks5(&mut client, "example.invalid", 443, None)
		.await
		.unwrap_err();
	assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
	assert!(error.to_string().contains("code 5"));

	let (mut client, mut server) = duplex(1024);
	tokio::spawn(async move {
		let mut sink = [0_u8; 64];
		let _ = server.read(&mut sink).await;
		server.write_all(&[0x05, 0x02]).await.unwrap();
		let _ = server.read(&mut sink).await;
		server.write_all(&[0x01, 0x01]).await.unwrap();
	});
	let auth = creds("bob", "wrong");
	let error = socks5(&mut client, "example.invalid", 443, Some(&auth))
		.await
		.unwrap_err();
	assert_eq!(error.kind(), ErrorKind::PermissionDenied);

	let (mut client, mut server) = duplex(1024);
	tokio::spawn(async move {
		let mut sink = [0_u8; 64];
		let _ = server.read(&mut sink).await;
		server.write_all(&[0x05, 0xff]).await.unwrap();
	});
	assert!(
		socks5(&mut client, "example.invalid", 443, None)
			.await
			.is_err()
	);
	let (mut client, _server) = duplex(64);
	assert!(
		socks5(&mut client, &"h".repeat(256), 443, None)
			.await
			.is_err()
	);
}

#[tokio::test]
async fn http_connect_tunnels_without_swallowing_payload() {
	let (mut client, mut server) = duplex(1024);
	let proxy = tokio::spawn(async move {
		let mut request = Vec::new();
		let mut byte = [0_u8; 1];
		while !request.ends_with(b"\r\n\r\n") {
			server.read_exact(&mut byte).await.unwrap();
			request.push(byte[0]);
		}
		let request = String::from_utf8(request).unwrap();
		assert!(request.starts_with("CONNECT gateway.discord.gg:443 HTTP/1.1\r\n"));
		assert!(request.contains("Host: gateway.discord.gg:443\r\n"));
		assert!(!request.contains("Proxy-Authorization"));
		server
			.write_all(b"HTTP/1.1 200 Connection established\r\nX: y\r\n\r\nHELLO")
			.await
			.unwrap();
	});
	http_connect(&mut client, "gateway.discord.gg", 443, None)
		.await
		.unwrap();
	let mut payload = [0_u8; 5];
	client.read_exact(&mut payload).await.unwrap();
	assert_eq!(&payload, b"HELLO");
	proxy.await.unwrap();
}

#[tokio::test]
async fn http_connect_sends_basic_credentials_and_maps_failures() {
	let (mut client, mut server) = duplex(1024);
	let proxy = tokio::spawn(async move {
		let mut request = Vec::new();
		let mut byte = [0_u8; 1];
		while !request.ends_with(b"\r\n\r\n") {
			server.read_exact(&mut byte).await.unwrap();
			request.push(byte[0]);
		}
		let request = String::from_utf8(request).unwrap();
		assert!(request.contains("CONNECT [2001:db8::1]:443 HTTP/1.1"));
		assert!(
			request.contains("Proxy-Authorization: Basic Ym9iOnBhc3M=\r\n"),
			"{request}"
		);
		server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
	});
	let auth = creds("bob", "pass");
	http_connect(&mut client, "2001:db8::1", 443, Some(&auth))
		.await
		.unwrap();
	proxy.await.unwrap();

	for (response, kind) in [
		(
			&b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
			ErrorKind::PermissionDenied,
		),
		(
			&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..],
			ErrorKind::ConnectionRefused,
		),
		(&b"garbage\r\n\r\n"[..], ErrorKind::InvalidData),
	] {
		let (mut client, mut server) = duplex(1024);
		let response = response.to_vec();
		tokio::spawn(async move {
			let mut sink = [0_u8; 256];
			let _ = server.read(&mut sink).await;
			server.write_all(&response).await.unwrap();
		});
		let error = http_connect(&mut client, "example.invalid", 443, None)
			.await
			.unwrap_err();
		assert_eq!(error.kind(), kind);
	}
	let (mut client, mut server) = duplex(64 * 1024);
	tokio::spawn(async move {
		let mut sink = [0_u8; 256];
		let _ = server.read(&mut sink).await;
		let _ = server.write_all(&vec![b'a'; MAX_HEADERS + 10]).await;
	});
	let error = http_connect(&mut client, "example.invalid", 443, None)
		.await
		.unwrap_err();
	assert_eq!(
		error.kind(),
		ErrorKind::InvalidData,
		"oversized header blocks are bounded"
	);
	let (mut client, _server) = duplex(64);
	assert!(
		http_connect(&mut client, "bad host", 443, None)
			.await
			.is_err()
	);
}

/// Minimal SOCKS5 server for the end-to-end tests: records the requested target and relays.
async fn spawn_socks_proxy(log: Arc<std::sync::Mutex<Vec<String>>>, target: String) -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		loop {
			let Ok((mut inbound, _)) = listener.accept().await else {
				return;
			};
			let log = log.clone();
			let target = target.clone();
			tokio::spawn(async move {
				let mut hello = [0_u8; 3];
				inbound.read_exact(&mut hello).await.unwrap();
				inbound.write_all(&[0x05, 0x00]).await.unwrap();
				let mut head = [0_u8; 4];
				inbound.read_exact(&mut head).await.unwrap();
				let host = match head[3] {
					0x03 => {
						let mut len = [0_u8; 1];
						inbound.read_exact(&mut len).await.unwrap();
						let mut name = vec![0_u8; len[0] as usize];
						inbound.read_exact(&mut name).await.unwrap();
						String::from_utf8(name).unwrap()
					}
					0x01 => {
						let mut ip = [0_u8; 4];
						inbound.read_exact(&mut ip).await.unwrap();
						std::net::Ipv4Addr::from(ip).to_string()
					}
					other => panic!("unexpected address type {other}"),
				};
				let mut port = [0_u8; 2];
				inbound.read_exact(&mut port).await.unwrap();
				let port = u16::from_be_bytes(port);
				log.lock().unwrap().push(format!("{host}:{port}"));
				// Every test target is served locally, whatever name was requested.
				let mut outbound = TcpStream::connect(&target).await.unwrap();
				inbound
					.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
					.await
					.unwrap();
				let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
			});
		}
	});
	port
}

#[tokio::test]
async fn websocket_goes_through_the_proxy_and_invalid_routes_fail_closed() {
	let _guard = route_lock().lock().await;
	let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let echo_addr = echo.local_addr().unwrap();
	tokio::spawn(async move {
		let (tcp, _) = echo.accept().await.unwrap();
		let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
		if let Some(Ok(Message::Text(text))) = ws.next().await {
			ws.send(Message::Text(format!("echo:{text}").into()))
				.await
				.unwrap();
		}
	});
	let log = Arc::new(std::sync::Mutex::new(Vec::new()));
	let port = spawn_socks_proxy(log.clone(), echo_addr.to_string()).await;
	set(State::Proxy(
		Proxy::parse(&format!("socks5://127.0.0.1:{port}")).unwrap(),
	));

	let mut socket = connect_ws("ws://gateway.example.invalid:80/?v=10", None)
		.await
		.unwrap();
	socket.send(Message::Text("hi".into())).await.unwrap();
	let reply = socket.next().await;
	assert!(
		matches!(reply, Some(Ok(Message::Text(ref t))) if t.as_str() == "echo:hi"),
		"{reply:?}"
	);
	assert_eq!(
		log.lock().unwrap().as_slice(),
		["gateway.example.invalid:80"],
		"the proxy received the hostname, so name resolution happened remotely"
	);

	set(State::Invalid("Proxy URL rejected: test"));
	let error = connect_ws("ws://127.0.0.1:1/", None).await.unwrap_err();
	assert!(error.to_string().contains("Proxy URL rejected"), "{error}");
	assert!(
		connect_tcp("127.0.0.1", 1)
			.await
			.unwrap_err()
			.to_string()
			.contains("rejected")
	);
	set(State::Direct);
}

#[tokio::test]
async fn rest_clients_use_the_http_and_socks_routes_and_fail_closed() {
	let _guard = route_lock().lock().await;
	let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = server.local_addr().unwrap().port();
	let seen = Arc::new(std::sync::Mutex::new(String::new()));
	let seen_by_server = seen.clone();
	tokio::spawn(async move {
		loop {
			let Ok((mut tcp, _)) = server.accept().await else {
				return;
			};
			let seen = seen_by_server.clone();
			tokio::spawn(async move {
				let mut buffer = vec![0_u8; 4096];
				let n = tcp.read(&mut buffer).await.unwrap_or(0);
				*seen.lock().unwrap() = String::from_utf8_lossy(&buffer[..n]).into_owned();
				let _ = tcp
					.write_all(
						b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
					)
					.await;
			});
		}
	});
	set(State::Proxy(
		Proxy::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
	));
	let client = apply(reqwest::Client::builder()).build().unwrap();
	let body = client
		.get("http://rest.example.invalid/api")
		.send()
		.await
		.unwrap()
		.text()
		.await
		.unwrap();
	assert_eq!(body, "ok");
	assert!(
		seen.lock()
			.unwrap()
			.starts_with("GET http://rest.example.invalid/api HTTP/1.1"),
		"{}",
		seen.lock().unwrap()
	);

	// socks5h: the proxy, not this process, resolves the REST hostname.
	let log = Arc::new(std::sync::Mutex::new(Vec::new()));
	let socks = spawn_socks_proxy(log.clone(), format!("127.0.0.1:{port}")).await;
	set(State::Proxy(
		Proxy::parse(&format!("socks5://127.0.0.1:{socks}")).unwrap(),
	));
	let client = apply(reqwest::Client::builder()).build().unwrap();
	let body = client
		.get("http://socks.example.invalid/api")
		.send()
		.await
		.unwrap()
		.text()
		.await
		.unwrap();
	assert_eq!(body, "ok");
	assert_eq!(log.lock().unwrap().as_slice(), ["socks.example.invalid:80"]);

	set(State::Invalid("Proxy URL rejected: test"));
	let client = apply(reqwest::Client::builder()).build().unwrap();
	assert!(
		client
			.get("http://rest.example.invalid/api")
			.send()
			.await
			.is_err(),
		"an invalid route must never fall back to a direct request"
	);
	set(State::Direct);
}

#[test]
fn proxy_file_takes_the_first_real_line_and_protects_credentials() {
	assert_eq!(State::from_file_contents("", Some(0o600)), State::Direct);
	assert_eq!(
		State::from_file_contents("# only a comment\n\n", Some(0o644)),
		State::Direct
	);
	let state =
		State::from_file_contents("# route\n\nsocks5://127.0.0.1:1080\nignored\n", Some(0o644));
	assert!(
		matches!(state, State::Proxy(ref p) if p.port() == 1080),
		"{state:?}"
	);
	// No credentials: any mode is fine. With credentials the file must be private.
	assert!(matches!(
		State::from_file_contents("socks5://u:p@127.0.0.1:1080", Some(0o600)),
		State::Proxy(_)
	));
	for mode in [0o644, 0o640, 0o604, 0o660] {
		assert!(
			matches!(
				State::from_file_contents("socks5://u:p@127.0.0.1:1080", Some(mode)),
				State::Invalid(_)
			),
			"{mode:o}"
		);
	}
	assert!(matches!(
		State::from_file_contents("socks5://u:p@127.0.0.1:1080", None),
		State::Proxy(_)
	));
	assert!(matches!(
		State::from_file_contents("garbage", Some(0o600)),
		State::Invalid(_)
	));
	assert!(matches!(
		State::from_file_contents(&"x".repeat(MAX_URL * 2 + 1), Some(0o600)),
		State::Invalid(_)
	));
}

#[test]
fn describe_never_contains_credentials() {
	let state = State::parse(Some("socks5://user:secret@127.0.0.1:1080"));
	let text = state.describe();
	assert_eq!(text, "socks5 127.0.0.1:1080 (with credentials)");
	assert!(!text.contains("secret") && !text.contains("user"));
	assert_eq!(State::Direct.describe(), "direct");
	assert!(State::parse(Some("bad")).describe().starts_with("invalid:"));
}

#[test]
fn proxy_new_validates_fields_and_endpoint_hides_credentials() {
	let proxy = Proxy::new(Kind::Socks5, " 127.0.0.1 ", 1080, Some(("bob", "p:ss"))).unwrap();
	assert_eq!(proxy.endpoint(), "socks5://127.0.0.1:1080");
	assert!(proxy.has_credentials());
	let v6 = Proxy::new(Kind::HttpConnect, "[::1]", 8080, None).unwrap();
	assert_eq!(
		(v6.host(), v6.endpoint().as_str()),
		("::1", "http://[::1]:8080")
	);
	for (host, port) in [
		("", 1080),
		("a b", 1080),
		("h/x", 1080),
		("u@h", 1080),
		("h", 0),
		("h\nx", 1),
	] {
		assert!(
			Proxy::new(Kind::Socks5, host, port, None).is_err(),
			"{host:?}:{port}"
		);
	}
	assert!(Proxy::new(Kind::Socks5, &"h".repeat(254), 1, None).is_err());
	assert!(Proxy::new(Kind::Socks5, "h", 1, Some(("", "x"))).is_err());
	assert!(Proxy::new(Kind::Socks5, "h", 1, Some(("a:b", "x"))).is_err());
	let base = Proxy::new(Kind::Socks5, "h", 1, None).unwrap();
	assert!(base.with_credentials("u", "p").unwrap().has_credentials());
	assert_eq!(
		base.with_credentials("u", "p").unwrap().endpoint(),
		base.endpoint()
	);
}

#[test]
fn config_file_is_private_atomic_and_never_stores_credentials() {
	let dir = std::env::temp_dir().join(format!("net-route-file-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	let path = dir.join("serein").join("proxy");
	let proxy = Proxy::new(Kind::Socks5, "127.0.0.1", 1080, Some(("bob", "secret"))).unwrap();

	write_config_file_at(&path, Some(&proxy), true).unwrap();
	let contents = std::fs::read_to_string(&path).unwrap();
	assert!(
		!contents.contains("bob") && !contents.contains("secret"),
		"{contents}"
	);
	assert!(contents.lines().any(|line| line.trim() == KEYRING_MARKER));
	assert!(
		!path.parent().unwrap().join(".proxy.tmp").exists(),
		"temporary file is renamed away"
	);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		assert_eq!(
			std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
			0o600
		);
		assert_eq!(
			std::fs::metadata(path.parent().unwrap())
				.unwrap()
				.permissions()
				.mode() & 0o777,
			0o700
		);
	}
	// The reader accepts exactly what the writer produced.
	let state = State::from_file_contents(&contents, Some(0o600));
	assert!(
		matches!(&state, State::Proxy(p) if p.endpoint() == "socks5://127.0.0.1:1080" && !p.has_credentials())
	);

	// Replacing keeps the file private and drops the marker when credentials are not stored.
	let other = Proxy::new(Kind::HttpConnect, "proxy.example", 8080, None).unwrap();
	write_config_file_at(&path, Some(&other), false).unwrap();
	let contents = std::fs::read_to_string(&path).unwrap();
	assert!(contents.contains("http://proxy.example:8080") && !contents.contains(KEYRING_MARKER));

	// Removing the route deletes the file and is idempotent.
	write_config_file_at(&path, None, false).unwrap();
	assert!(!path.exists());
	write_config_file_at(&path, None, false).unwrap();
	let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn candidate_routes_can_be_tested_without_changing_the_process_route() {
	let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let echo_addr = echo.local_addr().unwrap();
	tokio::spawn(async move {
		let (tcp, _) = echo.accept().await.unwrap();
		let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
		let _ = ws.send(Message::Text("hello".into())).await;
	});
	let log = Arc::new(std::sync::Mutex::new(Vec::new()));
	let port = spawn_socks_proxy(log.clone(), echo_addr.to_string()).await;
	let candidate = State::Proxy(Proxy::new(Kind::Socks5, "127.0.0.1", port, None).unwrap());
	let mut socket = connect_ws_with(&candidate, "ws://candidate.example.invalid:80/", None)
		.await
		.unwrap();
	assert!(matches!(socket.next().await, Some(Ok(Message::Text(ref t))) if t.as_str() == "hello"));
	assert_eq!(
		log.lock().unwrap().as_slice(),
		["candidate.example.invalid:80"]
	);
	// A candidate that is itself invalid fails closed without any network access.
	let error = connect_ws_with(&State::Invalid("nope"), "ws://127.0.0.1:1/", None)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("nope"));
}

#[tokio::test]
async fn gateway_probe_reports_success_and_failures_without_credentials() {
	// A local "gateway": a plain TCP server cannot speak wss, so test the failure mapping here and
	// the success path against the real gateway in the example run.
	let state = State::Proxy(Proxy::new(Kind::Socks5, "127.0.0.1", 1, None).unwrap());
	let error = probe_gateway(&state).await.unwrap_err();
	assert!(!error.is_empty() && error.len() <= 160, "{error}");
	let invalid = probe_gateway(&State::Invalid("Proxy URL rejected: test"))
		.await
		.unwrap_err();
	assert!(invalid.contains("Proxy URL rejected"), "{invalid}");
}
