//! Name resolution inside the Serein VPN namespace.
//!
//! `serein-vpn run` bind-mounts the tunnel's resolv.conf over /etc/resolv.conf, but NetworkManager
//! replaces the host file on every network change, and the kernel then detaches that mount. The
//! app would fall back to LAN resolvers it cannot reach through the tunnel, stalling every new
//! hostname for the first server's timeout. Inside the tunnel, names are therefore resolved against
//! the tunnel's own servers, read from the helper's file, whose path is never replaced.
use std::{
	collections::HashMap,
	hash::{BuildHasher, RandomState},
	io::{Error, ErrorKind, Result as IoResult},
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	sync::{
		Arc, Mutex,
		atomic::{AtomicU64, Ordering},
	},
	time::{Duration, Instant},
};

use tokio::net::{TcpStream, UdpSocket};

/// Written by `serein-vpn up` from the tunnel configuration.
const SERVERS_FILE: &str = "/etc/netns/serein-vpn/resolv.conf";
/// Set by `serein-vpn run` for programs started inside the tunnel.
const ACTIVE_ENV: &str = "SEREIN_VPN_ACTIVE";
const MAX_SERVERS: usize = 4;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CACHE: usize = 256;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

static CACHE: Mutex<Option<HashMap<String, (Instant, Vec<IpAddr>)>>> = Mutex::new(None);

/// True inside the Serein tunnel when its resolvers are known.
pub fn active() -> bool {
	std::env::var_os(ACTIVE_ENV).is_some_and(|value| value == "1") && !servers().is_empty()
}

fn servers() -> Vec<IpAddr> {
	std::fs::read_to_string(SERVERS_FILE)
		.map(|contents| parse_servers(&contents))
		.unwrap_or_default()
}

pub(crate) fn parse_servers(contents: &str) -> Vec<IpAddr> {
	contents
		.lines()
		.filter_map(|line| line.trim().strip_prefix("nameserver"))
		.filter_map(|server| server.trim().parse().ok())
		.take(MAX_SERVERS)
		.collect()
}

/// Uses the tunnel resolvers for this `reqwest` client when running inside the tunnel.
pub fn apply(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
	if active() {
		builder.dns_resolver(Arc::new(TunnelResolver))
	} else {
		builder
	}
}

/// `TcpStream::connect((host, port))` that resolves through the tunnel when inside it.
pub async fn connect(host: &str, port: u16) -> IoResult<TcpStream> {
	if !active() {
		return TcpStream::connect((host, port)).await;
	}
	let mut last = Error::new(ErrorKind::NotFound, "no address for host");
	for ip in lookup(host).await? {
		match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((ip, port))).await {
			Ok(Ok(stream)) => return Ok(stream),
			Ok(Err(error)) => last = error,
			Err(_) => last = Error::new(ErrorKind::TimedOut, "connection timed out"),
		}
	}
	Err(last)
}

struct TunnelResolver;

impl reqwest::dns::Resolve for TunnelResolver {
	fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
		let host = name.as_str().to_owned();
		Box::pin(async move {
			let addresses = lookup(&host).await?;
			let addresses: reqwest::dns::Addrs =
				Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
			Ok(addresses)
		})
	}
}

/// IPv4 first: the tunnel commonly carries no IPv6, and IPv6 answers then only cost a fallback.
pub async fn lookup(host: &str) -> IoResult<Vec<IpAddr>> {
	let host = host.trim_start_matches('[').trim_end_matches(']');
	if let Ok(ip) = host.parse::<IpAddr>() {
		return Ok(vec![ip]);
	}
	let key = host.trim_end_matches('.').to_ascii_lowercase();
	if let Some(cached) = cached(&key) {
		return Ok(cached);
	}
	let query = encode_name(&key).ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid hostname"))?;
	let mut last = Error::new(ErrorKind::NotFound, "no tunnel resolver answered");
	for server in servers() {
		match resolve_with(server, &query).await {
			Ok(Answer::Found(addresses, ttl)) => {
				store(key, &addresses, ttl);
				return Ok(addresses);
			}
			// A tunnel resolver's definitive "no" is final; asking elsewhere would leak the name.
			Ok(Answer::Missing) => return Err(Error::new(ErrorKind::NotFound, "unknown host")),
			Err(error) => last = error,
		}
	}
	Err(last)
}

fn cached(key: &str) -> Option<Vec<IpAddr>> {
	let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
	let cache = cache.get_or_insert_with(HashMap::new);
	match cache.get(key) {
		Some((until, addresses)) if Instant::now() < *until => Some(addresses.clone()),
		Some(_) => {
			cache.remove(key);
			None
		}
		None => None,
	}
}

fn store(key: String, addresses: &[IpAddr], ttl: u32) {
	let ttl = Duration::from_secs(u64::from(ttl.clamp(10, 300)));
	let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
	let cache = cache.get_or_insert_with(HashMap::new);
	if cache.len() >= MAX_CACHE {
		let now = Instant::now();
		cache.retain(|_, (until, _)| *until > now);
		if cache.len() >= MAX_CACHE {
			cache.clear();
		}
	}
	cache.insert(key, (Instant::now() + ttl, addresses.to_vec()));
}

#[derive(Debug, PartialEq)]
pub(crate) enum Answer {
	Found(Vec<IpAddr>, u32),
	Missing,
}

/// Asks one server for A and AAAA at once and waits for both answers.
async fn resolve_with(server: IpAddr, name: &[u8]) -> IoResult<Answer> {
	let bind: SocketAddr = if server.is_ipv4() {
		(Ipv4Addr::UNSPECIFIED, 0).into()
	} else {
		(Ipv6Addr::UNSPECIFIED, 0).into()
	};
	let socket = UdpSocket::bind(bind).await?;
	socket.connect((server, 53)).await?;
	let (id_a, id_aaaa) = (query_id(), query_id());
	socket.send(&encode_query(id_a, name, TYPE_A)).await?;
	socket.send(&encode_query(id_aaaa, name, TYPE_AAAA)).await?;
	let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
	let (mut v4, mut v6) = (None, None);
	let mut packet = [0u8; 1500];
	while v4.is_none() || v6.is_none() {
		let length = tokio::time::timeout_at(deadline, socket.recv(&mut packet))
			.await
			.map_err(|_| Error::new(ErrorKind::TimedOut, "tunnel resolver timed out"))??;
		let packet = &packet[..length];
		if v4.is_none()
			&& let Some(answer) = decode_response(packet, id_a)
		{
			v4 = Some(answer?);
		} else if v6.is_none()
			&& let Some(answer) = decode_response(packet, id_aaaa)
		{
			v6 = Some(answer?);
		}
	}
	let (v4, v6) = (v4.unwrap_or(Answer::Missing), v6.unwrap_or(Answer::Missing));
	Ok(match (v4, v6) {
		(Answer::Missing, Answer::Missing) => Answer::Missing,
		(Answer::Found(a, ttl), Answer::Missing) | (Answer::Missing, Answer::Found(a, ttl)) => {
			Answer::Found(a, ttl)
		}
		(Answer::Found(mut a, ttl_a), Answer::Found(b, ttl_b)) => {
			a.extend(b);
			Answer::Found(a, ttl_a.min(ttl_b))
		}
	})
}

fn query_id() -> u16 {
	static COUNTER: AtomicU64 = AtomicU64::new(0);
	RandomState::new().hash_one(COUNTER.fetch_add(1, Ordering::Relaxed)) as u16
}

/// Wire-format labels for `name`, or `None` when it is not a plain DNS hostname.
pub(crate) fn encode_name(name: &str) -> Option<Vec<u8>> {
	if name.is_empty() || name.len() > 253 {
		return None;
	}
	let mut encoded = Vec::with_capacity(name.len() + 2);
	for label in name.split('.') {
		if label.is_empty()
			|| label.len() > 63
			|| !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
		{
			return None;
		}
		encoded.push(label.len() as u8);
		encoded.extend_from_slice(label.as_bytes());
	}
	encoded.push(0);
	Some(encoded)
}

pub(crate) fn encode_query(id: u16, name: &[u8], kind: u16) -> Vec<u8> {
	let mut packet = Vec::with_capacity(12 + name.len() + 4);
	packet.extend_from_slice(&id.to_be_bytes());
	// Recursion desired; one question.
	packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
	packet.extend_from_slice(name);
	packet.extend_from_slice(&kind.to_be_bytes());
	packet.extend_from_slice(&1u16.to_be_bytes());
	packet
}

/// `None` when the packet is not the response to `id`; `Some(Err)` for a failed lookup.
pub(crate) fn decode_response(packet: &[u8], id: u16) -> Option<IoResult<Answer>> {
	if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id || packet[2] & 0x80 == 0 {
		return None;
	}
	let failed = |reason| Some(Err(Error::new(ErrorKind::InvalidData, reason)));
	if packet[2] & 0x02 != 0 {
		return failed("truncated DNS answer");
	}
	match packet[3] & 0x0f {
		0 => {}
		3 => return Some(Ok(Answer::Missing)),
		_ => return failed("DNS server failure"),
	}
	let questions = u16::from_be_bytes([packet[4], packet[5]]);
	let answers = u16::from_be_bytes([packet[6], packet[7]]);
	let mut at = 12;
	for _ in 0..questions {
		at = skip_name(packet, at)? + 4;
	}
	let mut addresses = Vec::new();
	let mut ttl = u32::MAX;
	for _ in 0..answers {
		at = skip_name(packet, at)?;
		let header = packet.get(at..at + 10)?;
		let kind = u16::from_be_bytes([header[0], header[1]]);
		let record_ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
		let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
		let data = packet.get(at + 10..at + 10 + length)?;
		at += 10 + length;
		let address = match (kind, length) {
			(TYPE_A, 4) => IpAddr::from(<[u8; 4]>::try_from(data).ok()?),
			(TYPE_AAAA, 16) => IpAddr::from(<[u8; 16]>::try_from(data).ok()?),
			_ => continue,
		};
		addresses.push(address);
		ttl = ttl.min(record_ttl);
	}
	Some(Ok(if addresses.is_empty() {
		Answer::Missing
	} else {
		Answer::Found(addresses, ttl)
	}))
}

fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
	loop {
		let length = *packet.get(at)?;
		match length {
			0 => return Some(at + 1),
			_ if length & 0xc0 == 0xc0 => return packet.get(at + 1).map(|_| at + 2),
			_ if length & 0xc0 == 0 => at += 1 + usize::from(length),
			_ => return None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_only_nameserver_lines() {
		let servers = parse_servers("# Generated\nnameserver 10.2.0.1\nsearch lan\nnameserver 1.1.1.1\nnameserver junk\n");
		assert_eq!(servers, vec![IpAddr::from([10, 2, 0, 1]), IpAddr::from([1, 1, 1, 1])]);
	}

	#[test]
	fn rejects_names_that_are_not_hostnames() {
		assert_eq!(
			encode_name("api.spotify.com").unwrap(),
			b"\x03api\x07spotify\x03com\x00".to_vec()
		);
		for name in ["", "a..b", "bad name.com", "x\0y", &"a".repeat(64)] {
			assert!(encode_name(name).is_none(), "{name:?}");
		}
	}

	/// Response to `encode_query`, with a CNAME then an A record using compressed names.
	fn response(id: u16, rcode: u8, answers: &[(u16, &[u8])]) -> Vec<u8> {
		let name = encode_name("api.spotify.com").unwrap();
		let mut packet = encode_query(id, &name, TYPE_A);
		packet[2] |= 0x80;
		packet[3] = rcode;
		packet[7] = answers.len() as u8;
		for (kind, data) in answers {
			packet.extend_from_slice(&[0xc0, 12]);
			packet.extend_from_slice(&kind.to_be_bytes());
			packet.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
			packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
			packet.extend_from_slice(data);
		}
		packet
	}

	#[test]
	fn decodes_addresses_after_a_cname() {
		let packet = response(7, 0, &[(5, b"\x04edge\xc0\x10"), (TYPE_A, &[35, 186, 224, 24])]);
		assert!(decode_response(&packet, 8).is_none());
		assert_eq!(
			decode_response(&packet, 7).unwrap().unwrap(),
			Answer::Found(vec![IpAddr::from([35, 186, 224, 24])], 60)
		);
	}

	#[test]
	fn nxdomain_and_empty_answers_are_missing() {
		assert_eq!(decode_response(&response(1, 3, &[]), 1).unwrap().unwrap(), Answer::Missing);
		assert_eq!(decode_response(&response(1, 0, &[]), 1).unwrap().unwrap(), Answer::Missing);
		assert!(decode_response(&response(1, 2, &[]), 1).unwrap().is_err());
	}

	#[test]
	fn malformed_answers_do_not_panic() {
		let packet = response(9, 0, &[(TYPE_A, &[1, 2, 3, 4])]);
		for cut in 0..packet.len() {
			let _ = decode_response(&packet[..cut], 9);
		}
	}
}
