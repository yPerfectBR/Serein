//! Opens a Discord WebSocket through the configured route and prints the first frame's opcode.
//! It sends no credentials and signs in to nothing:
//! `SEREIN_PROXY=socks5://127.0.0.1:1080 cargo run -p net-route --example probe -- 'wss://gateway.discord.gg/?v=10&encoding=json'`
use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let route = net_route::init();
	println!("route: {}", route.describe());
	let first = std::env::args().nth(1);
	if first.as_deref() == Some("--route-only") {
		return;
	}
	let url = first.unwrap_or_else(|| "wss://gateway.discord.gg/?v=10&encoding=json".into());
	let started = std::time::Instant::now();
	let mut socket = match tokio::time::timeout(
		Duration::from_secs(15),
		net_route::connect_ws(&url, None),
	)
	.await
	{
		Ok(Ok(socket)) => socket,
		Ok(Err(error)) => return println!("connect failed: {error}"),
		Err(_) => return println!("connect timed out"),
	};
	println!("connected in {} ms", started.elapsed().as_millis());
	match tokio::time::timeout(Duration::from_secs(10), socket.next()).await {
		Ok(Some(Ok(Message::Text(text)))) => {
			let op = text.split("\"op\":").nth(1).map(|rest| {
				rest.chars()
					.take_while(char::is_ascii_digit)
					.collect::<String>()
			});
			println!("first frame: op {}", op.as_deref().unwrap_or("?"));
		}
		Ok(Some(Ok(other))) => println!("first frame: {other:?}"),
		Ok(Some(Err(error))) => println!("read failed: {error}"),
		Ok(None) => println!("closed before the first frame"),
		Err(_) => println!("no frame within 10 s"),
	}
}
