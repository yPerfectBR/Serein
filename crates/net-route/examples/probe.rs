//! Opens the Discord gateway through the configured route and reports the first frame.
//! It sends no credentials and signs in to nothing:
//! `SEREIN_PROXY=socks5://127.0.0.1:1080 cargo run -p net-route --example probe`
//! `probe --route-only` prints the active route without connecting.
#[tokio::main(flavor = "current_thread")]
async fn main() {
	let route = net_route::init();
	println!("route: {}", route.describe());
	if std::env::args().nth(1).as_deref() == Some("--route-only") {
		return;
	}
	match net_route::probe_gateway(&route).await {
		Ok(elapsed) => println!(
			"connected, first frame: op 10 (Hello) in {} ms",
			elapsed.as_millis()
		),
		Err(reason) => println!("connect failed: {reason}"),
	}
}
