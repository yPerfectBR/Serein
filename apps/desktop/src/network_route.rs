//! Host side of Settings > Network: writes the route file, keeps the proxy login in the OS
//! credential store, tests a candidate route against the gateway and restarts the app.
use std::sync::mpsc;
use ui::network_route::{Candidate, Form, Login, Mode, Request, Status};

enum Outcome {
	Saved { has_login: bool },
	Removed,
	Tested(Result<u128, String>),
	CredentialStore,
	SaveFailed,
}

#[derive(Default)]
pub struct Handler {
	loaded: bool,
	pending: Option<mpsc::Receiver<Outcome>>,
}

fn mode_of(kind: net_route::Kind) -> Mode {
	match kind {
		net_route::Kind::Socks5 => Mode::Socks5,
		net_route::Kind::HttpConnect => Mode::Http,
	}
}

fn proxy_of(candidate: &Candidate) -> Option<net_route::Proxy> {
	let kind = candidate.mode.kind()?;
	net_route::Proxy::new(kind, &candidate.host, candidate.port, None).ok()
}

/// After `net_route::init()`: a proxy file that asks for a stored login gets it from the OS
/// credential store, but only for the endpoint it was saved for. A store that cannot be read
/// fails closed rather than connecting without the login.
pub fn apply_saved_login() {
	let net_route::State::Proxy(proxy) = net_route::state() else {
		return;
	};
	if proxy.has_credentials() || !net_route::keyring_credentials_wanted() {
		return;
	}
	match platform::route_credentials::load() {
		Ok(Some(saved)) if saved.endpoint == proxy.endpoint() => {
			match proxy.with_credentials(&saved.username, &saved.password) {
				Ok(with_login) => net_route::set(net_route::State::Proxy(with_login)),
				Err(reason) => net_route::set(net_route::State::Invalid(reason)),
			}
		}
		Ok(_) => {}
		Err(_) => net_route::set(net_route::State::Invalid(
			"The proxy login is in the OS credential store, which is unavailable",
		)),
	}
}

fn save(candidate: &Candidate, had_login: bool) -> Outcome {
	let Some(proxy) = proxy_of(candidate) else {
		return Outcome::SaveFailed;
	};
	let keyring = match &candidate.login {
		Login::Keep => had_login,
		Login::Forget => {
			if platform::route_credentials::forget().is_err() {
				return Outcome::CredentialStore;
			}
			false
		}
		Login::Replace(user, pass) => {
			let credentials = platform::route_credentials::Credentials {
				endpoint: proxy.endpoint(),
				username: user.clone(),
				password: pass.clone(),
			};
			if platform::route_credentials::save(&credentials).is_err() {
				return Outcome::CredentialStore;
			}
			true
		}
	};
	match net_route::write_config_file(Some(&proxy), keyring) {
		Ok(()) => Outcome::Saved { has_login: keyring },
		Err(_) => Outcome::SaveFailed,
	}
}

fn remove() -> Outcome {
	// A forgotten file must not leave a login behind for the next proxy.
	let forgotten = platform::route_credentials::forget().is_ok();
	match net_route::write_config_file(None, false) {
		Ok(()) if forgotten => Outcome::Removed,
		Ok(()) => Outcome::CredentialStore,
		Err(_) => Outcome::SaveFailed,
	}
}

/// The route to test, with the typed login or the stored one when the field was left empty.
fn test_state(candidate: &Candidate, had_login: bool) -> Result<net_route::State, Outcome> {
	let proxy = proxy_of(candidate).ok_or(Outcome::SaveFailed)?;
	let proxy = match &candidate.login {
		Login::Replace(user, pass) => proxy
			.with_credentials(user, pass)
			.map_err(|_| Outcome::SaveFailed)?,
		Login::Keep if had_login => match platform::route_credentials::load() {
			Ok(Some(saved)) if saved.endpoint == proxy.endpoint() => proxy
				.with_credentials(&saved.username, &saved.password)
				.map_err(|_| Outcome::SaveFailed)?,
			Ok(_) => proxy,
			Err(_) => return Err(Outcome::CredentialStore),
		},
		Login::Keep | Login::Forget => proxy,
	};
	Ok(net_route::State::Proxy(proxy))
}

#[cfg(unix)]
fn restart(ctx: &eframe::egui::Context) {
	use std::os::unix::process::CommandExt;
	let Ok(exe) = std::env::current_exe() else {
		return;
	};
	// Wait for this process to exit (its single-instance lock), then start the new one.
	let mut helper = std::process::Command::new("sh");
	helper
		.arg("-c")
		.arg("i=0; while kill -0 \"$1\" 2>/dev/null && [ $i -lt 150 ]; do sleep 0.2; i=$((i+1)); done; exec \"$0\"")
		.arg(&exe)
		.arg(std::process::id().to_string())
		.stdin(std::process::Stdio::null())
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null())
		.process_group(0);
	if helper.spawn().is_ok() {
		ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);
		// Closing can be swallowed (for example hiding to the tray); do not leave the helper waiting.
		std::thread::spawn(|| {
			std::thread::sleep(std::time::Duration::from_secs(4));
			std::process::exit(0);
		});
	}
}
#[cfg(not(unix))]
fn restart(_: &eframe::egui::Context) {}

impl Handler {
	pub fn tick(
		&mut self,
		form: &mut Form,
		runtime: &tokio::runtime::Runtime,
		ctx: &eframe::egui::Context,
		demo: bool,
	) {
		// The offline preview brings its own state; it must not be replaced by the real route.
		if !self.loaded && demo {
			self.loaded = true;
		}
		if !self.loaded {
			self.loaded = true;
			form.env_locked = net_route::env_overrides();
			form.restart_supported = cfg!(unix);
			match net_route::state() {
				net_route::State::Proxy(proxy) => form.load(
					mode_of(proxy.kind()),
					proxy.host(),
					proxy.port(),
					net_route::keyring_credentials_wanted(),
				),
				_ => form.load(Mode::Direct, "", 0, false),
			}
		}
		if let Some(receiver) = &self.pending {
			match receiver.try_recv() {
				Ok(outcome) => {
					self.pending = None;
					form.busy = false;
					match outcome {
						Outcome::Saved { has_login } => {
							form.clear_draft();
							form.has_saved_login = has_login;
							form.restart_needed = true;
							form.status = Status::Saved;
						}
						Outcome::Removed => {
							form.clear_draft();
							form.has_saved_login = false;
							form.restart_needed = true;
							form.status = Status::Removed;
						}
						Outcome::Tested(Ok(ms)) => form.status = Status::TestOk(ms),
						Outcome::Tested(Err(reason)) => form.status = Status::TestFailed(reason),
						Outcome::CredentialStore => form.status = Status::CredentialStore,
						Outcome::SaveFailed => form.status = Status::SaveFailed,
					}
				}
				Err(mpsc::TryRecvError::Empty) => {}
				Err(mpsc::TryRecvError::Disconnected) => {
					self.pending = None;
					form.busy = false;
					form.status = Status::SaveFailed;
				}
			}
		}
		let Some(request) = form.request.take() else {
			return;
		};
		if demo {
			form.status = Status::Demo;
			return;
		}
		if form.env_locked || self.pending.is_some() {
			return;
		}
		let had_login = form.has_saved_login;
		let (send, receive) = mpsc::sync_channel(1);
		let repaint = ctx.clone();
		match request {
			Request::Restart => restart(ctx),
			Request::Save(candidate) => {
				self.pending = Some(receive);
				form.busy = true;
				runtime.spawn_blocking(move || {
					let _ = send.send(save(&candidate, had_login));
					repaint.request_repaint();
				});
			}
			Request::Remove => {
				self.pending = Some(receive);
				form.busy = true;
				runtime.spawn_blocking(move || {
					let _ = send.send(remove());
					repaint.request_repaint();
				});
			}
			Request::Test(candidate) => {
				self.pending = Some(receive);
				form.busy = true;
				runtime.spawn(async move {
					let outcome = match tokio::task::spawn_blocking(move || {
						test_state(&candidate, had_login)
					})
					.await
					{
						Ok(Ok(state)) => match net_route::probe_gateway(&state).await {
							Ok(elapsed) => Outcome::Tested(Ok(elapsed.as_millis())),
							Err(reason) => Outcome::Tested(Err(reason)),
						},
						Ok(Err(outcome)) => outcome,
						Err(_) => Outcome::SaveFailed,
					};
					let _ = send.send(outcome);
					repaint.request_repaint();
				});
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ui::network_route::Login;

	fn candidate(mode: Mode, host: &str, port: u16, login: Login) -> Candidate {
		Candidate {
			mode,
			host: host.into(),
			port,
			login,
		}
	}

	#[test]
	fn candidates_become_proxies_and_direct_has_none() {
		let socks = candidate(Mode::Socks5, "127.0.0.1", 1080, Login::Keep);
		assert_eq!(
			proxy_of(&socks).unwrap().endpoint(),
			"socks5://127.0.0.1:1080"
		);
		let http = candidate(Mode::Http, "proxy.example", 8080, Login::Keep);
		assert_eq!(
			proxy_of(&http).unwrap().endpoint(),
			"http://proxy.example:8080"
		);
		assert!(proxy_of(&candidate(Mode::Direct, "", 0, Login::Keep)).is_none());
		assert!(proxy_of(&candidate(Mode::Socks5, "bad host", 1080, Login::Keep)).is_none());
	}

	#[test]
	fn test_state_attaches_only_a_typed_login_without_touching_the_store() {
		let typed = candidate(
			Mode::Socks5,
			"127.0.0.1",
			1080,
			Login::Replace(
				zeroize::Zeroizing::new("owner".into()),
				zeroize::Zeroizing::new("synthetic".into()),
			),
		);
		let Ok(net_route::State::Proxy(proxy)) = test_state(&typed, false) else {
			panic!("expected a proxy state");
		};
		assert!(proxy.has_credentials());
		// Forget/Keep without a stored login never reads the credential store.
		for login in [Login::Keep, Login::Forget] {
			let Ok(net_route::State::Proxy(proxy)) =
				test_state(&candidate(Mode::Http, "proxy.example", 8080, login), false)
			else {
				panic!("expected a proxy state");
			};
			assert!(!proxy.has_credentials());
		}
	}

	#[test]
	fn the_form_is_filled_from_the_active_route_only_once() {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.build()
			.unwrap();
		let ctx = eframe::egui::Context::default();
		let mut handler = Handler::default();
		let mut form = Form::default();
		handler.tick(&mut form, &runtime, &ctx, false);
		assert!(handler.loaded);
		assert_eq!(form.restart_supported, cfg!(unix));
		// Demo mode keeps a previewed form as it is.
		let mut preview = Form::default();
		preview.preview(Mode::Socks5, Status::Idle, false);
		let mut demo_handler = Handler::default();
		demo_handler.tick(&mut preview, &runtime, &ctx, true);
		assert!(demo_handler.loaded);
		assert!(
			preview.candidate().is_ok_and(|c| c.mode == Mode::Socks5),
			"preview must survive the first tick"
		);
		// Demo mode never starts file, credential or network work.
		form.request = Some(Request::Remove);
		handler.tick(&mut form, &runtime, &ctx, true);
		assert_eq!(form.status, Status::Demo);
		assert!(handler.pending.is_none() && !form.busy);
	}
}
