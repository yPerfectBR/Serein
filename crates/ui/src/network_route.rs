//! Settings > Network: the proxy that carries Serein's Discord traffic (gateway, voice
//! signalling, REST and CDN). The page only collects and validates input; the host performs the
//! file, credential-store and network work and reports back through [`Form::status`].
use crate::design;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum Mode {
	#[default]
	Direct,
	Socks5,
	Http,
}
impl Mode {
	const ALL: [Self; 3] = [Self::Direct, Self::Socks5, Self::Http];
	fn label_key(self) -> &'static str {
		match self {
			Self::Direct => "network-mode-direct",
			Self::Socks5 => "network-mode-socks5",
			Self::Http => "network-mode-http",
		}
	}
	pub fn kind(self) -> Option<net_route::Kind> {
		match self {
			Self::Direct => None,
			Self::Socks5 => Some(net_route::Kind::Socks5),
			Self::Http => Some(net_route::Kind::HttpConnect),
		}
	}
}

/// What to do with the login stored in the OS credential store.
pub enum Login {
	/// Leave the saved login (if any) untouched.
	Keep,
	Forget,
	Replace(Zeroizing<String>, Zeroizing<String>),
}

pub struct Candidate {
	pub mode: Mode,
	pub host: String,
	pub port: u16,
	pub login: Login,
}

pub enum Request {
	Save(Candidate),
	Test(Candidate),
	Remove,
	Restart,
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub enum Status {
	#[default]
	Idle,
	InvalidAddress,
	InvalidPort,
	InvalidLogin,
	Saved,
	Removed,
	Testing,
	TestOk(u128),
	TestFailed(String),
	CredentialStore,
	SaveFailed,
	Demo,
}
impl Status {
	fn key(&self) -> Option<&'static str> {
		Some(match self {
			Self::Idle => return None,
			Self::InvalidAddress => "network-status-invalid-address",
			Self::InvalidPort => "network-status-invalid-port",
			Self::InvalidLogin => "network-status-invalid-login",
			Self::Saved => "network-status-saved",
			Self::Removed => "network-status-removed",
			Self::Testing => "network-status-testing",
			Self::CredentialStore => "network-status-credential-store",
			Self::SaveFailed => "network-status-save-failed",
			Self::Demo => "network-status-demo",
			Self::TestOk(_) | Self::TestFailed(_) => return None,
		})
	}
}

#[derive(Default)]
pub struct Form {
	mode: Mode,
	host: String,
	port: String,
	username: Zeroizing<String>,
	password: Zeroizing<String>,
	/// Host-owned state: a login for this proxy is in the OS credential store.
	pub has_saved_login: bool,
	/// `SEREIN_PROXY` is set, so it overrides everything saved here.
	pub env_locked: bool,
	/// A change was saved; the route is read when Serein starts.
	pub restart_needed: bool,
	pub restart_supported: bool,
	pub request: Option<Request>,
	pub status: Status,
	/// Host is working (saving or testing); inputs are disabled.
	pub busy: bool,
}

impl Form {
	/// Fills the inputs from the route that is saved (or active) at startup.
	pub fn load(&mut self, mode: Mode, host: &str, port: u16, has_saved_login: bool) {
		self.mode = mode;
		self.host = host.to_owned();
		self.port = if mode == Mode::Direct || port == 0 {
			String::new()
		} else {
			port.to_string()
		};
		self.has_saved_login = has_saved_login;
	}

	/// Fixture-only: opens the page in a given state for the offline settings preview.
	pub fn preview(&mut self, mode: Mode, status: Status, saved_login: bool) {
		self.load(mode, "127.0.0.1", 1080, saved_login);
		self.restart_supported = true;
		self.restart_needed = matches!(status, Status::Saved);
		self.status = status;
	}

	/// Drops the typed login once the host has stored (or rejected) it.
	pub fn clear_draft(&mut self) {
		self.username.zeroize();
		self.password.zeroize();
	}

	/// Validates the inputs with the same rules the transport uses.
	pub fn candidate(&self) -> Result<Candidate, Status> {
		let Some(kind) = self.mode.kind() else {
			return Ok(Candidate {
				mode: Mode::Direct,
				host: String::new(),
				port: 0,
				login: Login::Keep,
			});
		};
		let port = self
			.port
			.trim()
			.parse::<u16>()
			.ok()
			.filter(|port| *port != 0)
			.ok_or(Status::InvalidPort)?;
		let typed = !self.username.is_empty() || !self.password.is_empty();
		let credentials = typed.then(|| (self.username.as_str(), self.password.as_str()));
		let proxy =
			net_route::Proxy::new(kind, &self.host, port, credentials).map_err(|reason| {
				if reason.contains("credentials") {
					Status::InvalidLogin
				} else {
					Status::InvalidAddress
				}
			})?;
		Ok(Candidate {
			mode: self.mode,
			host: proxy.host().to_owned(),
			port,
			login: if typed {
				Login::Replace(self.username.clone(), self.password.clone())
			} else {
				Login::Keep
			},
		})
	}

	fn queue(&mut self, test: bool) {
		match self.candidate() {
			Err(status) => self.status = status,
			Ok(candidate) if candidate.mode == Mode::Direct && test => {
				self.status = Status::InvalidAddress;
			}
			Ok(candidate) if candidate.mode == Mode::Direct => self.request = Some(Request::Remove),
			Ok(candidate) => {
				self.status = if test { Status::Testing } else { Status::Idle };
				self.request = Some(if test {
					Request::Test(candidate)
				} else {
					Request::Save(candidate)
				});
			}
		}
	}

	pub fn show(&mut self, ui: &mut egui::Ui, demo: bool) {
		design::group(ui, "network-title", |ui| {
			if self.env_locked {
				design::hint(ui, &crate::i18n::translate("network-env-locked"));
				design::card_divider(ui);
			}
			// Demo mode keeps the inputs usable (for screenshots); the host refuses to act on them.
			let editable = !self.env_locked && !self.busy;
			ui.add_enabled_ui(editable, |ui| {
				design::row(ui, "network-proxy", Some("network-proxy-detail"), |ui| {
					let labels = Mode::ALL.map(Mode::label_key);
					let selected = Mode::ALL.iter().position(|m| *m == self.mode).unwrap_or(0);
					if let Some(index) = design::segmented(ui, &labels, selected) {
						self.mode = Mode::ALL[index];
						self.status = Status::Idle;
					}
				});
				if self.mode != Mode::Direct {
					design::card_divider(ui);
					labelled(ui, "network-host", Some("network-host-detail"), |ui| {
						design::input(
							ui,
							egui::TextEdit::singleline(&mut self.host)
								.hint_text("127.0.0.1")
								.char_limit(253),
						);
					});
					labelled(ui, "network-port", None, |ui| {
						ui.allocate_ui(egui::vec2(140.0, 0.0), |ui| {
							design::input(
								ui,
								egui::TextEdit::singleline(&mut self.port)
									.hint_text("1080")
									.char_limit(5),
							);
						});
					});
					design::card_divider(ui);
					let login_detail = if self.has_saved_login {
						"network-login-saved"
					} else {
						"network-login-detail"
					};
					labelled(ui, "network-login", Some(login_detail), |ui| {
						credential_input(ui, "network-username", &mut self.username, false, 255);
						ui.add_space(6.0);
						credential_input(ui, "network-password", &mut self.password, true, 255);
					});
					if self.mode == Mode::Http {
						design::hint(ui, &crate::i18n::translate("network-http-warning"));
					}
				}
			});
			ui.add_space(8.0);
			ui.horizontal(|ui| {
				ui.add_enabled_ui(editable, |ui| {
					if design::button(ui, "network-save", design::ButtonKind::Primary).clicked() {
						self.queue(false);
					}
					if self.mode != Mode::Direct {
						if design::button(ui, "network-test", design::ButtonKind::Outline).clicked()
						{
							self.queue(true);
						}
						if self.has_saved_login
							&& design::button(
								ui,
								"network-forget-login",
								design::ButtonKind::Neutral,
							)
							.clicked()
						{
							self.clear_draft();
							if let Ok(mut candidate) = self.candidate() {
								candidate.login = Login::Forget;
								self.request = Some(Request::Save(candidate));
							}
						}
					}
				});
				if self.restart_needed
					&& self.restart_supported
					&& !demo && design::button(ui, "network-restart", design::ButtonKind::Danger)
					.clicked()
				{
					self.request = Some(Request::Restart);
				}
			});
			if demo && self.status == Status::Idle {
				design::hint(ui, &crate::i18n::translate("network-status-demo"));
			} else {
				self.show_status(ui);
			}
		});
		design::group(ui, "network-scope-title", |ui| {
			design::hint(ui, &crate::i18n::translate("network-scope-routed"));
			design::card_divider(ui);
			design::hint(ui, &crate::i18n::translate("network-scope-direct"));
			design::card_divider(ui);
			design::hint(ui, &crate::i18n::translate("network-terms"));
		});
	}

	fn show_status(&self, ui: &mut egui::Ui) {
		match &self.status {
			Status::TestOk(ms) => {
				let ms = ms.to_string();
				design::hint(
					ui,
					&crate::i18n::translate_args("network-status-test-ok", &[("ms", &ms)]),
				);
			}
			Status::TestFailed(reason) => {
				design::hint(
					ui,
					&crate::i18n::translate_args(
						"network-status-test-failed",
						&[("reason", reason)],
					),
				);
			}
			status => {
				if let Some(key) = status.key() {
					design::hint(ui, &crate::i18n::translate(key));
				}
			}
		}
		if self.restart_needed {
			design::hint(ui, &crate::i18n::translate("network-restart-needed"));
		}
	}
}

/// A title, an optional description and then the control, stacked at full width.
fn labelled(
	ui: &mut egui::Ui,
	title_key: &str,
	detail_key: Option<&str>,
	add: impl FnOnce(&mut egui::Ui),
) {
	let palette = design::palette(ui);
	ui.add_space(8.0);
	ui.add(egui::Label::new(
		design::medium(ui, crate::i18n::translate(title_key), 14.0).color(palette.text_strong),
	));
	if let Some(detail) = detail_key {
		design::hint(ui, &crate::i18n::translate(detail));
	}
	ui.add_space(4.0);
	add(ui);
}

fn credential_input(
	ui: &mut egui::Ui,
	label_key: &str,
	value: &mut Zeroizing<String>,
	password: bool,
	limit: usize,
) -> egui::Id {
	let response = design::input(
		ui,
		egui::TextEdit::singleline(&mut **value)
			.id_salt(("network-route-login", password))
			.hint_text(crate::i18n::translate(label_key))
			.password(password)
			.char_limit(limit),
	);
	// Password masking still records raw text in egui's persistent undo history.
	if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), response.id) {
		state.clear_undoer();
		state.store(ui.ctx(), response.id);
	}
	let role = if password {
		egui::Role::PasswordInput
	} else {
		egui::Role::TextInput
	};
	response
		.widget_info(|| egui::WidgetInfo::labeled(role, true, crate::i18n::translate(label_key)));
	response.id
}

#[cfg(test)]
mod tests {
	use super::*;

	fn form(mode: Mode, host: &str, port: &str) -> Form {
		Form {
			mode,
			host: host.into(),
			port: port.into(),
			..Default::default()
		}
	}

	#[test]
	fn direct_mode_saves_as_a_removal_and_cannot_be_tested() {
		let mut f = form(Mode::Direct, "", "");
		f.queue(false);
		assert!(matches!(f.request.take(), Some(Request::Remove)));
		f.queue(true);
		assert!(f.request.is_none());
		assert_eq!(f.status, Status::InvalidAddress);
	}

	#[test]
	fn proxy_modes_validate_host_and_port_like_the_transport() {
		for (host, port, expected) in [
			("", "1080", Status::InvalidAddress),
			("a b", "1080", Status::InvalidAddress),
			("h/x", "1080", Status::InvalidAddress),
			("127.0.0.1", "", Status::InvalidPort),
			("127.0.0.1", "0", Status::InvalidPort),
			("127.0.0.1", "65536", Status::InvalidPort),
			("127.0.0.1", "abc", Status::InvalidPort),
		] {
			let mut f = form(Mode::Socks5, host, port);
			f.queue(false);
			assert!(f.request.is_none(), "{host:?}:{port:?}");
			assert_eq!(f.status, expected, "{host:?}:{port:?}");
		}
		let mut f = form(Mode::Socks5, " 127.0.0.1 ", " 1080 ");
		f.queue(false);
		let Some(Request::Save(c)) = f.request.take() else {
			panic!("expected a save request");
		};
		assert_eq!(
			(c.mode, c.host.as_str(), c.port),
			(Mode::Socks5, "127.0.0.1", 1080)
		);
		assert!(matches!(c.login, Login::Keep));
	}

	#[test]
	fn typed_login_is_replaced_and_invalid_logins_are_rejected() {
		let mut f = form(Mode::Http, "proxy.example", "8080");
		f.username = Zeroizing::new("owner".into());
		f.password = Zeroizing::new("synthetic-password".into());
		let c = f.candidate().unwrap();
		assert!(
			matches!(&c.login, Login::Replace(u, p) if u.as_str() == "owner" && p.as_str() == "synthetic-password")
		);
		f.clear_draft();
		assert!(f.username.is_empty() && f.password.is_empty());
		f.username = Zeroizing::new("bad:name".into());
		f.password = Zeroizing::new("x".into());
		assert_eq!(f.candidate().err(), Some(Status::InvalidLogin));
	}

	#[test]
	fn test_requests_set_a_testing_status_and_load_formats_the_port() {
		let mut f = form(Mode::Socks5, "127.0.0.1", "1080");
		f.queue(true);
		assert!(matches!(f.request.take(), Some(Request::Test(_))));
		assert_eq!(f.status, Status::Testing);
		f.load(Mode::Http, "proxy.example", 8080, true);
		assert_eq!((f.port.as_str(), f.has_saved_login), ("8080", true));
		f.load(Mode::Direct, "", 0, false);
		assert!(f.port.is_empty());
	}

	#[test]
	fn forgetting_the_login_queues_a_save_that_forgets_it() {
		let mut f = form(Mode::Socks5, "127.0.0.1", "1080");
		f.has_saved_login = true;
		let mut candidate = f.candidate().unwrap();
		candidate.login = Login::Forget;
		f.request = Some(Request::Save(candidate));
		assert!(matches!(
			f.request.take(),
			Some(Request::Save(Candidate {
				login: Login::Forget,
				..
			}))
		));
	}

	#[test]
	fn page_renders_in_every_mode_without_panicking() {
		let ctx = egui::Context::default();
		for (mode, env_locked, demo) in [
			(Mode::Direct, false, false),
			(Mode::Socks5, false, false),
			(Mode::Http, true, false),
			(Mode::Socks5, false, true),
		] {
			let mut f = form(mode, "127.0.0.1", "1080");
			f.env_locked = env_locked;
			f.restart_needed = true;
			f.restart_supported = true;
			f.has_saved_login = true;
			f.status = Status::TestOk(120);
			let mut output = ctx.run_ui(egui::RawInput::default(), |ui| f.show(ui, demo));
			output.textures_delta.clear();
			f.status = Status::TestFailed("connection refused".into());
			let mut output = ctx.run_ui(egui::RawInput::default(), |ui| f.show(ui, demo));
			output.textures_delta.clear();
		}
	}
}
