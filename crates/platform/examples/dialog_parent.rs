//! Opens a stand-in Serein window and the Linux verification window over it, so the compositor's
//! dialog placement can be checked (`umbriel windows --json`). Uses hCaptcha's public test sitekey and
//! never talks to Discord. Exits after SEREIN_DIALOG_PROBE_SECS (default 20) seconds. Wayland only.
#![allow(unsafe_code)]
use std::{
	io::Write,
	os::fd::AsFd,
	sync::Arc,
	time::{Duration, Instant},
};
use wayland_client::{
	Connection, Dispatch, Proxy, QueueHandle,
	backend::{Backend, ObjectId},
	delegate_noop,
	protocol::{
		wl_buffer::WlBuffer, wl_registry, wl_shm, wl_shm_pool::WlShmPool, wl_surface::WlSurface,
	},
};
use winit::{
	application::ApplicationHandler,
	event::WindowEvent,
	event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
	platform::wayland::WindowAttributesExtWayland,
	raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle},
	window::{Window, WindowId},
};

const TEST_SITEKEY: &str = "10000000-ffff-ffff-ffff-000000000001";

#[derive(Default)]
struct Shm(Option<wl_shm::WlShm>);
impl Dispatch<wl_registry::WlRegistry, ()> for Shm {
	fn event(
		state: &mut Self,
		registry: &wl_registry::WlRegistry,
		event: wl_registry::Event,
		_: &(),
		_: &Connection,
		qh: &QueueHandle<Self>,
	) {
		if let wl_registry::Event::Global {
			name, interface, ..
		} = event && interface == wl_shm::WlShm::interface().name
		{
			state.0 = Some(registry.bind(name, 1, qh, ()));
		}
	}
}
delegate_noop!(Shm: ignore wl_shm::WlShm);
delegate_noop!(Shm: ignore WlShmPool);
delegate_noop!(Shm: ignore WlBuffer);

/// winit draws nothing, and Wayland maps a window only once it has a buffer: paint a flat one.
fn paint(window: &Window) -> Option<Connection> {
	let RawDisplayHandle::Wayland(display) = window.display_handle().ok()?.as_raw() else {
		return None;
	};
	let RawWindowHandle::Wayland(surface) = window.window_handle().ok()?.as_raw() else {
		return None;
	};
	let size = window.inner_size();
	let (w, h) = (size.width.max(1) as i32, size.height.max(1) as i32);
	// SAFETY: winit keeps the display and surface alive while `window` exists (the whole probe).
	let connection = Connection::from_backend(unsafe {
		Backend::from_foreign_display(display.display.as_ptr().cast())
	});
	let mut queue = connection.new_event_queue::<Shm>();
	let qh = queue.handle();
	let mut shm = Shm::default();
	let _registry = connection.display().get_registry(&qh, ());
	queue.roundtrip(&mut shm).ok()?;
	let shm = shm.0?;
	let mut file = tempfile::tempfile().ok()?;
	let pixel = 0xff31_3338_u32.to_le_bytes();
	file.write_all(&pixel.repeat((w * h) as usize)).ok()?;
	let pool = shm.create_pool(file.as_fd(), w * h * 4, &qh, ());
	let buffer = pool.create_buffer(0, w, h, w * 4, wl_shm::Format::Argb8888, &qh, ());
	let id = unsafe { ObjectId::from_ptr(WlSurface::interface(), surface.surface.as_ptr().cast()) }
		.ok()?;
	let wl_surface = WlSurface::from_id(&connection, id).ok()?;
	wl_surface.attach(Some(&buffer), 0, 0);
	wl_surface.damage_buffer(0, 0, w, h);
	wl_surface.commit();
	queue.roundtrip(&mut Shm::default()).ok()?;
	Some(connection)
}

struct Probe {
	window: Option<Arc<Window>>,
	painted: Option<Connection>,
	captcha: Option<platform::captcha::CaptchaView>,
	opened_at: Instant,
	deadline: Instant,
}

impl ApplicationHandler for Probe {
	fn resumed(&mut self, event_loop: &ActiveEventLoop) {
		if self.window.is_none() {
			let attributes = Window::default_attributes()
				.with_title("Serein dialog probe")
				.with_name("cz.viceverse.serein.dialog-probe", "")
				.with_inner_size(winit::dpi::LogicalSize::new(1100.0, 750.0));
			self.window = Some(Arc::new(
				event_loop.create_window(attributes).expect("window"),
			));
			self.opened_at = Instant::now();
		}
	}

	fn window_event(&mut self, event_loop: &ActiveEventLoop, _: WindowId, event: WindowEvent) {
		if matches!(event, WindowEvent::CloseRequested) {
			event_loop.exit();
		}
	}

	fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
		if Instant::now() >= self.deadline {
			event_loop.exit();
			return;
		}
		let Some(window) = self.window.clone() else {
			return;
		};
		let since = self.opened_at.elapsed();
		if self.painted.is_none() && since > Duration::from_millis(300) {
			self.painted = paint(&window);
			if self.painted.is_none() {
				eprintln!("probe: could not paint the parent (not Wayland?)");
				event_loop.exit();
				return;
			}
		}
		if self.captcha.is_none() && since > Duration::from_millis(1500) {
			let challenge =
				client_core::captcha::Challenge::new(TEST_SITEKEY.into(), None, None, None, false)
					.expect("challenge");
			match platform::captcha::CaptchaView::open(window, &challenge, true, || {}) {
				Ok(view) => self.captcha = Some(view),
				Err(error) => {
					eprintln!("probe: verification window failed: {error}");
					event_loop.exit();
					return;
				}
			}
		}
		if let Some(view) = &self.captcha {
			let _ = view.poll();
		}
		event_loop.set_control_flow(ControlFlow::WaitUntil(
			Instant::now() + Duration::from_millis(16),
		));
	}
}

fn main() {
	let secs = std::env::var("SEREIN_DIALOG_PROBE_SECS")
		.ok()
		.and_then(|v| v.parse().ok())
		.unwrap_or(20);
	let event_loop = EventLoop::new().expect("event loop");
	let mut probe = Probe {
		window: None,
		painted: None,
		captcha: None,
		opened_at: Instant::now(),
		deadline: Instant::now() + Duration::from_secs(secs),
	};
	event_loop.run_app(&mut probe).expect("run");
}
