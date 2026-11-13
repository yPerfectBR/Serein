//! Parents the GTK login and verification windows to Serein's winit window on Wayland.
//!
//! GTK and winit hold separate Wayland connections, so `xdg_toplevel.set_parent` cannot link them.
//! Instead Serein's toplevel is exported through xdg-foreign-unstable-v2 on winit's own connection
//! and GTK imports that handle. Compositors then treat the WebKit window as a dialog of Serein
//! (centered over it, on the same workspace or scratchpad) instead of an unrelated application.
//! Anything unsupported (X11, no exporter global) leaves the window standalone, as before.
#![allow(unsafe_code)]

use gtk4::prelude::*;
use std::sync::Arc;
use wayland_client::{
	Connection, Dispatch, EventQueue, Proxy, QueueHandle,
	backend::{Backend, ObjectId},
	delegate_noop,
	protocol::{wl_registry, wl_surface::WlSurface},
};
use wayland_protocols::xdg::foreign::zv2::client::{
	zxdg_exported_v2::{self, ZxdgExportedV2},
	zxdg_exporter_v2::ZxdgExporterV2,
};
use winit::raw_window_handle::{
	HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle,
};

/// Keeps Serein's toplevel exported while the dialog is open; dropping it revokes the handle.
pub(crate) struct ExportedParent {
	exported: ZxdgExportedV2,
	connection: Connection,
	_queue: EventQueue<State>,
	// The exported wl_surface belongs to this window; hold it for the export's lifetime.
	_parent: Arc<winit::window::Window>,
}

impl Drop for ExportedParent {
	fn drop(&mut self) {
		self.exported.destroy();
		let _ = self.connection.flush();
	}
}

#[derive(Default)]
struct State {
	exporter: Option<ZxdgExporterV2>,
	handle: Option<String>,
}

impl Dispatch<wl_registry::WlRegistry, ()> for State {
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
		} = event && interface == ZxdgExporterV2::interface().name
		{
			state.exporter = Some(registry.bind(name, 1, qh, ()));
		}
	}
}

delegate_noop!(State: ignore ZxdgExporterV2);

impl Dispatch<ZxdgExportedV2, ()> for State {
	fn event(
		state: &mut Self,
		_: &ZxdgExportedV2,
		event: zxdg_exported_v2::Event,
		_: &(),
		_: &Connection,
		_: &QueueHandle<Self>,
	) {
		if let zxdg_exported_v2::Event::Handle { handle } = event {
			state.handle = Some(handle);
		}
	}
}

/// Makes `window` a modal dialog of `parent`. Call before the window is presented.
pub(crate) fn attach(
	window: &gtk4::Window,
	parent: Arc<winit::window::Window>,
) -> Option<ExportedParent> {
	let RawDisplayHandle::Wayland(display) = parent.display_handle().ok()?.as_raw() else {
		return None;
	};
	let RawWindowHandle::Wayland(surface) = parent.window_handle().ok()?.as_raw() else {
		return None;
	};
	WidgetExt::realize(window);
	let toplevel = window
		.surface()?
		.downcast::<gdk4_wayland::WaylandToplevel>()
		.ok()?;
	// SAFETY: winit owns the wl_display for the process lifetime and the wl_surface for as long as
	// `parent` lives; `ExportedParent` keeps `parent` alive for as long as these proxies are used.
	// Our objects live on a private event queue, so winit's dispatching never sees them.
	let backend = unsafe { Backend::from_foreign_display(display.display.as_ptr().cast()) };
	let connection = Connection::from_backend(backend);
	let mut queue = connection.new_event_queue::<State>();
	let qh = queue.handle();
	let mut state = State::default();
	let _registry = connection.display().get_registry(&qh, ());
	queue.roundtrip(&mut state).ok()?;
	let exporter = state.exporter.take()?;
	// SAFETY: see above; the pointer is winit's live wl_surface proxy.
	let id = unsafe { ObjectId::from_ptr(WlSurface::interface(), surface.surface.as_ptr().cast()) }
		.ok()?;
	let wl_surface = WlSurface::from_id(&connection, id).ok()?;
	let exported = exporter.export_toplevel(&wl_surface, &qh, ());
	exporter.destroy();
	queue.roundtrip(&mut state).ok()?;
	let Some(handle) = state.handle.take() else {
		exported.destroy();
		return None;
	};

	if !toplevel.set_transient_for_exported(&handle) {
		exported.destroy();
		return None;
	}
	window.set_modal(true);
	Some(ExportedParent {
		exported,
		connection,
		_queue: queue,
		_parent: parent,
	})
}
