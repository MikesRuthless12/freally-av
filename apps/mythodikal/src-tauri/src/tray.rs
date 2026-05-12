//! System tray icon + menu (TASK-158, Phase 4 wave 6).
//!
//! Implements FR-162. The tray icon is the Mythodikal `M` glyph in one of
//! four states; right-clicking it surfaces the FR-162.5-normative menu.
//! macOS uses a 22×22 monochrome template image so the menu bar can recolor
//! it; Linux uses StatusNotifierItem via the Tauri v2 tray API; Windows
//! uses 16×16/32×32 multi-DPI icons.
//!
//! State machine priority (highest wins): `shields_off` > `update_available`
//! > `scanning` > `idle`.
//!
//! The state mutates in response to shields / engine-update / scan progress
//! events; the [`TrayManager`] owns the current state and is `App::manage()`'d
//! so the frontend can read it via `tray_get_state` and Rust-side hooks
//! (e.g. scan start) can push updates.
//!
//! **Menu items** (FR-162.5 normative):
//!   1. Show / Hide main window
//!   2. Shields ▸ Turn Off / Pause 15 min / Pause 1 h / Pause until restart
//!   3. Run quick scan
//!   4. Check for app updates
//!   5. Check for virus database updates
//!   6. Quit Mythodikal

use std::sync::{Arc, Mutex};

use mythkernel::realtime::shields::ShieldsActor;
use serde::Serialize;
use tauri::{
    AppHandle, Emitter, Manager, Wry,
    image::Image,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

/// One of the four tray-icon states (FR-162). Stable wire string set
/// because the TS-side store keys on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayIconState {
    Idle,
    Scanning,
    ShieldsOff,
    UpdateAvailable,
}

impl TrayIconState {
    pub fn as_str(self) -> &'static str {
        match self {
            TrayIconState::Idle => "idle",
            TrayIconState::Scanning => "scanning",
            TrayIconState::ShieldsOff => "shields_off",
            TrayIconState::UpdateAvailable => "update_available",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            TrayIconState::Idle => "Mythodikal Anti-Virus — idle",
            TrayIconState::Scanning => "Mythodikal Anti-Virus — scanning",
            TrayIconState::ShieldsOff => "Mythodikal Anti-Virus — Shields OFF",
            TrayIconState::UpdateAvailable => "Mythodikal Anti-Virus — update available",
        }
    }

    /// Owned `String` variant of [`Self::tooltip`]. Code-review CR-I13
    /// — replaces the duplicate `tray_tooltip_for` helper in lib.rs.
    pub fn tooltip_string(self) -> String {
        self.tooltip().to_string()
    }

    /// Resolve the platform-appropriate icon bytes for this state.
    /// On macOS we use the 22×22 monochrome template variant so the
    /// menu bar can recolor it for light/dark mode.
    fn icon_bytes(self) -> &'static [u8] {
        match self {
            #[cfg(target_os = "macos")]
            TrayIconState::Idle => include_bytes!("../icons/tray-idle-mac-22.png"),
            #[cfg(target_os = "macos")]
            TrayIconState::Scanning => include_bytes!("../icons/tray-scanning-mac-22.png"),
            #[cfg(target_os = "macos")]
            TrayIconState::ShieldsOff => include_bytes!("../icons/tray-shields_off-mac-22.png"),
            #[cfg(target_os = "macos")]
            TrayIconState::UpdateAvailable => {
                include_bytes!("../icons/tray-update_available-mac-22.png")
            }
            #[cfg(not(target_os = "macos"))]
            TrayIconState::Idle => include_bytes!("../icons/tray-idle-32.png"),
            #[cfg(not(target_os = "macos"))]
            TrayIconState::Scanning => include_bytes!("../icons/tray-scanning-32.png"),
            #[cfg(not(target_os = "macos"))]
            TrayIconState::ShieldsOff => include_bytes!("../icons/tray-shields_off-32.png"),
            #[cfg(not(target_os = "macos"))]
            TrayIconState::UpdateAvailable => {
                include_bytes!("../icons/tray-update_available-32.png")
            }
        }
    }
}

/// Inputs that drive the priority state machine. The manager combines them
/// per FR-162: `shields_off` > `update_available` > `scanning` > `idle`.
#[derive(Debug, Clone, Default)]
pub struct TrayStateInputs {
    pub shields_off: bool,
    pub update_available: bool,
    pub scanning: bool,
}

impl TrayStateInputs {
    pub fn resolve(&self) -> TrayIconState {
        if self.shields_off {
            TrayIconState::ShieldsOff
        } else if self.update_available {
            TrayIconState::UpdateAvailable
        } else if self.scanning {
            TrayIconState::Scanning
        } else {
            TrayIconState::Idle
        }
    }
}

/// Tray state managed by the Tauri shell. `App::manage()`-stored so
/// frontend commands can read it without re-running the priority
/// computation, and Rust-side hooks (scan start, shields:changed
/// subscribers) can push updates via `set_*` helpers.
pub struct TrayManager {
    inputs: Mutex<TrayStateInputs>,
}

impl TrayManager {
    pub fn new() -> Self {
        Self {
            inputs: Mutex::new(TrayStateInputs::default()),
        }
    }

    pub fn snapshot(&self) -> (TrayIconState, String) {
        let inputs = self
            .inputs
            .lock()
            .expect("tray inputs mutex poisoned (holder panicked)");
        let state = inputs.resolve();
        (state, state.tooltip().to_string())
    }

    pub fn set_shields_off(&self, off: bool) -> TrayIconState {
        let mut inputs = self
            .inputs
            .lock()
            .expect("tray inputs mutex poisoned (holder panicked)");
        inputs.shields_off = off;
        inputs.resolve()
    }

    pub fn set_update_available(&self, avail: bool) -> TrayIconState {
        let mut inputs = self
            .inputs
            .lock()
            .expect("tray inputs mutex poisoned (holder panicked)");
        inputs.update_available = avail;
        inputs.resolve()
    }

    pub fn set_scanning(&self, scanning: bool) -> TrayIconState {
        let mut inputs = self
            .inputs
            .lock()
            .expect("tray inputs mutex poisoned (holder panicked)");
        inputs.scanning = scanning;
        inputs.resolve()
    }
}

impl Default for TrayManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Build + register the tray icon + menu at app startup. Returns the
/// TrayIcon so the caller can `App::manage()` it if desired. The menu
/// callback runs on Tauri's event loop and dispatches per FR-162.5.
pub fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_menu(app)?;

    let initial_state = TrayIconState::Idle;
    let icon = Image::from_bytes(initial_state.icon_bytes())?;
    let tray = TrayIconBuilder::with_id("mythodikal-tray")
        .icon(icon)
        .tooltip(initial_state.tooltip())
        .menu(&menu)
        // macOS tray icons must declare themselves as template images so
        // the menu bar can recolor them for light/dark mode.
        .icon_as_template(cfg!(target_os = "macos"))
        .on_menu_event(handle_menu_event)
        .on_tray_icon_event(handle_tray_event)
        .build(app)?;

    // Keep the tray icon alive for the lifetime of the app by handing
    // it to the Tauri state manager.
    app.manage(TrayHandle(Arc::new(Mutex::new(Some(tray)))));
    Ok(())
}

/// Hand-rolled wrapper so the tray icon is `Send + Sync` for storage in
/// Tauri state. Option lets us `take()` it on teardown.
pub struct TrayHandle(pub Arc<Mutex<Option<tauri::tray::TrayIcon<Wry>>>>);

fn build_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    // Item ids are stable wire strings — referenced by the menu-event
    // handler below. New menu items MUST add a matching arm to
    // handle_menu_event.
    let show_hide = MenuItem::with_id(
        app,
        "show_hide",
        "Show / Hide main window",
        true,
        None::<&str>,
    )?;

    let shields_off = MenuItem::with_id(app, "shields_off", "Turn Off", true, None::<&str>)?;
    let shields_pause_15 =
        MenuItem::with_id(app, "shields_pause_15", "Pause 15 min", true, None::<&str>)?;
    let shields_pause_60 =
        MenuItem::with_id(app, "shields_pause_60", "Pause 1 h", true, None::<&str>)?;
    let shields_pause_until_restart = MenuItem::with_id(
        app,
        "shields_pause_until_restart",
        "Pause until restart",
        true,
        None::<&str>,
    )?;
    let shields_on = MenuItem::with_id(app, "shields_on", "Turn On", true, None::<&str>)?;
    let shields_submenu = Submenu::with_items(
        app,
        "Shields",
        true,
        &[
            &shields_on,
            &shields_off,
            &PredefinedMenuItem::separator(app)?,
            &shields_pause_15,
            &shields_pause_60,
            &shields_pause_until_restart,
        ],
    )?;

    let quick_scan = MenuItem::with_id(app, "quick_scan", "Run quick scan", true, None::<&str>)?;
    let check_app = MenuItem::with_id(
        app,
        "check_app",
        "Check for app updates",
        true,
        None::<&str>,
    )?;
    let check_db = MenuItem::with_id(
        app,
        "check_db",
        "Check for virus database updates",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit Mythodikal", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &show_hide,
            &PredefinedMenuItem::separator(app)?,
            &shields_submenu,
            &quick_scan,
            &PredefinedMenuItem::separator(app)?,
            &check_app,
            &check_db,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    Ok(menu)
}

fn handle_menu_event(app: &AppHandle, event: MenuEvent) {
    // The frontend has the contextual state (current scan, ShieldsBroker
    // pause durations, etc.) so we mostly translate menu events into
    // Tauri events that the renderer picks up. Items that don't need
    // renderer state (quit, show/hide window) execute server-side.
    let id = event.id.as_ref();
    match id {
        "show_hide" => toggle_main_window(app),
        "quit" => {
            // Surface a "quit requested" event so the renderer can pop
            // a mid-scan confirmation modal if needed. The renderer is
            // responsible for calling `app_quit` (which is itself
            // scan-aware per sec-review M1) after the user confirms.
            let _ = app.emit("tray:quit_requested", ());
            show_main_window(app);
        }
        "shields_on" => trigger_shields(app, true, None),
        "shields_off" => trigger_shields(app, false, None),
        "shields_pause_15" => trigger_shields(app, false, Some(15)),
        "shields_pause_60" => trigger_shields(app, false, Some(60)),
        // Code-review CR-I4: a "Pause until restart" is semantically a
        // very long pause, not the same as "Turn Off". We use 30 days
        // as the sentinel — the shields broker auto-resumes shields-on
        // at the end of the pause, and 30 days is longer than any
        // realistic session (the user will reboot or restart Mythodikal
        // well before that).
        "shields_pause_until_restart" => trigger_shields(app, false, Some(30 * 24 * 60)),
        "quick_scan" => {
            let _ = app.emit("tray:quick_scan_requested", ());
            show_main_window(app);
        }
        "check_app" => {
            let _ = app.emit("tray:check_app_requested", ());
            show_main_window(app);
        }
        "check_db" => {
            let _ = app.emit("tray:check_db_requested", ());
            show_main_window(app);
        }
        other => {
            tracing::warn!(menu_id = %other, "unknown tray menu id");
        }
    }
}

fn handle_tray_event(tray: &tauri::tray::TrayIcon<Wry>, event: TrayIconEvent) {
    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Up,
        ..
    } = event
    {
        toggle_main_window(tray.app_handle());
    }
}

fn toggle_main_window(app: &AppHandle) {
    let Some(win) = app.get_webview_window("main") else {
        return;
    };
    match win.is_visible() {
        Ok(true) => {
            let _ = win.hide();
        }
        _ => {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

fn trigger_shields(app: &AppHandle, enabled: bool, pause_minutes: Option<u32>) {
    // The ShieldsBroker is owned by `AppState`; we reach it via
    // `app.state::<AppState>()`. Errors are best-effort — failure to
    // toggle from the tray menu shouldn't crash the app.
    let Some(state) = app.try_state::<ui_bridge::commands::AppState>() else {
        tracing::warn!("tray: ShieldsBroker unavailable (AppState not yet managed)");
        return;
    };
    match state
        .shields
        .set(enabled, pause_minutes, ShieldsActor::Tray)
    {
        Ok(next) => {
            if let Err(err) = app.emit("shields:changed", &next) {
                tracing::warn!(error = %err, "tray: shields:changed emit failed");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "tray: shields.set failed");
        }
    }
}

/// Push a new tray-icon state into the live TrayIcon. The TrayManager
/// also persists the new resolved state.
pub fn apply_state(app: &AppHandle, state: TrayIconState) {
    let Some(handle) = app.try_state::<TrayHandle>() else {
        return;
    };
    let guard = handle.0.lock();
    let Ok(guard) = guard else { return };
    let Some(tray) = guard.as_ref() else { return };
    if let Ok(img) = Image::from_bytes(state.icon_bytes()) {
        let _ = tray.set_icon(Some(img));
    }
    let _ = tray.set_tooltip(Some(state.tooltip()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_resolution_picks_highest() {
        let mut inputs = TrayStateInputs::default();
        assert_eq!(inputs.resolve(), TrayIconState::Idle);
        inputs.scanning = true;
        assert_eq!(inputs.resolve(), TrayIconState::Scanning);
        inputs.update_available = true;
        // update_available wins over scanning
        assert_eq!(inputs.resolve(), TrayIconState::UpdateAvailable);
        inputs.shields_off = true;
        // shields_off wins over everything
        assert_eq!(inputs.resolve(), TrayIconState::ShieldsOff);
    }

    #[test]
    fn priority_falls_back_to_lower_when_higher_clears() {
        let mut inputs = TrayStateInputs {
            shields_off: true,
            update_available: true,
            scanning: true,
        };
        assert_eq!(inputs.resolve(), TrayIconState::ShieldsOff);
        inputs.shields_off = false;
        assert_eq!(inputs.resolve(), TrayIconState::UpdateAvailable);
        inputs.update_available = false;
        assert_eq!(inputs.resolve(), TrayIconState::Scanning);
        inputs.scanning = false;
        assert_eq!(inputs.resolve(), TrayIconState::Idle);
    }

    #[test]
    fn state_wire_strings_are_stable() {
        assert_eq!(TrayIconState::Idle.as_str(), "idle");
        assert_eq!(TrayIconState::Scanning.as_str(), "scanning");
        assert_eq!(TrayIconState::ShieldsOff.as_str(), "shields_off");
        assert_eq!(TrayIconState::UpdateAvailable.as_str(), "update_available");
    }

    #[test]
    fn tray_manager_set_round_trips() {
        let m = TrayManager::new();
        assert_eq!(m.snapshot().0, TrayIconState::Idle);
        assert_eq!(m.set_scanning(true), TrayIconState::Scanning);
        assert_eq!(m.snapshot().0, TrayIconState::Scanning);
        assert_eq!(m.set_update_available(true), TrayIconState::UpdateAvailable);
        assert_eq!(m.set_shields_off(true), TrayIconState::ShieldsOff);
        // Clearing scanning leaves update_available + shields_off; shields still wins.
        assert_eq!(m.set_scanning(false), TrayIconState::ShieldsOff);
    }

    #[test]
    fn tooltips_include_brand_name() {
        for s in [
            TrayIconState::Idle,
            TrayIconState::Scanning,
            TrayIconState::ShieldsOff,
            TrayIconState::UpdateAvailable,
        ] {
            assert!(s.tooltip().contains("Mythodikal"), "{}", s.as_str());
        }
    }

    #[test]
    fn manager_default_matches_new() {
        let from_new = TrayManager::new();
        let from_default = TrayManager::default();
        assert_eq!(from_new.snapshot().0, from_default.snapshot().0);
    }
}
