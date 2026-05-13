use std::sync::{Arc, Mutex};

use std::time::Duration;

use mythkernel::{
    config, db,
    engine::ScanEngine,
    quarantine::QuarantineVault,
    realtime::shields::ShieldsBroker,
    updater::{
        abusech::AbuseChUpdater,
        database::{AbuseChFeedRunner, DatabaseChannel, NsrlFeedRunner},
        engine::EngineChannel,
        nsrl::{NsrlSource, NsrlUpdater},
        scheduler::{self, AbuseChScheduledFeed, ScheduledFeed, SchedulerHandle},
    },
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_updater::UpdaterExt;
use ui_bridge::commands::{AppState, build_pipeline_from_feeds};
use ui_bridge::invoke_handler;

pub mod tray;
use tray::TrayManager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Best-effort tracing init. The engine emits structured logs via the
    // `tracing` crate; the Tauri shell wires up a stderr subscriber so
    // dev builds show what's going on. CLI / mythctl wires its own
    // subscriber elsewhere.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MYTH_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let state = match init_state() {
        Ok(s) => Some(s),
        Err(err) => {
            // We can't open the DB or build the vault. The Tauri shell
            // will still launch but commands will fail until the user
            // resolves the underlying problem (typically a corrupted
            // data dir). tracing logs the cause.
            tracing::error!(error = %err, "engine init failed; running in degraded mode");
            None
        }
    };

    // Spawn the feed auto-updater scheduler (TASK-043). Owns its own
    // task; dropped on app shutdown. The handle is stored in tauri
    // state so the `feed_update_now` command can kick it. When no
    // feeds are configured (e.g. missing abuse.ch auth key) the
    // scheduler idles without making network calls.
    //
    // Phase 5 wave 3 smoke-test fix: `scheduler::spawn` is now
    // runtime-agnostic — it detects `tokio::runtime::Handle::try_current()`
    // and uses the ambient runtime when available, otherwise builds
    // its own `mythkernel-scheduler` thread + current-thread runtime.
    // Prior to that fix, calling it here (before
    // `tauri::Builder::run` starts the runtime) panicked with
    // "no reactor running" and the MSI / NSIS launch produced an
    // invisible crash because the panic had no console output.
    let scheduler_handle = state.as_ref().map(spawn_feed_scheduler);

    // TASK-157 / sec-review L6: `tauri.conf.json :: window.visible = false`
    // keeps the window hidden during plugin init so the autostart flow
    // can decide whether to show it. When the binary launches without
    // `--start-minimized` we show the window from the `setup()` hook
    // below; with `--start-minimized` we leave it hidden until the user
    // clicks the tray icon (TASK-158).
    let start_minimized = std::env::args().any(|a| a == "--start-minimized");

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}))
        // TASK-044 / TASK-130 — engine self-update. Endpoint + ed25519
        // pubkey live in tauri.conf.json :: plugins.updater.
        .plugin(tauri_plugin_updater::Builder::new().build())
        // TASK-157 — start-with-OS auto-launch. `--start-minimized` is
        // the canonical autostart argv; the main window suppresses
        // initial show when this arg is present.
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--start-minimized"]),
        ))
        // TASK-158 — required by the tray menu's "Quit" item to trigger
        // a clean app exit + restart-after-update flow.
        .plugin(tauri_plugin_process::init())
        // Phase 6 — folder/file picker for the Scan target chooser.
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            // TASK-158 — build the system tray icon + menu. Errors are
            // logged but non-fatal: an app without a tray icon is
            // strictly less polished but still functional.
            if let Err(err) = tray::build_tray(app.handle()) {
                tracing::warn!(error = %err, "tray init failed; running without system tray");
            }
            // TASK-158 — share the TrayManager state with frontend
            // commands.
            app.manage(TrayManager::new());

            if !start_minimized && let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            // TASK-158 — close-to-tray: when the user clicks the X on
            // the main window, hide instead of quitting (matching the
            // default config.general.close_action = "minimize_to_tray").
            //
            // Sec-review M3: use `try_lock` instead of `lock` so a
            // slow `settings_update` mid-flight never blocks the
            // window-event thread. Lock contention falls through to
            // the safer "minimize_to_tray" default.
            if let Some(win) = app.get_webview_window("main") {
                let app_for_close = app.handle().clone();
                win.on_window_event(move |evt| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = evt {
                        let close_action = app_for_close
                            .try_state::<ui_bridge::commands::AppState>()
                            .and_then(|s| {
                                s.config
                                    .try_lock()
                                    .ok()
                                    .map(|c| c.general.close_action.clone())
                            })
                            .unwrap_or_else(|| "minimize_to_tray".to_string());
                        if close_action == "minimize_to_tray" {
                            if let Some(w) = app_for_close.get_webview_window("main") {
                                let _ = w.hide();
                            }
                            api.prevent_close();
                        }
                    }
                });
            }
            Ok(())
        });
    if let Some(s) = state {
        builder = builder.manage(s);
    }
    if let Some(h) = scheduler_handle {
        builder = builder.manage(SchedulerSlot(std::sync::Mutex::new(Some(h))));
    }
    builder
        .invoke_handler(tauri::generate_handler![
            engine_install_update,
            autostart_get,
            autostart_set,
            tray_get_state,
            tray_set_scanning,
            tray_set_update_available,
            tray_quick_scan_default_path,
            window_show_main,
            window_hide_main,
            app_quit,
        ])
        .invoke_handler(invoke_handler!())
        .run(tauri::generate_context!())
        .expect("error while running Mythodikal Anti-Virus");
}

// ============================================================================
// Tray + window commands (TASK-158)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
struct TrayStateView {
    icon: String,
    tooltip: String,
}

/// Read the current resolved tray-icon state (TASK-158). Frontend uses
/// this to render the matching badge in the header.
#[tauri::command]
fn tray_get_state(manager: State<'_, TrayManager>) -> TrayStateView {
    let (icon, tooltip) = manager.snapshot();
    TrayStateView {
        icon: icon.as_str().to_string(),
        tooltip,
    }
}

/// Push a "scanning" state into the tray. Called by the frontend scan
/// store at `scan:started` and cleared at terminal events.
#[tauri::command]
fn tray_set_scanning(
    app: AppHandle,
    manager: State<'_, TrayManager>,
    scanning: bool,
) -> TrayStateView {
    let resolved = manager.set_scanning(scanning);
    tray::apply_state(&app, resolved);
    TrayStateView {
        icon: resolved.as_str().to_string(),
        tooltip: resolved.tooltip_string(),
    }
}

/// Push an "update available" state into the tray. Called when the
/// engine channel's `check_for_updates` returns `Some(_)`.
#[tauri::command]
fn tray_set_update_available(
    app: AppHandle,
    manager: State<'_, TrayManager>,
    available: bool,
) -> TrayStateView {
    let resolved = manager.set_update_available(available);
    tray::apply_state(&app, resolved);
    TrayStateView {
        icon: resolved.as_str().to_string(),
        tooltip: resolved.tooltip_string(),
    }
}

#[tauri::command]
fn window_show_main(app: AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

#[tauri::command]
fn window_hide_main(app: AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
}

/// Force-quit the app from the renderer. Sec-review M1: gate on no
/// active scan so a forced exit doesn't kill an in-flight scan mid-iteration
/// (resume tokens flush only at iteration boundaries). The renderer can
/// still bypass the guard by passing `force = true` after surfacing a
/// confirmation modal.
#[tauri::command]
fn app_quit(app: AppHandle, force: Option<bool>) -> Result<(), String> {
    let force = force.unwrap_or(false);
    if !force
        && let Some(state) = app.try_state::<ui_bridge::commands::AppState>()
        && let Ok(flags) = state.active_pause_flags.lock()
        && !flags.is_empty()
    {
        return Err(
            "scan in progress — pass force = true after the user confirms via the mid-scan modal"
                .into(),
        );
    }
    app.exit(0);
    Ok(())
}

/// Return the default target path for the tray-menu "Run quick scan"
/// item (sec-review H1 + code-review CR-I6). Resolves to the *current*
/// user's home dir — not the parent directory of every user's home, which
/// would leak file-existence metadata from sibling accounts into the
/// engine's history DB.
#[tauri::command]
fn tray_quick_scan_default_path() -> Result<String, String> {
    let home = dirs::home_dir()
        .ok_or_else(|| "could not resolve current user's home directory".to_string())?;
    Ok(home.to_string_lossy().to_string())
}

// ============================================================================
// Shell-level Tauri commands that need the AppHandle / plugin extensions
// (cannot live in ui-bridge because they reach into tauri-plugin-* APIs).
// ============================================================================

/// Engine self-update install (TASK-130). Drives the Tauri Updater plugin's
/// `check` + `download_and_install` flow and emits `engine_update:progress`
/// events at ≤ 10 Hz with phases `download | verify | install | restart_pending`
/// so the Settings → Updates → Engine pane can render per-phase bars.
///
/// Returns the new engine version on success. The plugin verifies the
/// ed25519 signature internally against the public key compiled into the
/// app (tauri.conf.json :: plugins.updater.pubkey).
#[tauri::command]
async fn engine_install_update(app: AppHandle) -> Result<String, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let app_for_dl = app.clone();
    let maybe_update = updater.check().await.map_err(|e| e.to_string())?;
    let update = match maybe_update {
        Some(u) => u,
        None => return Err("no update available (run engine_check_for_updates first)".into()),
    };
    let version = update.version.clone();

    // Phase events. The Tauri Updater plugin doesn't expose phase
    // transitions natively; we emit them from this side at the points
    // where the user-visible state changes (download start → bytes
    // streaming → verify+install → restart-pending).
    let _ = app.emit(
        "engine_update:progress",
        &EngineUpdateProgressEvent {
            phase: "download".to_string(),
            bytes_done: 0,
            // Tauri Updater's `Update` doesn't expose total content
            // length up-front for every endpoint shape; the closure
            // below receives the per-chunk total when the server sent
            // `Content-Length`. UI falls back to indeterminate progress
            // when `bytes_total == 0`.
            bytes_total: 0,
            message: format!("Downloading v{version}"),
        },
    );

    let mut bytes_done = 0u64;
    let mut bytes_total_observed = 0u64;
    let app_progress = app.clone();
    update
        .download_and_install(
            move |chunk, maybe_total| {
                bytes_done = bytes_done.saturating_add(chunk as u64);
                if let Some(t) = maybe_total
                    && t > bytes_total_observed
                {
                    bytes_total_observed = t;
                }
                let _ = app_progress.emit(
                    "engine_update:progress",
                    &EngineUpdateProgressEvent {
                        phase: "download".to_string(),
                        bytes_done,
                        bytes_total: bytes_total_observed,
                        message: String::new(),
                    },
                );
            },
            move || {
                let _ = app_for_dl.emit(
                    "engine_update:progress",
                    &EngineUpdateProgressEvent {
                        phase: "verify".to_string(),
                        bytes_done: 0,
                        bytes_total: 0,
                        message: "Verifying ed25519 signature".to_string(),
                    },
                );
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    let _ = app.emit(
        "engine_update:progress",
        &EngineUpdateProgressEvent {
            phase: "install".to_string(),
            bytes_done: 0,
            bytes_total: 0,
            message: "Installing".to_string(),
        },
    );
    let _ = app.emit(
        "engine_update:progress",
        &EngineUpdateProgressEvent {
            phase: "restart_pending".to_string(),
            bytes_done: 0,
            bytes_total: 0,
            message: format!("v{version} installed; restart to apply"),
        },
    );

    Ok(version)
}

/// TS-side mirror of `mythkernel::updater::engine::EngineUpdateProgress`.
/// Re-declared here to avoid pulling the kernel type through the Tauri
/// event serializer (which has its own derive constraints).
#[derive(Debug, Clone, Serialize)]
struct EngineUpdateProgressEvent {
    phase: String,
    bytes_done: u64,
    bytes_total: u64,
    message: String,
}

/// Read the OS autostart state (FR-161 / TASK-157). Mirrors the Tauri
/// Autostart plugin so the UI's "Start with operating system" toggle
/// reflects the OS truth on every render.
#[tauri::command]
async fn autostart_get(app: AppHandle) -> Result<AutostartView, String> {
    let manager = app.autolaunch();
    let enabled = manager.is_enabled().map_err(|e| e.to_string())?;
    Ok(AutostartView {
        enabled,
        mechanism: autostart_mechanism().to_string(),
    })
}

/// Flip the OS autostart state. Idempotent.
#[tauri::command]
async fn autostart_set(app: AppHandle, enabled: bool) -> Result<AutostartView, String> {
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    autostart_get(app).await
}

#[derive(Debug, Clone, Serialize)]
struct AutostartView {
    enabled: bool,
    mechanism: String,
}

fn autostart_mechanism() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "~/.config/autostart/mythodikal.desktop"
    }
    #[cfg(target_os = "macos")]
    {
        "SMAppService LoginItem"
    }
    #[cfg(target_os = "windows")]
    {
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown"
    }
}

/// Wrapper around the scheduler handle so we can `App::manage()` it
/// even though `SchedulerHandle` is not `Sync`. The Option lets us
/// `take()` it on shutdown.
pub struct SchedulerSlot(pub std::sync::Mutex<Option<SchedulerHandle>>);

fn spawn_feed_scheduler(state: &ui_bridge::commands::AppState) -> SchedulerHandle {
    let feeds_dir = ui_bridge::commands::feeds_dir(&state.data_dir);
    let cfg = state.config.lock().map(|g| g.clone()).unwrap_or_default();
    let interval = if cfg.updater.auto_update_enabled {
        Duration::from_secs(cfg.updater.interval_hours.max(1) as u64 * 3600)
    } else {
        // Sentinel — when auto-update is disabled we still spawn the
        // task (so manual kicks can run feeds) but with an interval far
        // beyond any realistic session so it never fires on its own.
        Duration::from_secs(365 * 24 * 3600)
    };
    let mut feeds: Vec<Box<dyn ScheduledFeed>> = Vec::new();
    if !cfg.updater.abusech_auth_key.trim().is_empty() {
        let updater =
            AbuseChUpdater::new(cfg.updater.abusech_auth_key.trim().to_string(), &feeds_dir);
        feeds.push(Box::new(AbuseChScheduledFeed::new(updater)));
    } else {
        tracing::info!(
            "feed scheduler: abuse.ch auth key not configured — scheduled abuse.ch refresh disabled"
        );
    }
    scheduler::spawn(feeds, feeds_dir, interval)
}

fn init_state() -> Result<AppState, Box<dyn std::error::Error>> {
    let data_dir = db::default_data_dir()?;
    let db_path = data_dir.join("mythodikal.db");
    let conn = db::open(&db_path)?;
    let db = Arc::new(Mutex::new(conn));

    // Build the pipeline from whatever .bin feeds exist on disk. First
    // run has no feeds — that's fine; users add them via `mythctl feed
    // update` or Settings → Updates (Phase 4).
    let pipeline = build_pipeline_from_feeds(&data_dir);
    let pipeline_count = pipeline.len();

    // The engine writes via its own SQLite Connection so its scan
    // worker doesn't contend with command-side reads on the
    // Arc<Mutex<Connection>>. Both handles open the same DB file in
    // WAL mode (configured in db::configure_connection) so engine
    // writes are visible to command reads after the engine's tx
    // commits. The Tauri commands read via `state.db`; the engine
    // writes via its own internal handle.
    let engine_conn = db::open(&db_path)?;
    let engine = Arc::new(ScanEngine::new(engine_conn).with_detection_pipeline(pipeline));

    let vault = Arc::new(
        QuarantineVault::new(&data_dir).map_err(|e| format!("open quarantine vault: {e}"))?,
    );

    // FR-160 / TASK-156 — master Shields kill-switch. Default ON;
    // persists across restart at `<data_dir>/shields.json`. Phase 4
    // ships the architecture only; daemons in Phases 8/9/12 will
    // subscribe to ShieldsBroker::subscribe() and translate the state
    // into their platform's ALLOW-everything mode when OFF.
    let shields =
        ShieldsBroker::open(&data_dir).map_err(|e| format!("open shields broker: {e}"))?;

    // TASK-041 — load the user's TOML config so settings_get / _update
    // can read and persist live values. Missing file returns defaults;
    // parse errors fail the load and we fall back to defaults with a
    // log line (preferring a working app over a non-bootable one when
    // the user has hand-edited the file).
    let config_path = config::default_config_path()?;
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %config_path.display(),
                "config load failed; using defaults"
            );
            config::Config::default()
        }
    };
    let config_state = Arc::new(Mutex::new(cfg));

    tracing::info!(
        data_dir = %data_dir.display(),
        detectors = pipeline_count,
        shields_enabled = shields.get().enabled,
        config_path = %config_path.display(),
        "engine initialized"
    );

    let updater_engine = Arc::new(EngineChannel::new(&data_dir, env!("CARGO_PKG_VERSION")));
    let updater_db = Arc::new(build_database_channel(&data_dir));

    Ok(AppState {
        engine,
        db,
        vault,
        shields,
        config: config_state,
        config_path,
        active_pause_flags: Arc::new(Mutex::new(std::collections::HashMap::new())),
        active_cancel_flags: Arc::new(Mutex::new(std::collections::HashMap::new())),
        data_dir,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        updater_engine,
        updater_db,
    })
}

/// Build the database update channel with the currently-supported feed
/// runners (TASK-131). The channel itself is configured once at startup;
/// per-cycle execution happens in response to user-clicked "Check now"
/// or the auto-update timer.
fn build_database_channel(data_dir: &std::path::Path) -> DatabaseChannel {
    let feeds_dir = ui_bridge::commands::feeds_dir(data_dir);
    let mut channel = DatabaseChannel::new(data_dir);
    // Always register feeds at startup so manual "Check now" works
    // without the user having configured an auth-key first; the
    // adapter itself fails fast when the key is empty.
    let abusech_auth_key = std::env::var("MYTHODIKAL_ABUSECH_AUTH_KEY").unwrap_or_default();
    if !abusech_auth_key.is_empty() {
        let updater = AbuseChUpdater::new(abusech_auth_key, &feeds_dir);
        channel = channel.register(AbuseChFeedRunner::new(updater));
    }
    let nsrl_local = std::env::var("MYTHODIKAL_NSRL_LOCAL").unwrap_or_default();
    if !nsrl_local.is_empty() {
        let updater = NsrlUpdater::new(NsrlSource::Local(nsrl_local.into()), &feeds_dir);
        channel = channel.register(NsrlFeedRunner::new(updater));
    }
    let registered: Vec<&str> = channel.iter_feed_ids().collect();
    tracing::info!(
        feeds = ?registered,
        "database channel built ({} feeds registered)",
        registered.len()
    );
    channel
}
