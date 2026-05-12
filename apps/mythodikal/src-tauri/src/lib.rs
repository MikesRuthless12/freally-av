use std::sync::{Arc, Mutex};

use std::time::Duration;

use mythkernel::{
    config, db,
    engine::ScanEngine,
    quarantine::QuarantineVault,
    realtime::shields::ShieldsBroker,
    updater::{
        abusech::AbuseChUpdater,
        scheduler::{self, AbuseChScheduledFeed, ScheduledFeed, SchedulerHandle},
    },
};
use ui_bridge::commands::{AppState, build_pipeline_from_feeds};
use ui_bridge::invoke_handler;

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
    let scheduler_handle = state.as_ref().map(spawn_feed_scheduler);

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}));
    if let Some(s) = state {
        builder = builder.manage(s);
    }
    if let Some(h) = scheduler_handle {
        builder = builder.manage(SchedulerSlot(std::sync::Mutex::new(Some(h))));
    }
    builder
        .invoke_handler(invoke_handler!())
        .run(tauri::generate_context!())
        .expect("error while running Mythodikal Anti-Virus");
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

    Ok(AppState {
        engine,
        db,
        vault,
        shields,
        config: config_state,
        config_path,
        active_pause_flags: Arc::new(Mutex::new(std::collections::HashMap::new())),
        data_dir,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
