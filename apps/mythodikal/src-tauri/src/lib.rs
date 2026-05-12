use std::sync::{Arc, Mutex};

use mythkernel::{db, engine::ScanEngine, quarantine::QuarantineVault};
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

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}));
    if let Some(s) = state {
        builder = builder.manage(s);
    }
    builder
        .invoke_handler(invoke_handler!())
        .run(tauri::generate_context!())
        .expect("error while running Mythodikal Anti-Virus");
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

    // Engine shares the same Connection via the Mutex so commands can
    // read scan/findings rows the engine just wrote without a race.
    let engine_conn = db::open(&db_path)?;
    let engine = Arc::new(ScanEngine::new(engine_conn).with_detection_pipeline(pipeline));

    let vault = Arc::new(
        QuarantineVault::new(&data_dir).map_err(|e| format!("open quarantine vault: {e}"))?,
    );

    tracing::info!(
        data_dir = %data_dir.display(),
        detectors = pipeline_count,
        "engine initialized"
    );

    Ok(AppState {
        engine,
        db,
        vault,
        data_dir,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
