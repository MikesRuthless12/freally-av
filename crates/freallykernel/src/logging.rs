//! Tracing + structured logs.
//!
//! TASK-014 (Phase 1) — wires `tracing` to a JSON layer that writes
//! daily-rolling files at `<data_dir>/logs/freally.log.YYYY-MM-DD`.
//! The level is read from the `MYTH_LOG` env var (`info` by default).
//!
//! Per FR-100, default retention is 7 days; the rolling layer handles file
//! rotation, but pruning past 7 days is the engine's responsibility (the
//! scheduled-task work in Phase 10 will hook this in).

use std::path::{Path, PathBuf};

use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::error::EngineError;

/// Resolve the canonical engine log directory (`<data_dir>/logs/`), creating
/// it on demand. Returns the directory path so callers can quote it in their
/// startup banner.
pub fn default_log_dir() -> Result<PathBuf, EngineError> {
    let data = crate::db::default_data_dir()?;
    let dir = data.join("logs");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Initialize tracing with a daily-rolling JSON file appender at `log_dir`.
///
/// The returned [`WorkerGuard`] must be kept alive for the lifetime of the
/// process — dropping it flushes the non-blocking writer. Loose use:
///
/// ```ignore
/// let _guard = freallykernel::logging::init(&freallykernel::logging::default_log_dir()?)?;
/// ```
pub fn init(log_dir: &Path) -> Result<WorkerGuard, EngineError> {
    std::fs::create_dir_all(log_dir)?;

    let file_appender = rolling::daily(log_dir, "freally.log");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_env("MYTH_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    let json_layer = fmt::layer().json().with_writer(writer).with_target(true);

    // Use `.try_init()` so callers can call `init()` more than once across
    // tests / repeated bootstraps without panicking on the global subscriber.
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .try_init();

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_log_dir_and_writes() {
        let dir = tempdir().unwrap();
        let log_dir = dir.path().join("logs");
        let _guard = init(&log_dir).unwrap();
        assert!(log_dir.exists());
        tracing::info!(test_event = "hello");
        // The non-blocking writer flushes when guard drops at end of scope.
    }
}
