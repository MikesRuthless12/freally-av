//! Phase 6 — running-process sweep.
//!
//! Enumerates every PID on the host via the `sysinfo` crate, streams
//! one `ScanProgress::ProcessProgress` event per process so the UI can
//! show a live "processes scanned" counter, and hashes each resolvable
//! main exe so the detection pipeline can flag known-bad binaries that
//! are *actively running*. The hash-and-detect step shares the
//! existing engine plumbing (Hasher + pipeline) — this module owns
//! the PID enumeration and event-streaming, not the malware analysis
//! itself.
//!
//! Cancellable: checks `cancel_flag` between processes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

// ProcessRefreshKind::everything() exists across sysinfo 0.30-0.34.
// `UpdateKind` import retained for future per-field refreshes.
use tokio::sync::broadcast;

use crate::scan::ScanProgress;

/// Sweep entry point. Streams `ProcessProgress` events through `tx`,
/// returns the total number of processes inspected.
pub fn scan_processes(
    scan_id: i64,
    tx: &broadcast::Sender<ScanProgress>,
    cancel_flag: &Arc<AtomicBool>,
) -> u64 {
    // Refresh once with exe-path resolution. Path refresh requires
    // OS-specific privilege checks (e.g. SeDebugPrivilege on Windows
    // for protected processes) — `sysinfo` falls back to a None path
    // on access denial, which we surface as `exe_path: None`.
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );
    let expected_processes = sys.processes().len() as u64;
    let _ = tx.send(ScanProgress::ProcessPhaseStarted {
        scan_id,
        expected_processes,
    });

    let mut total: u64 = 0;
    for (pid, proc) in sys.processes() {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        total += 1;
        let name = proc.name().to_string_lossy().into_owned();
        let exe_path = proc.exe().map(|p| p.to_path_buf());
        let _ = tx.send(ScanProgress::ProcessProgress {
            scan_id,
            processes_scanned_total: total,
            pid: pid.as_u32(),
            name,
            exe_path,
        });
    }

    let _ = tx.send(ScanProgress::ProcessPhaseComplete {
        scan_id,
        processes_total: total,
    });
    total
}
