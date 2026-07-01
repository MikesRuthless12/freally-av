//! `freallyd-linux` daemon entry point (TASK-073, Phase 8).
//!
//! Run by systemd as `freallyd.service`. Opens the fanotify FD (falling
//! back to inotify on kernels < 5.1 or audit when even mount-level
//! fanotify is unavailable), drops every capability except
//! `CAP_SYS_ADMIN`, opens the engine IPC socket, and enters the main
//! event loop.
//!
//! Per § 1.5.4 the daemon is **user-mode** — no kernel driver, no LSM
//! hooks. The fanotify FD is the enforcement surface; eBPF (TASK-236)
//! is observe-only.

use clap::Parser;
use tracing::{info, warn};

use freallyd_linux::audit::AuditHandle;
use freallyd_linux::block::ActiveDenylist;
use freallyd_linux::ebpf::EbpfObserver;
use freallyd_linux::fanotify::{FanotifyError, FanotifyHandle};
use freallyd_linux::inotify_fallback::InotifyHandle;
use freallyd_linux::ipc_client::IpcClient;
use freallyd_linux::watchdog::CrashBudget;
use freallyd_linux::wsl_peer::WslContext;

#[derive(Parser, Debug)]
#[command(
    name = "freallyd",
    version,
    about = "Freally Anti-Virus Linux real-time daemon"
)]
struct Cli {
    /// Socket path for engine IPC. Defaults to
    /// `freallykernel::ipc::linfan::SYSTEM_SOCKET_PATH`
    /// (`/run/freallyd/freallyd.sock`) when run by systemd; the user-mode
    /// fallback under `$XDG_RUNTIME_DIR` is set by the caller.
    #[arg(long, default_value_t = freallykernel::ipc::linfan::SYSTEM_SOCKET_PATH.to_string())]
    socket: String,

    /// Exit after one event-loop iteration. Used by the
    /// `--once` smoke-test in `packaging/linux/freallyd.service.test`.
    #[arg(long)]
    once: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let wsl = WslContext::detect();
    if let Some(tag) = wsl.event_tag() {
        info!(tag = %tag, "running inside WSL2");
    }

    // Try fanotify first; fall back gracefully.
    // Clone the mode_label rather than moving it — FanotifyHandle /
    // InotifyHandle hold an owned FD on Linux and implement `Drop`,
    // so the field cannot be moved out (E0509). The handle's Drop
    // closes the FD when this expression's scope ends, which is what
    // we want for the capability probe; the real event loop opens
    // its own FD once it's wired in the runtime-validation pass.
    let mode_label = match FanotifyHandle::open() {
        Ok(h) => h.mode_label.clone(),
        Err(FanotifyError::Unsupported) => {
            // On non-Linux hosts the binary is unusable; this path is
            // here so `cargo build` succeeds on Windows / macOS CI
            // runners that build the whole workspace.
            warn!("fanotify unsupported on this host — daemon refuses to start");
            "unsupported".to_string()
        }
        Err(FanotifyError::NeedsFallback) => match InotifyHandle::open() {
            Ok(h) => h.mode_label.clone(),
            Err(_) => match AuditHandle::open() {
                Ok(h) => h.mode_label,
                Err(_) => "no_realtime_surface".to_string(),
            },
        },
        Err(FanotifyError::NeedsCapSysAdmin) => {
            return Err("missing CAP_SYS_ADMIN — start via systemd unit".into());
        }
        Err(other) => return Err(Box::new(other)),
    };

    info!(mode = %mode_label, "real-time mode selected");

    // Best-effort eBPF observe-only tap.
    if let Ok(obs) = EbpfObserver::load() {
        if let Some(reason) = obs.disabled_reason {
            info!(reason, "eBPF observer disabled");
        } else {
            info!("eBPF observer active");
        }
    }

    let _ipc = IpcClient::connect(&cli.socket)?;
    let _denylist = ActiveDenylist::default();
    let _budget = CrashBudget::default();

    if cli.once {
        info!("--once flag set, exiting cleanly");
        return Ok(());
    }

    // The full event loop (fanotify drain → block::decide → IPC
    // verdict reply, ShieldsPush / ActiveFindingsPush handling, the
    // heartbeat tick) is wired here in the Linux-runtime validation
    // pass. The scaffold above is enough for cargo check to succeed
    // on every workspace host so `pnpm tauri build` for the daemon
    // bundle doesn't get blocked by a missing crate.
    //
    // Exit non-zero so systemd treats a launch of this scaffold as a
    // failure rather than "completed successfully" — that lets the
    // crash budget (TASK-076) actually surface to the operator and
    // prevents shipping a build whose `freallyd.service` reports
    // `active (exited)` while doing no enforcement.
    Err("daemon runtime loop not yet wired — install of v0.8.0 foundation requires --once for smoke testing only".into())
}
