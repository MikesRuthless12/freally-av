//! Real-time rule set bundled with `mythd-linux`.
//!
//! Each rule consumes the fanotify event stream and surfaces a
//! finding through the engine IPC. Rules live here (rather than in
//! `mythkernel::detect`) because they need OS-specific event shape
//! and `kill(pid, SIGSTOP)` semantics; the cross-platform planning
//! lives in `mythkernel::detect::honeyfiles`.

pub mod browser_creds;
pub mod honey;
