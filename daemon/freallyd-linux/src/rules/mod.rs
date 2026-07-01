//! Real-time rule set bundled with `freallyd-linux`.
//!
//! Each rule consumes the fanotify event stream and surfaces a
//! finding through the engine IPC. Rules live here (rather than in
//! `freallykernel::detect`) because they need OS-specific event shape
//! and `kill(pid, SIGSTOP)` semantics; the cross-platform planning
//! lives in `freallykernel::detect::honeyfiles`.

pub mod browser_creds;
pub mod honey;
