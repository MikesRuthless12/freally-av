//! Real-time component coordination (TASK-156 onward, Phase 4+).
//!
//! Phase 4 ships only the Shields master kill-switch architecture —
//! per FR-160 the daemons themselves land in Phases 8 (Linux fanotify),
//! 9 (macOS ESF NOTIFY), and 12 (Windows ETW+AMSI+WDAC). This module is
//! the *single source of truth* every future daemon will subscribe to.

pub mod shields;
