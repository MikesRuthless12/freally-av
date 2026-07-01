//! FSEvents ↔ ESF NOTIFY fast-path failover (TASK-252, Phase 9 Wave 2).
//!
//! Runs both sources in parallel when ESF ([`crate::esf_notify`]) is
//! loadable on this host. The failover module dedupes by
//! `(inode, mtime_ns, size)` within a 50 ms window, prefers ESF's
//! richer event when both arrive, and falls back to FSEvents alone
//! when ESF emits `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` or stops
//! heart-beating.
//!
//! Per `docs/prd.md` § 1.5.4: **NOTIFY-only on both sides** — there
//! is no AUTH path on either source. Failover is transparent to the
//! engine: it sees a single normalized event stream through
//! [`crate::ipc::macesf::IpcFrame::NotifyEvent`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use freallykernel::ipc::macesf::NotifySource;

/// Dedup-window length. Spec: 50 ms. An event from one source that
/// hasn't been corroborated by the other within this window is
/// flushed downstream unilaterally.
pub const DEDUP_WINDOW: Duration = Duration::from_millis(50);

/// Normalized event the failover emits. Same shape regardless of
/// source; the `source` field tells the engine which feed delivered
/// it (and dictates which extra-metadata columns are populated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    pub source: NotifySource,
    pub path: PathBuf,
    /// Dedup key — `(inode, mtime_ns, size)`. i64 ns since epoch
    /// matches the IPC frame at `freallykernel::ipc::macesf::NotifyEvent`.
    pub inode: u64,
    pub mtime_ns: i64,
    pub size: u64,
    /// PID + ppid + signing info. `pid = 0` and the option fields are
    /// `None` when the source was FSEvents (FSEvents has no PID
    /// reporter); these are populated when the source is ESF.
    pub pid: i32,
    pub ppid: i32,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    /// FSEvents flags bitmask, 0 when source is ESF.
    pub fsevents_flags: u32,
    /// ESF event-type bits, 0 when source is FSEvents.
    pub esf_event: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    inode: u64,
    mtime_ns: i64,
    size: u64,
}

impl DedupKey {
    fn from_event(ev: &NormalizedEvent) -> Self {
        Self {
            inode: ev.inode,
            mtime_ns: ev.mtime_ns,
            size: ev.size,
        }
    }
}

/// State of the ESF feed. Failover transitions between `Active` and
/// `Unavailable` driven by `mark_esf_*` calls. When `Unavailable`,
/// every FSEvents event is flushed unilaterally (no dedup wait).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsfFeedState {
    Active,
    Unavailable(String),
}

/// The failover dedupe + arbiter. Caller drives it with `push_*`
/// methods and pulls normalized events out of [`Failover::flush_ready`].
#[derive(Debug)]
pub struct Failover {
    pending: HashMap<DedupKey, (NormalizedEvent, Instant)>,
    output: Vec<NormalizedEvent>,
    esf_state: EsfFeedState,
    window: Duration,
}

impl Default for Failover {
    fn default() -> Self {
        Self::with_window(DEDUP_WINDOW)
    }
}

impl Failover {
    pub fn with_window(window: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            output: Vec::new(),
            esf_state: EsfFeedState::Active,
            window,
        }
    }

    pub fn esf_state(&self) -> &EsfFeedState {
        &self.esf_state
    }

    /// Mark ESF as unavailable. Reason string is propagated to the
    /// "ESF channel down: <reason>" log line per the validation gate.
    /// All pending events buffered for dedup — including any
    /// already-observed ESF events that haven't seen their FSEvents
    /// twin yet — are flushed immediately. Filtering to FSEvents-
    /// only here would silently drop legitimate ESF observations
    /// (review CR-1, 2026-05-27).
    pub fn mark_esf_unavailable(&mut self, reason: impl Into<String>) {
        self.esf_state = EsfFeedState::Unavailable(reason.into());
        let drained: Vec<NormalizedEvent> = self.pending.drain().map(|(_, (ev, _))| ev).collect();
        self.output.extend(drained);
    }

    /// Mark ESF as available again. Subsequent events resume normal
    /// dedupe behavior. Idempotent.
    pub fn mark_esf_available(&mut self) {
        self.esf_state = EsfFeedState::Active;
    }

    /// Push one normalized event into the failover. Caller is
    /// responsible for filling in `source`. The failover decides
    /// whether to emit it immediately, hold it for dedupe, or merge
    /// it with a pending peer.
    pub fn push(&mut self, ev: NormalizedEvent, now: Instant) {
        // First sweep expired pending entries before deciding what to
        // do with `ev`; that way a long-buffered FSEvents event gets
        // flushed before its ESF would-be twin invalidates the wait.
        self.expire(now);
        let key = DedupKey::from_event(&ev);
        match self.esf_state {
            EsfFeedState::Unavailable(_) => {
                // ESF dead → no dedupe possible. Emit unilaterally.
                // FSEvents events flow through; any stray ESF event
                // arriving after the channel was marked dead is also
                // emitted (defensive: a late callback shouldn't be
                // dropped silently).
                self.output.push(ev);
            }
            EsfFeedState::Active => {
                if let Some((prev, _)) = self.pending.remove(&key) {
                    // Dedup hit. Prefer ESF's richer event when both
                    // sources observed the same `(inode, mtime, size)`.
                    let chosen = if prev.source == NotifySource::Esf {
                        prev
                    } else if ev.source == NotifySource::Esf {
                        ev
                    } else {
                        // Both FSEvents — shouldn't happen in practice,
                        // but if FSEvents double-fires for the same
                        // target keep the first one.
                        prev
                    };
                    self.output.push(chosen);
                } else {
                    self.pending.insert(key, (ev, now));
                }
            }
        }
    }

    /// Sweep `pending` for entries older than `self.window` and emit
    /// them unilaterally. Caller-driven so the failover doesn't need
    /// a timer thread; the daemon's main loop calls this on each
    /// iteration.
    pub fn expire(&mut self, now: Instant) {
        let window = self.window;
        let expired: Vec<DedupKey> = self
            .pending
            .iter()
            .filter_map(|(k, (_, ts))| {
                if now.saturating_duration_since(*ts) >= window {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect();
        for k in expired {
            if let Some((ev, _)) = self.pending.remove(&k) {
                self.output.push(ev);
            }
        }
    }

    /// Drain every event the failover has decided is final. Caller
    /// alternates `push` / `expire` / `flush_ready` in the main loop.
    pub fn flush_ready(&mut self) -> Vec<NormalizedEvent> {
        std::mem::take(&mut self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(source: NotifySource, ino: u64, path: &str) -> NormalizedEvent {
        NormalizedEvent {
            source,
            path: PathBuf::from(path),
            inode: ino,
            mtime_ns: 1_700_000_000_000_000_000_i64,
            size: 4096,
            pid: if matches!(source, NotifySource::Esf) {
                4321
            } else {
                0
            },
            ppid: 1,
            team_id: matches!(source, NotifySource::Esf).then(|| "ABCDE12345".into()),
            signing_id: matches!(source, NotifySource::Esf).then(|| "com.x".into()),
            fsevents_flags: 0,
            esf_event: 0,
        }
    }

    #[test]
    fn fsevents_then_esf_within_window_emits_esf_copy() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let now = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        f.push(sample(NotifySource::Esf, 7, "/x"), now);
        let out = f.flush_ready();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, NotifySource::Esf);
        assert_eq!(out[0].pid, 4321);
    }

    #[test]
    fn esf_then_fsevents_within_window_emits_esf_copy() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let now = Instant::now();
        f.push(sample(NotifySource::Esf, 7, "/x"), now);
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        let out = f.flush_ready();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, NotifySource::Esf);
    }

    #[test]
    fn unmatched_event_flushes_after_window_expires() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let t0 = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), t0);
        assert!(f.flush_ready().is_empty(), "should still be pending");
        let later = t0 + Duration::from_millis(51);
        f.expire(later);
        let out = f.flush_ready();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, NotifySource::FsEvents);
    }

    #[test]
    fn distinct_keys_do_not_dedupe() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let now = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        f.push(sample(NotifySource::Esf, 8, "/y"), now);
        // Neither has been matched; both should flush after expiry.
        f.expire(now + Duration::from_millis(60));
        let out = f.flush_ready();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn marking_esf_unavailable_flushes_every_pending_event() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let now = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        f.push(sample(NotifySource::FsEvents, 8, "/y"), now);
        // Pending ESF event (no FSEvents twin yet) — must NOT be
        // silently dropped on the state transition. Regression for
        // code-review finding CR-1.
        f.push(sample(NotifySource::Esf, 9, "/z"), now);
        assert!(f.flush_ready().is_empty());
        f.mark_esf_unavailable("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED");
        let out = f.flush_ready();
        assert_eq!(out.len(), 3, "ESF-pending event was dropped");
        assert!(out.iter().any(|e| e.source == NotifySource::Esf));
        assert!(matches!(f.esf_state(), EsfFeedState::Unavailable(_)));
    }

    #[test]
    fn while_esf_unavailable_fsevents_passes_through_unilaterally() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        f.mark_esf_unavailable("down");
        let now = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        // No window wait — emitted immediately.
        let out = f.flush_ready();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn esf_recovery_transitions_back_to_active() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        f.mark_esf_unavailable("blip");
        f.mark_esf_available();
        assert!(matches!(f.esf_state(), EsfFeedState::Active));
    }

    #[test]
    fn double_push_same_source_keeps_first() {
        let mut f = Failover::with_window(Duration::from_millis(50));
        let now = Instant::now();
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        // A defensive double-fire from FSEvents.
        f.push(sample(NotifySource::FsEvents, 7, "/x"), now);
        f.expire(now + Duration::from_millis(60));
        let out = f.flush_ready();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, NotifySource::FsEvents);
    }
}
