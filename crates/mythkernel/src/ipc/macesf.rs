//! macOS Endpoint Security XPC bridge (TASK-081, Phase 9 Wave 1).
//!
//! The wire format is line-delimited JSON ("Codable JSON" in the
//! Swift / Apple sense): every message is one `IpcFrame` serialized
//! with `serde_json` plus a trailing `\n`. Both peers (the daemon's
//! `mythd-macos` binary and the engine-side `ui-bridge` consumer)
//! speak the same enum. JSON is chosen over CBOR for parity with
//! Apple's Codable surface; the system extension is most naturally
//! written in Swift, which talks JSON natively.
//!
//! Per `docs/prd.md` § 1.5.4: **NOTIFY-only** — there is no AUTH
//! path. The frame set deliberately excludes `Verdict` / `VerdictReply`
//! (compare to `crate::ipc::linfan`) because macOS daemon never blocks
//! a syscall. Block-on-detected (FR-133) is implemented in the engine
//! by closing the file post-write and quarantining, not by a pre-open
//! AUTH reply.
//!
//! Frame set:
//!
//!   * [`IpcFrame::NotifyEvent`] — daemon → engine, one FS event.
//!     Either FSEvents (TASK-079) or ESF NOTIFY (TASK-080) source.
//!   * [`IpcFrame::Heartbeat`] — daemon → engine, 1 Hz liveness.
//!   * [`IpcFrame::ShieldsPush`] — engine → daemon, current
//!     `shields.enabled` state. Daemon's `ShieldsGate` short-circuits
//!     every event when OFF (per FR-160 + TASK-156). Pushed on
//!     connect and on every transition.
//!   * [`IpcFrame::ActiveFindingsPush`] — engine → daemon, paths with
//!     open `detected` findings (FR-133). Daemon surfaces a `P1`
//!     finding when any of these paths is touched, regardless of
//!     Shields state.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::realtime::shields::ShieldsState;

/// Maximum allowed payload size for a single line. Defends against a
/// runaway peer that streams a multi-gigabyte JSON object. 4 MiB is
/// generous; a real `NotifyEvent` frame fits in < 2 KiB.
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// On-disk XPC socket path for the user-level daemon (started by
/// launchd as a LaunchAgent — see `packaging/macos/com.mythodikal.mythd.plist`).
/// The daemon `bind`s here; the engine-side connector `connect`s here.
/// Path is per-user under `~/Library/Application Support/Mythodikal/`
/// because LaunchAgents have no `/run/<service>` equivalent.
pub const USER_SOCKET_PATH: &str = "~/Library/Application Support/Mythodikal/mythd.sock";

/// Canonical filename for the launchd heartbeat JSON. Re-exported
/// from both the daemon crate (`mythd_macos::launchd::HEARTBEAT_FILENAME`)
/// and the ui-bridge command surface (`commands_mac::HEARTBEAT_FILENAME`).
/// Single source of truth lives here so the writer and reader
/// can never drift independently (review CR-10, 2026-05-27).
pub const HEARTBEAT_FILENAME: &str = "heartbeat.json";

/// Source of a NOTIFY event. Both sources are NOTIFY-only; the engine
/// uses this only for the live-event-log column ("source: fsevents" /
/// "source: esf") so an operator can tell at a glance whether ESF is
/// healthy. The Wave 2 failover (TASK-252) dedupes by `(inode,
/// mtime_ns, size)` and prefers `Esf` when both arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifySource {
    FsEvents,
    Esf,
}

impl NotifySource {
    pub fn as_str(self) -> &'static str {
        match self {
            NotifySource::FsEvents => "fsevents",
            NotifySource::Esf => "esf",
        }
    }
}

/// One NOTIFY event the daemon forwards to the engine. Mirrors
/// [`crate::ipc::linfan::IpcFrame::NotifyEvent`] with macOS-only
/// extras (team_id, signing_id) that ESF provides on top of the path
/// FSEvents already gives us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyEvent {
    pub ts_utc: i64,
    pub path: String,
    pub source: NotifySource,
    pub pid: i32,
    pub ppid: i32,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    /// Inode reported by the kernel. Used by the failover dedupe key.
    pub inode: u64,
    /// `stat.st_mtim` in nanoseconds at the time of the event. i64
    /// (not i128) so serde_json round-trips cleanly — serde_json
    /// rejects i128 on decode. i64 ns since epoch covers ~292 years,
    /// far past any plausible filesystem timestamp.
    pub mtime_ns: i64,
    /// `stat.st_size` at the time of the event.
    pub size: u64,
    /// FSEvents flags bitmask. 0 when `source = esf` (ESF carries
    /// a different event-type taxonomy).
    pub fsevents_flags: u32,
    /// ESF event type bit. 0 when `source = fsevents`.
    pub esf_event: u32,
}

/// Every wire frame. Two halves: pushes (daemon → engine) and pushes
/// (engine → daemon). The `kind` tag makes the on-wire format
/// self-describing so a future schema bump can add variants without
/// rewriting the framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcFrame {
    /// `daemon → engine` — a NOTIFY event for the live event log.
    /// No verdict is requested (NOTIFY-only).
    NotifyEvent(NotifyEvent),
    /// `daemon → engine` — heartbeat so the engine knows the daemon
    /// is alive. The engine surfaces a "real-time crashed" badge in
    /// the UI when these stop arriving (TASK-254 watchdog uses the
    /// launchd heartbeat file as the canonical liveness signal; this
    /// frame is the IPC-side belt-and-suspenders).
    Heartbeat {
        ts_utc: i64,
        mode: String,
        esf_active: bool,
    },
    /// `engine → daemon` — current Shields master switch state. The
    /// daemon caches this and short-circuits ALLOW for every event
    /// when `enabled = false` (per FR-160 + TASK-156). Pushed on
    /// connect and on every transition.
    ShieldsPush(ShieldsState),
    /// `engine → daemon` — current set of paths with open `detected`
    /// findings (FR-133). Each push is the **full** set; the daemon
    /// replaces its in-memory cache.
    ActiveFindingsPush { paths: Vec<String> },
}

/// Encoder/decoder for line-delimited JSON frames over a blocking
/// `io::Read + io::Write` pair. Both ends use the same `IpcCodec`.
pub struct IpcCodec;

impl IpcCodec {
    /// Encode `frame` into `out`. Writes one JSON line followed by
    /// `\n`. Errors propagate from the writer or from a payload that
    /// would exceed [`MAX_PAYLOAD_BYTES`].
    pub fn write_frame<W: Write>(out: &mut W, frame: &IpcFrame) -> Result<(), IpcError> {
        let buf = serde_json::to_vec(frame).map_err(|e| IpcError::Encode(e.to_string()))?;
        if buf.len() > MAX_PAYLOAD_BYTES {
            return Err(IpcError::OversizedPayload(buf.len()));
        }
        out.write_all(&buf)?;
        out.write_all(b"\n")?;
        Ok(())
    }

    /// Read one frame from `inp`. Reads byte-by-byte until the next
    /// `\n` then decodes the prefix as a single JSON value. Byte-by-
    /// byte avoids the read-ahead issue you get with
    /// [`std::io::BufReader`] — wrapping a fresh `BufReader` per call
    /// would consume bytes past the newline that the next call
    /// expects to see. Returns `Err(IpcError::EndOfStream)` cleanly
    /// when the peer closed at a frame boundary. A peer that closed
    /// mid-frame (any buffered bytes without a terminating `\n`)
    /// returns `Err(IpcError::Truncated)` — accepting the partial
    /// prefix as a valid frame would let a crashed daemon hand the
    /// engine an undefined-shape JSON blob (review CR-5, 2026-05-27;
    /// matches the strict behavior of `ipc::linfan::IpcCodec`).
    pub fn read_frame<R: Read>(inp: &mut R) -> Result<IpcFrame, IpcError> {
        let mut line = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            match inp.read(&mut byte)? {
                0 => {
                    if line.is_empty() {
                        return Err(IpcError::EndOfStream);
                    }
                    return Err(IpcError::Truncated(line.len()));
                }
                _ => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    line.push(byte[0]);
                    if line.len() > MAX_PAYLOAD_BYTES {
                        return Err(IpcError::OversizedPayload(line.len()));
                    }
                }
            }
        }
        serde_json::from_slice(&line).map_err(|e| IpcError::Decode(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("payload exceeds {MAX_PAYLOAD_BYTES} bytes (got {0})")]
    OversizedPayload(usize),
    #[error("peer closed cleanly")]
    EndOfStream,
    #[error("peer closed mid-frame after buffering {0} bytes without a terminating newline")]
    Truncated(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_notify_event() -> IpcFrame {
        IpcFrame::NotifyEvent(NotifyEvent {
            ts_utc: 1_700_000_000,
            path: "/Users/me/Documents/installer.dmg".into(),
            source: NotifySource::Esf,
            pid: 4321,
            ppid: 1,
            team_id: Some("ABCDE12345".into()),
            signing_id: Some("com.example.installer".into()),
            inode: 9_999_999,
            mtime_ns: 1_700_000_000_000_000_000_i64,
            size: 4096,
            fsevents_flags: 0,
            esf_event: 0x2, // NOTIFY_EXEC
        })
    }

    fn sample_heartbeat() -> IpcFrame {
        IpcFrame::Heartbeat {
            ts_utc: 1_700_000_001,
            mode: "fsevents+esf".into(),
            esf_active: true,
        }
    }

    fn sample_shields_push() -> IpcFrame {
        IpcFrame::ShieldsPush(ShieldsState {
            enabled: false,
            pause_until_utc: Some(1_700_003_600),
        })
    }

    fn sample_active_findings() -> IpcFrame {
        IpcFrame::ActiveFindingsPush {
            paths: vec![
                "/Users/me/bad.dmg".into(),
                "/Users/me/Library/LaunchAgents/evil.plist".into(),
            ],
        }
    }

    #[test]
    fn round_trips_every_frame_variant() {
        for frame in [
            sample_notify_event(),
            sample_heartbeat(),
            sample_shields_push(),
            sample_active_findings(),
        ] {
            let mut buf = Vec::new();
            IpcCodec::write_frame(&mut buf, &frame).unwrap();
            let mut cur = Cursor::new(buf);
            let got = IpcCodec::read_frame(&mut cur).unwrap();
            assert_eq!(got, frame);
        }
    }

    #[test]
    fn streams_multiple_frames_back_to_back() {
        let mut buf = Vec::new();
        IpcCodec::write_frame(&mut buf, &sample_notify_event()).unwrap();
        IpcCodec::write_frame(&mut buf, &sample_heartbeat()).unwrap();
        let mut cur = Cursor::new(buf);
        let a = IpcCodec::read_frame(&mut cur).unwrap();
        let b = IpcCodec::read_frame(&mut cur).unwrap();
        assert_eq!(a, sample_notify_event());
        assert_eq!(b, sample_heartbeat());
    }

    #[test]
    fn end_of_stream_at_frame_boundary_is_clean() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        let err = IpcCodec::read_frame(&mut cur).unwrap_err();
        assert!(matches!(err, IpcError::EndOfStream));
    }

    #[test]
    fn truncated_frame_returns_truncated_not_decode() {
        // Peer crashed mid-frame: bytes without a terminating \n.
        // Must NOT be accepted as a valid frame and fed to serde_json
        // (review CR-5, 2026-05-27).
        let mut cur = Cursor::new(b"{\"kind\":\"heart".to_vec());
        let err = IpcCodec::read_frame(&mut cur).unwrap_err();
        match err {
            IpcError::Truncated(n) => assert_eq!(n, b"{\"kind\":\"heart".len()),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn notify_source_strings_are_stable() {
        // Stable string ids surface in the UI log column; a rename
        // would invalidate saved log filters.
        assert_eq!(NotifySource::FsEvents.as_str(), "fsevents");
        assert_eq!(NotifySource::Esf.as_str(), "esf");
    }

    #[test]
    fn no_verdict_or_auth_in_any_macesf_frame() {
        // NOTIFY-only proof: NO frame variant in the macesf set may
        // serialize anything containing "verdict" or "auth" — those
        // belong on the Linux side. Iterate every sample so a future
        // contributor who adds e.g. a `verdict_hint` to `Heartbeat`
        // trips this test (review CR-8, 2026-05-27 — prior version
        // only checked NotifyEvent).
        for frame in [
            sample_notify_event(),
            sample_heartbeat(),
            sample_shields_push(),
            sample_active_findings(),
        ] {
            let mut buf = Vec::new();
            IpcCodec::write_frame(&mut buf, &frame).unwrap();
            let on_wire = String::from_utf8(buf).unwrap();
            assert!(
                !on_wire.contains("verdict"),
                "variant leaked 'verdict' onto the wire: {on_wire}"
            );
            assert!(
                !on_wire.contains("auth"),
                "variant leaked 'auth' onto the wire: {on_wire}"
            );
        }
    }
}
