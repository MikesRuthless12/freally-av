//! Linux fanotify daemon ↔ engine IPC (TASK-074, Phase 8).
//!
//! The wire format is a length-prefixed CBOR stream: every message is
//! `u32::to_le_bytes(payload_len) ++ ciborium_encoded_payload`. Both
//! peers (the daemon and the engine-side `ui-bridge` consumer) speak
//! the same `IpcFrame` enum.
//!
//! The transport is a Unix-domain socket at `/run/freallyd/freallyd.sock`
//! when run with systemd-level privileges, or `<XDG_RUNTIME_DIR>/freallyd.sock`
//! when run as the user. The transport itself is selected at startup
//! by the daemon; this module only owns the **framing** and the
//! **payload schema**.
//!
//! The frame set is deliberately small in Phase 8 wave 1:
//!
//!   * [`DaemonRequest::Verdict`] — daemon asks the engine for a
//!     verdict on `(path, blake3?, sha256?)`. The engine returns one
//!     [`EngineResponse::Verdict`] with `ALLOW` / `DENY` / `DEFER`.
//!   * [`EnginePush::ShieldsState`] — engine pushes the current
//!     `shields.enabled` state so the daemon can short-circuit
//!     verdicts locally when Shields=OFF (per FR-160 + TASK-156). No
//!     per-event engine call is needed in that mode.
//!   * [`EnginePush::ActiveFindings`] — engine pushes the current set
//!     of paths with open `detected` findings so the daemon can DENY
//!     opens regardless of Shields state (TASK-140, FR-133).
//!
//! Wave 2 will extend the frame set (USB events, mount toggles), but
//! the **framing** stays binary-compatible — additions live behind new
//! `IpcFrame` variants; ciborium tolerates unknown variants on decode
//! provided the discriminator + payload encoding is preserved.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::realtime::shields::ShieldsState;

/// Maximum allowed payload size for a single frame. Defends against a
/// runaway peer that streams a multi-gigabyte payload over the
/// length-prefix and exhausts memory. 4 MiB is generous; a real
/// `Verdict` request fits in < 1 KiB.
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// On-disk socket path for the system-managed daemon (started by
/// systemd with root + CAP_SYS_ADMIN). The daemon `bind`s here; the
/// engine-side connector `connect`s here. See TASK-076 for the unit.
pub const SYSTEM_SOCKET_PATH: &str = "/run/freallyd/freallyd.sock";

/// What a verdict frame asks the engine. The daemon never trusts the
/// path directly — it carries the hash if it already had time to
/// compute one (for example, a recently-modified file the daemon
/// hashed itself); otherwise the engine recomputes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictRequest {
    /// fanotify event id. Echoed in the response so multiple in-flight
    /// requests can be matched.
    pub req_id: u64,
    /// Absolute path of the file fanotify is asking about. Already
    /// resolved against the fanotify file descriptor on the daemon
    /// side so it is the canonical form, not a relative or
    /// `/proc/self/fd/<n>` indirection.
    pub path: String,
    /// fanotify mask of what was requested (FAN_OPEN_PERM /
    /// FAN_ACCESS_PERM / etc.). The engine logs this and may use it to
    /// pick a verdict policy.
    pub mask_bits: u64,
    /// PID of the process whose syscall triggered the event. The
    /// engine uses this for the `exclusions.scope = realtime_only`
    /// per-process exclusion lookup.
    pub pid: i32,
    /// Optional pre-computed BLAKE3 (hex). When set, the engine can
    /// skip re-hashing.
    pub blake3_hex: Option<String>,
    /// Optional pre-computed SHA-256 (hex).
    pub sha256_hex: Option<String>,
}

/// Three-way verdict the daemon hands back to fanotify. `Defer` keeps
/// the kernel waiting on the permission decision so the engine can
/// finish hashing a large file out-of-band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    Defer,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Defer => "defer",
        }
    }
}

/// Response to a [`VerdictRequest`] — the verdict plus an optional
/// human-readable reason for the daemon log + UI explainer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictResponse {
    pub req_id: u64,
    pub verdict: Verdict,
    /// Short rule_id-style identifier of the matched policy
    /// (e.g. `"block_on_detected"`, `"shields_off"`, `"clean"`).
    pub policy_id: String,
    pub reason: Option<String>,
}

/// Every wire frame. Two halves: requests (daemon → engine) and
/// pushes (engine → daemon). The `kind` tag makes the on-wire format
/// self-describing so a future schema bump (Phase 8 Wave 2) can add
/// variants without rewriting the framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcFrame {
    /// `daemon → engine` — please tell me what to do with this open.
    Verdict(VerdictRequest),
    /// `engine → daemon` — the answer to a prior Verdict request.
    VerdictReply(VerdictResponse),
    /// `engine → daemon` — current Shields master switch state. The
    /// daemon caches this and short-circuits ALLOW for every event
    /// when `enabled = false` (per FR-160 + TASK-156). Pushed on
    /// connect and on every transition.
    ShieldsPush(ShieldsState),
    /// `engine → daemon` — current set of paths with open `detected`
    /// findings (TASK-140 + FR-133). The daemon DENYs opens on any
    /// path in this set regardless of Shields state. Each push is
    /// the **full** set; the daemon replaces its in-memory cache.
    ActiveFindingsPush { paths: Vec<String> },
    /// `daemon → engine` — heartbeat so the engine knows the daemon
    /// is alive. The engine surfaces a "real-time crashed" badge in
    /// the UI when these stop arriving (TASK-076 watchdog).
    Heartbeat { ts_utc: i64, mode: String },
    /// `daemon → engine` — a fanotify-NOTIFY (not PERM) event the
    /// engine wants for the live event log (TASK-075 UI). No verdict
    /// is requested.
    NotifyEvent {
        ts_utc: i64,
        path: String,
        mask_bits: u64,
        pid: i32,
    },
}

/// Encoder/decoder for length-prefixed CBOR frames over a blocking
/// `io::Read + io::Write` pair. Both ends use the same `IpcCodec`.
pub struct IpcCodec;

impl IpcCodec {
    /// Encode `frame` into `out`. Writes `u32 LE length` followed by
    /// CBOR bytes. Errors propagate from the writer or from a payload
    /// that would exceed [`MAX_PAYLOAD_BYTES`].
    pub fn write_frame<W: Write>(out: &mut W, frame: &IpcFrame) -> Result<(), IpcError> {
        let mut buf = Vec::with_capacity(256);
        ciborium::into_writer(frame, &mut buf).map_err(|e| IpcError::Encode(e.to_string()))?;
        if buf.len() > MAX_PAYLOAD_BYTES {
            return Err(IpcError::OversizedPayload(buf.len()));
        }
        out.write_all(&(buf.len() as u32).to_le_bytes())?;
        out.write_all(&buf)?;
        Ok(())
    }

    /// Read one frame from `inp`. Reads `u32 LE length`, then exactly
    /// that many bytes, then decodes them as a single CBOR value.
    /// Returns `Err(IpcError::EndOfStream)` cleanly when the peer
    /// closed without sending a partial frame.
    pub fn read_frame<R: Read>(inp: &mut R) -> Result<IpcFrame, IpcError> {
        let mut len_buf = [0u8; 4];
        match inp.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(IpcError::EndOfStream);
            }
            Err(e) => return Err(e.into()),
        }
        let payload_len = u32::from_le_bytes(len_buf) as usize;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(IpcError::OversizedPayload(payload_len));
        }
        let mut payload = vec![0u8; payload_len];
        inp.read_exact(&mut payload)?;
        ciborium::from_reader(&payload[..]).map_err(|e| IpcError::Decode(e.to_string()))
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_verdict_req() -> IpcFrame {
        IpcFrame::Verdict(VerdictRequest {
            req_id: 7,
            path: "/home/me/Downloads/installer.bin".into(),
            mask_bits: 0x1, // FAN_ACCESS
            pid: 1234,
            blake3_hex: Some("ab".repeat(32)),
            sha256_hex: None,
        })
    }

    fn sample_verdict_reply() -> IpcFrame {
        IpcFrame::VerdictReply(VerdictResponse {
            req_id: 7,
            verdict: Verdict::Deny,
            policy_id: "block_on_detected".into(),
            reason: Some("path has open `detected` finding".into()),
        })
    }

    #[test]
    fn round_trips_verdict_request_and_reply() {
        let mut buf = Vec::new();
        IpcCodec::write_frame(&mut buf, &sample_verdict_req()).unwrap();
        IpcCodec::write_frame(&mut buf, &sample_verdict_reply()).unwrap();
        let mut cur = Cursor::new(buf);
        let req = IpcCodec::read_frame(&mut cur).unwrap();
        let reply = IpcCodec::read_frame(&mut cur).unwrap();
        assert_eq!(req, sample_verdict_req());
        assert_eq!(reply, sample_verdict_reply());
    }

    #[test]
    fn round_trips_shields_push() {
        let frame = IpcFrame::ShieldsPush(ShieldsState {
            enabled: false,
            pause_until_utc: Some(1_700_000_000),
        });
        let mut buf = Vec::new();
        IpcCodec::write_frame(&mut buf, &frame).unwrap();
        let mut cur = Cursor::new(buf);
        let got = IpcCodec::read_frame(&mut cur).unwrap();
        assert_eq!(got, frame);
    }

    #[test]
    fn round_trips_active_findings_push() {
        let frame = IpcFrame::ActiveFindingsPush {
            paths: vec!["/home/me/bad.bin".into(), "/tmp/x.so".into()],
        };
        let mut buf = Vec::new();
        IpcCodec::write_frame(&mut buf, &frame).unwrap();
        let mut cur = Cursor::new(buf);
        let got = IpcCodec::read_frame(&mut cur).unwrap();
        assert_eq!(got, frame);
    }

    #[test]
    fn round_trips_heartbeat_and_notify() {
        for frame in [
            IpcFrame::Heartbeat {
                ts_utc: 42,
                mode: "fanotify".into(),
            },
            IpcFrame::NotifyEvent {
                ts_utc: 99,
                path: "/etc/passwd".into(),
                mask_bits: 0x2,
                pid: 4321,
            },
        ] {
            let mut buf = Vec::new();
            IpcCodec::write_frame(&mut buf, &frame).unwrap();
            let mut cur = Cursor::new(buf);
            assert_eq!(IpcCodec::read_frame(&mut cur).unwrap(), frame);
        }
    }

    #[test]
    fn rejects_oversized_payload_on_decode() {
        let mut buf = Vec::new();
        // u32 LE length that exceeds MAX_PAYLOAD_BYTES.
        buf.extend_from_slice(&((MAX_PAYLOAD_BYTES + 1) as u32).to_le_bytes());
        // No payload bytes — read_frame should bail before trying to
        // allocate the oversize buffer.
        let mut cur = Cursor::new(buf);
        let err = IpcCodec::read_frame(&mut cur).unwrap_err();
        match err {
            IpcError::OversizedPayload(n) => assert_eq!(n, MAX_PAYLOAD_BYTES + 1),
            other => panic!("expected OversizedPayload, got {other:?}"),
        }
    }

    #[test]
    fn end_of_stream_at_frame_boundary_is_clean() {
        // Empty reader → EOF before reading the 4-byte length.
        let mut cur = Cursor::new(Vec::<u8>::new());
        let err = IpcCodec::read_frame(&mut cur).unwrap_err();
        assert!(matches!(err, IpcError::EndOfStream));
    }

    #[test]
    fn verdict_strs_match_prd() {
        assert_eq!(Verdict::Allow.as_str(), "allow");
        assert_eq!(Verdict::Deny.as_str(), "deny");
        assert_eq!(Verdict::Defer.as_str(), "defer");
    }
}
