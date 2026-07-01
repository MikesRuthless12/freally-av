//! TASK-234 — Remote-mount scan mode.
//!
//! When the user opts in to "scan this remote mount slow", the engine:
//!
//! - drops worker count to a conservative `2`,
//! - applies a leaky-bucket bandwidth cap inside the hasher's read
//!   loop so we never saturate the user's network link,
//! - disables FastCDC selective rehash for that mount (chunk-store
//!   overhead is net-negative when each chunk round-trips a Wi-Fi
//!   network).
//!
//! Remote-ness is auto-detected per OS:
//! - Linux: `/proc/mounts` `fstype ∈ {nfs, nfs4, cifs, smb3, smbfs, sshfs, fuse.sshfs}`,
//! - Windows: `GetDriveType == DRIVE_REMOTE`,
//! - macOS: `getmntinfo` flag `MNT_LOCAL == 0`.
//!
//! Auto-detection only *advertises* the mount as remote in the UI; the
//! engine never silently activates remote mode — the user explicitly
//! toggles it per mount.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Engine configuration for a single remote mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteScanConfig {
    /// Max concurrent scan workers on this mount. Default 2.
    pub workers: usize,
    /// Bandwidth cap in megabytes-per-second (MB/s, base-10 to match
    /// network-speed conventions). Default 5.
    pub bandwidth_mbps: u32,
    /// FastCDC selective rehash gated *off* on remote mounts by
    /// default — every chunk read costs a network round trip.
    pub fastcdc_enabled: bool,
}

impl Default for RemoteScanConfig {
    fn default() -> Self {
        Self {
            workers: 2,
            bandwidth_mbps: 5,
            fastcdc_enabled: false,
        }
    }
}

impl RemoteScanConfig {
    /// Tokens (bytes) per second the leaky bucket releases.
    pub fn bytes_per_second(&self) -> u64 {
        (self.bandwidth_mbps as u64) * 1_000_000
    }
}

/// Leaky-bucket rate limiter. The previous implementation used a
/// pair of atomics, but `fetch_add` followed by a cap-check `store`
/// is not atomic — two threads racing through `refill()` could
/// both fetch_add and push the bucket well above the cap. We use a
/// short-lived Mutex instead: bandwidth-capped scans are slow by
/// construction, so the mutex contention is negligible (one acquire
/// per chunk read, on the order of micro-seconds).
#[derive(Debug)]
pub struct LeakyBucket {
    bytes_per_second: u64,
    state: Mutex<LeakyState>,
}

#[derive(Debug)]
struct LeakyState {
    tokens: u64,
    last_refill_nanos: u64,
    start: Instant,
}

impl LeakyBucket {
    pub fn new(bytes_per_second: u64) -> Self {
        let bytes_per_second = bytes_per_second.max(1);
        Self {
            bytes_per_second,
            state: Mutex::new(LeakyState {
                tokens: bytes_per_second,
                last_refill_nanos: 0,
                start: Instant::now(),
            }),
        }
    }

    /// Attempt to consume `n` tokens. Returns the time the caller
    /// should sleep before retrying when the bucket doesn't have
    /// enough tokens; `Duration::ZERO` means the take succeeded.
    pub fn take(&self, n: u64) -> Duration {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Refill atomically with the take so concurrent callers can't
        // double-credit the same elapsed window.
        let now_nanos = state.start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        if now_nanos > state.last_refill_nanos {
            let elapsed = (now_nanos - state.last_refill_nanos) as u128;
            // u128 → u64 with saturation: a multi-day pause can't
            // overflow the multiply.
            let new_tokens = elapsed
                .saturating_mul(self.bytes_per_second as u128)
                .checked_div(1_000_000_000)
                .unwrap_or(0)
                .min(self.bytes_per_second as u128) as u64;
            if new_tokens > 0 {
                state.last_refill_nanos = now_nanos;
                // Cap at one second's worth of tokens (no burst > 1 s).
                state.tokens = state
                    .tokens
                    .saturating_add(new_tokens)
                    .min(self.bytes_per_second);
            }
        }
        if state.tokens >= n {
            state.tokens -= n;
            return Duration::ZERO;
        }
        let deficit = n - state.tokens;
        let nanos = deficit
            .saturating_mul(1_000_000_000)
            .checked_div(self.bytes_per_second)
            .unwrap_or(0);
        Duration::from_nanos(nanos)
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }
}

/// Outcome of [`detect_remote`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    Local,
    Remote(RemoteFs),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteFs {
    Nfs,
    Cifs,
    Smb,
    Sshfs,
    Other,
}

/// Detect whether the given path is on a remote mount.
///
/// Foundation-only: returns `MountKind::Unknown` on every OS until
/// per-OS bindings land. The engine treats `Unknown` as "no special
/// behaviour" — auto-detection never auto-activates remote mode,
/// the user always opts in.
pub fn detect_remote(_path: &std::path::Path) -> MountKind {
    MountKind::Unknown
}

/// Classify an fstype string (e.g. from `/proc/mounts`). Exposed so
/// the per-OS implementation can call into the classification
/// without re-encoding the table.
pub fn classify_fstype(fstype: &str) -> MountKind {
    let lower = fstype.to_ascii_lowercase();
    let s = lower.as_str();
    match s {
        "nfs" | "nfs3" | "nfs4" => MountKind::Remote(RemoteFs::Nfs),
        "cifs" => MountKind::Remote(RemoteFs::Cifs),
        "smbfs" | "smb3" | "smb" => MountKind::Remote(RemoteFs::Smb),
        "sshfs" | "fuse.sshfs" => MountKind::Remote(RemoteFs::Sshfs),
        "fuse" | "fuseblk" => MountKind::Remote(RemoteFs::Other),
        "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" | "zfs" | "apfs" | "hfs" | "ntfs" | "ntfs3"
        | "exfat" | "fat32" | "vfat" | "tmpfs" | "overlay" => MountKind::Local,
        _ => MountKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_config_matches_spec() {
        let c = RemoteScanConfig::default();
        assert_eq!(c.workers, 2);
        assert_eq!(c.bandwidth_mbps, 5);
        assert!(!c.fastcdc_enabled);
    }

    #[test]
    fn bytes_per_second_conversion() {
        let c = RemoteScanConfig::default();
        assert_eq!(c.bytes_per_second(), 5_000_000);
    }

    #[test]
    fn classify_known_remote_fstypes() {
        assert_eq!(classify_fstype("nfs"), MountKind::Remote(RemoteFs::Nfs));
        assert_eq!(classify_fstype("nfs4"), MountKind::Remote(RemoteFs::Nfs));
        assert_eq!(classify_fstype("cifs"), MountKind::Remote(RemoteFs::Cifs));
        assert_eq!(classify_fstype("smbfs"), MountKind::Remote(RemoteFs::Smb));
        assert_eq!(
            classify_fstype("fuse.sshfs"),
            MountKind::Remote(RemoteFs::Sshfs)
        );
    }

    #[test]
    fn classify_known_local_fstypes() {
        assert_eq!(classify_fstype("ext4"), MountKind::Local);
        assert_eq!(classify_fstype("ntfs"), MountKind::Local);
        assert_eq!(classify_fstype("APFS"), MountKind::Local);
    }

    #[test]
    fn classify_unknown_fstype_is_unknown() {
        assert_eq!(classify_fstype("9p2000"), MountKind::Unknown);
    }

    #[test]
    fn detect_remote_returns_unknown_foundation_only() {
        assert_eq!(detect_remote(Path::new("/")), MountKind::Unknown);
    }

    #[test]
    fn leaky_bucket_initial_capacity_full() {
        let lb = LeakyBucket::new(1000);
        // First take of full capacity should succeed.
        assert_eq!(lb.take(1000), Duration::ZERO);
    }

    #[test]
    fn leaky_bucket_blocks_when_drained() {
        let lb = LeakyBucket::new(100);
        let _ = lb.take(100); // drain
        let wait = lb.take(50);
        assert!(
            wait > Duration::ZERO,
            "expected non-zero wait when bucket is empty"
        );
        // We expect roughly 500 ms wait for 50 tokens at 100 / s.
        // Allow a generous range so the test isn't flaky on slow CI.
        assert!(wait < Duration::from_secs(2));
    }

    #[test]
    fn leaky_bucket_refills_over_time() {
        let lb = LeakyBucket::new(1_000_000);
        // Drain entirely, sleep briefly, retry.
        let _ = lb.take(1_000_000);
        std::thread::sleep(Duration::from_millis(50));
        // After 50 ms we expect ~50 KB of fresh tokens.
        assert_eq!(lb.take(10_000), Duration::ZERO);
    }

    #[test]
    fn remote_fs_serde_round_trip() {
        let kinds = [
            MountKind::Local,
            MountKind::Remote(RemoteFs::Nfs),
            MountKind::Remote(RemoteFs::Sshfs),
            MountKind::Unknown,
        ];
        for k in kinds {
            let s = serde_json::to_string(&k).unwrap();
            let k2: MountKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, k2);
        }
    }
}
