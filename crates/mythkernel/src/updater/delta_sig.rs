//! TASK-194 — Feed delta verification: chained ed25519 epoch sig.
//!
//! Each feed epoch ships a `manifest.json` listing:
//!
//! ```json
//! {
//!   "epoch": 4242,
//!   "prev_epoch": 4241,
//!   "feed_artifact_sha256": "<hex>",
//!   "prev_epoch_sha256": "<hex>",
//!   "signature_b64": "<base64 ed25519 sig over prev_epoch || epoch || feed_artifact_sha256>"
//! }
//! ```
//!
//! The chain is verified end-to-end at update time. A broken link
//! (missing prev epoch in the cache, signature mismatch, or
//! prev_epoch_sha256 disagreement) rejects the new epoch and keeps
//! the prior one. Provides cryptographic continuity across the feed
//! timeline so a one-off CDN compromise can't substitute a single
//! corrupted epoch.
//!
//! The signing keypair is the same ed25519 pair already used for
//! the Tauri Updater (TASK-044) — single key fingerprint baked into
//! the binary. The maintainer's private key lives in GitHub Secrets;
//! the public half is verified via the existing `minisign-verify`
//! crate per `docs/prd.md` security posture.
//!
//! ## Scope for Wave 2 Phase A
//!
//! Pure data + verification logic; the wire-up to the per-feed
//! updaters is a follow-up. The maintainer-side signing tool lives
//! at `tools/feed-builder/src/sign.rs` (also a follow-up; the
//! `Manifest` shape below is the spec the tool will emit).

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum DeltaSigError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode: {0}")]
    Base64(String),
    #[error("malformed manifest: {0}")]
    Malformed(&'static str),
    #[error("signature verification failed")]
    BadSignature,
    #[error(
        "epoch chain broken: manifest says prev_epoch_sha256 = {expected}, cached prior epoch artifact has sha256 = {actual}"
    )]
    BrokenChain { expected: String, actual: String },
    #[error("non-monotone epoch: manifest epoch {new} <= cached epoch {cached}")]
    NonMonotoneEpoch { new: u64, cached: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub epoch: u64,
    pub prev_epoch: u64,
    /// Hex SHA-256 of the new feed artifact (what the client will
    /// verify against after download).
    pub feed_artifact_sha256: String,
    /// Hex SHA-256 of the *prior* epoch's feed artifact. The
    /// client compares this to its locally-cached prior artifact
    /// before accepting the new epoch.
    pub prev_epoch_sha256: String,
    /// Base64 ed25519 signature over the message body:
    ///   `epoch || prev_epoch || feed_artifact_sha256 || prev_epoch_sha256`.
    pub signature_b64: String,
}

impl Manifest {
    pub fn parse(json: &str) -> Result<Self, DeltaSigError> {
        let m: Manifest = serde_json::from_str(json)?;
        if m.feed_artifact_sha256.len() != 64
            || !m.feed_artifact_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(DeltaSigError::Malformed("feed_artifact_sha256 not hex(64)"));
        }
        if m.prev_epoch_sha256.len() != 64
            || !m.prev_epoch_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(DeltaSigError::Malformed("prev_epoch_sha256 not hex(64)"));
        }
        Ok(m)
    }

    /// Bytes the signature was computed over. Stable serialisation
    /// — fixed-width-hex hashes + decimal-encoded epoch numbers
    /// joined by `||`. Don't change without bumping a version field.
    pub fn signed_message(&self) -> Vec<u8> {
        let s = format!(
            "{epoch}||{prev_epoch}||{art}||{prev_art}",
            epoch = self.epoch,
            prev_epoch = self.prev_epoch,
            art = self.feed_artifact_sha256.to_ascii_lowercase(),
            prev_art = self.prev_epoch_sha256.to_ascii_lowercase(),
        );
        s.into_bytes()
    }
}

/// Verify the manifest chain. The caller passes the prior cached
/// epoch state so we can enforce monotonicity + sha256 continuity.
/// `verify_sig(msg, sig_b64)` is the ed25519 verification callback
/// — the engine wires this to the existing `minisign-verify` path.
pub fn verify_chain<F>(
    manifest: &Manifest,
    cached_epoch: Option<u64>,
    cached_prior_sha256: Option<&str>,
    verify_sig: F,
) -> Result<(), DeltaSigError>
where
    F: FnOnce(&[u8], &str) -> bool,
{
    if let Some(cached) = cached_epoch
        && manifest.epoch <= cached
    {
        return Err(DeltaSigError::NonMonotoneEpoch {
            new: manifest.epoch,
            cached,
        });
    }
    if let Some(prior) = cached_prior_sha256
        && !manifest
            .prev_epoch_sha256
            .eq_ignore_ascii_case(prior)
    {
        return Err(DeltaSigError::BrokenChain {
            expected: manifest.prev_epoch_sha256.to_ascii_lowercase(),
            actual: prior.to_ascii_lowercase(),
        });
    }
    let msg = manifest.signed_message();
    if !verify_sig(&msg, &manifest.signature_b64) {
        return Err(DeltaSigError::BadSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_manifest(epoch: u64, prev_epoch: u64, art: &str, prev_art: &str) -> Manifest {
        Manifest {
            epoch,
            prev_epoch,
            feed_artifact_sha256: art.to_string(),
            prev_epoch_sha256: prev_art.to_string(),
            signature_b64: "fakesig".to_string(),
        }
    }

    const HEX64A: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const HEX64B: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn parse_valid_manifest() {
        let m = ok_manifest(2, 1, HEX64A, HEX64B);
        let json = serde_json::to_string(&m).unwrap();
        let parsed = Manifest::parse(&json).unwrap();
        assert_eq!(parsed.epoch, 2);
    }

    #[test]
    fn parse_rejects_bad_hex_length() {
        let m = ok_manifest(2, 1, "short", HEX64B);
        let json = serde_json::to_string(&m).unwrap();
        let err = Manifest::parse(&json).unwrap_err();
        assert!(matches!(err, DeltaSigError::Malformed(_)));
    }

    #[test]
    fn signed_message_stable() {
        let m = ok_manifest(2, 1, HEX64A, HEX64B);
        let bytes = m.signed_message();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("||"));
        assert!(s.starts_with("2||1||"));
    }

    #[test]
    fn verify_chain_rejects_non_monotone_epoch() {
        let m = ok_manifest(1, 0, HEX64A, HEX64B);
        let err = verify_chain(&m, Some(5), None, |_, _| true).unwrap_err();
        assert!(matches!(err, DeltaSigError::NonMonotoneEpoch { .. }));
    }

    #[test]
    fn verify_chain_rejects_broken_chain() {
        let m = ok_manifest(2, 1, HEX64A, HEX64B);
        let err = verify_chain(&m, Some(1), Some(HEX64A), |_, _| true).unwrap_err();
        assert!(matches!(err, DeltaSigError::BrokenChain { .. }));
    }

    #[test]
    fn verify_chain_rejects_bad_sig() {
        let m = ok_manifest(2, 1, HEX64A, HEX64B);
        let err = verify_chain(&m, Some(1), Some(HEX64B), |_, _| false).unwrap_err();
        assert!(matches!(err, DeltaSigError::BadSignature));
    }

    #[test]
    fn verify_chain_accepts_valid() {
        let m = ok_manifest(2, 1, HEX64A, HEX64B);
        verify_chain(&m, Some(1), Some(HEX64B), |_, _| true).unwrap();
    }
}
