//! End-to-end smoke test (TASK-027, Phase 2).
//!
//! Walks a synthetic "malicious" payload through the production layers
//! wired in Phase 2:
//!
//!   1. Hash the file (BLAKE3 + SHA-256) via the engine's [`Hasher`].
//!   2. Build a `<feeds>/abusech_sha256.bin` containing the file's hash.
//!   3. Run [`DetectionPipeline`] over a [`FileCtx`] populated from the
//!      hash → assert [`PipelineOutcome::Detected`].
//!   4. Record the finding via [`history::record_finding`].
//!   5. Apply [`FindingAction::Quarantine`] via
//!      [`findings::apply_action`] → state advances to
//!      [`FindingState::Quarantined`].
//!   6. Move the file into the vault via
//!      [`QuarantineVault::quarantine`].
//!   7. Restore via [`QuarantineVault::restore`] and assert the recovered
//!      bytes equal the original payload.
//!
//! **Why a synthetic payload and not the literal EICAR string?** Windows
//! Defender (and most consumer AVs) intercepts the EICAR string on file
//! creation with `ERROR_VIRUS_INFECTED`, so any CI matrix that includes
//! Windows can't run a real-EICAR drop test without disabling Defender
//! globally — which we won't do in CI. The synthetic payload below is a
//! Mythodikal-private 256-byte sentinel that no upstream AV will block;
//! the engine plumbing it exercises is identical to what an EICAR drop
//! would have hit. A literal EICAR drop test is documented in the manual
//! Phase 2 smoke-test playbook (run on Linux / macOS systems without
//! Defender-equivalent on-write scanners).
//!
//! Full integration through `ScanEngine::scan` (so the pipeline runs
//! inline on every walked file) lands in Phase 3 — the engine grows a
//! detector-registry surface in TASK-028. The component contracts that
//! *will* be wired through that layer are all verified here.

use std::fs;

use mythkernel::db;
use mythkernel::detect::hash_blacklist::HashBlacklistDetector;
use mythkernel::detect::hash_set_file::write_sorted;
use mythkernel::detect::{
    DetectionPipeline, FileCtx, HashKind, PipelineOutcome, blake3_hex_to_bytes,
};
use mythkernel::findings::{self, FindingAction, FindingState};
use mythkernel::hasher::Hasher;
use mythkernel::history::{ScanTrigger, create_scan, record_finding};
use mythkernel::quarantine::{QuarantineKey, QuarantineVault};
use tempfile::tempdir;

/// 256-byte synthetic "malware" payload — a Mythodikal-private sentinel
/// that no third-party AV product will flag (so this test is safe to run
/// on Windows with Defender on). Distinct from EICAR specifically because
/// EICAR-on-Windows trips ERROR_VIRUS_INFECTED at fs::write time.
const SYNTH_PAYLOAD: &[u8; 256] = &{
    let mut b = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        b[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
        i += 1;
    }
    b
};

#[tokio::test(flavor = "multi_thread")]
async fn drop_payload_detect_quarantine_restore_roundtrip() {
    let dir = tempdir().unwrap();
    let target_path = dir.path().join("sample.bin");
    fs::write(&target_path, SYNTH_PAYLOAD).unwrap();

    // 1. Hash with SHA-256 enabled — abuse.ch detector queries SHA-256.
    let hasher = Hasher::new().with_sha256(true);
    let hash = hasher.hash_file(&target_path).unwrap();
    let blake3 = blake3_hex_to_bytes(&hash.blake3).expect("blake3 hex");
    let sha256 = decode_sha256(hash.sha256.as_deref().expect("sha256 enabled"));

    // 2. Build a synthetic abuse.ch SHA-256 .bin containing only the
    //    payload's hash.
    let feeds_dir = dir.path().join("feeds");
    fs::create_dir_all(&feeds_dir).unwrap();
    let feed_path = feeds_dir.join("abusech_sha256.bin");
    write_sorted(&feed_path, [sha256]).unwrap();

    // 3. Run the detection pipeline over a FileCtx matching what the
    //    engine would build after the hasher returns.
    let detector = HashBlacklistDetector::open(&feed_path)
        .expect("opens the freshly-built feed")
        .with_hash_kind(HashKind::Sha256);
    assert_eq!(detector.loaded_count(), 1);
    let pipeline = DetectionPipeline::new(vec![Box::new(detector)]);

    let ctx = FileCtx {
        path: &target_path,
        size_bytes: SYNTH_PAYLOAD.len() as u64,
        blake3: &blake3,
        sha256: Some(&sha256),
    };
    let outcome = pipeline.evaluate(&ctx);
    let (rule_id, rule_source, severity_str) = match outcome {
        PipelineOutcome::Detected {
            rule_id,
            rule_source,
            severity,
            detector_id,
            ..
        } => {
            assert_eq!(detector_id, "hash_blacklist");
            assert_eq!(rule_source, "abusech");
            (rule_id, rule_source, severity.as_str().to_string())
        }
        other => panic!("expected Detected, got {other:?}"),
    };

    // 4. Persist a scan + a finding the way history::record_finding does.
    let mut conn = db::open_in_memory().unwrap();
    let scan_id = create_scan(
        &conn,
        1_700_000_000,
        ScanTrigger::Manual,
        "path",
        &serde_json::to_string(std::slice::from_ref(&target_path)).unwrap(),
        "[]",
        env!("CARGO_PKG_VERSION"),
        "{\"abusech\":1}",
    )
    .unwrap();
    let finding_id = record_finding(
        &conn,
        scan_id,
        target_path.to_string_lossy().as_ref(),
        Some(SYNTH_PAYLOAD.len() as i64),
        Some(&blake3),
        Some(&sha256),
        &rule_id,
        &rule_source,
        &severity_str,
        1_700_000_100,
    )
    .unwrap();

    // 5. Transition the finding to Quarantined via the action API.
    let next = findings::apply_action(&conn, finding_id, FindingAction::Quarantine).unwrap();
    assert_eq!(next, FindingState::Quarantined);

    // 6. Move the file into the vault.
    let vault = QuarantineVault::with_key(dir.path().join("vault"), fixed_key()).unwrap();
    let canonical_target = target_path.canonicalize().unwrap();
    let entry = vault
        .quarantine(&mut conn, Some(finding_id), &target_path)
        .unwrap();
    assert!(!target_path.exists(), "original file should be removed");
    assert!(entry.vault_path.exists(), "vault file should exist");
    // The vault file is XOR'd — it must NOT equal the payload bytes.
    let vault_bytes = fs::read(&entry.vault_path).unwrap();
    assert_eq!(vault_bytes.len(), SYNTH_PAYLOAD.len());
    assert_ne!(&vault_bytes[..], &SYNTH_PAYLOAD[..]);

    // 7. Restore and verify byte-for-byte equality with the original.
    let restored = vault.restore(&mut conn, entry.id).unwrap();
    assert_eq!(restored, canonical_target);
    let recovered = fs::read(&target_path).unwrap();
    assert_eq!(&recovered[..], &SYNTH_PAYLOAD[..]);

    // The quarantine row should be gone after a successful restore.
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 0);

    // The finding row's state was set by apply_action(Quarantine) — that
    // is the pure-DB transition the orchestrator owns. The next-step
    // transition to Restored is the responsibility of the higher layer
    // (TASK-026 / Phase 3 ui-bridge); this test stops at the engine
    // layer's contract.
    let final_state = findings::current_state(&conn, finding_id).unwrap();
    assert_eq!(final_state, FindingState::Quarantined);

    // Sanity: rule_id has the abuse.ch prefix shape we expect.
    assert!(rule_id.starts_with("abusech:hash:"), "got {rule_id}");
}

#[test]
fn pipeline_outcome_is_clean_when_payload_not_in_blacklist() {
    let dir = tempdir().unwrap();
    let target_path = dir.path().join("benign.bin");
    fs::write(&target_path, b"not in any feed").unwrap();
    let hasher = Hasher::new().with_sha256(true);
    let hash = hasher.hash_file(&target_path).unwrap();
    let blake3 = blake3_hex_to_bytes(&hash.blake3).unwrap();
    let sha256 = decode_sha256(hash.sha256.as_deref().unwrap());

    let feed_path = dir.path().join("empty.bin");
    write_sorted(&feed_path, std::iter::empty()).unwrap();
    let detector = HashBlacklistDetector::open(&feed_path).unwrap();
    let pipeline = DetectionPipeline::new(vec![Box::new(detector)]);
    let outcome = pipeline.evaluate(&FileCtx {
        path: &target_path,
        size_bytes: 0,
        blake3: &blake3,
        sha256: Some(&sha256),
    });
    assert_eq!(outcome, PipelineOutcome::Clean);
}

fn fixed_key() -> QuarantineKey {
    QuarantineKey::from_bytes([0x55; 32])
}

fn decode_sha256(hex_str: &str) -> [u8; 32] {
    assert_eq!(hex_str.len(), 64);
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).expect("valid hex");
    out
}
