//! Signature feed + engine updaters. Filled in by TASK-022/023 (Phase 2),
//! TASK-129/130/131 (Phase 4 channel split).
//!
//! Phase 4 wave 3 — TASK-129 split the updater into two completely independent
//! channels (engine vs database) per FR-151. The legacy [`scheduler`] module is
//! kept as a thin compatibility shim while callers migrate to the new
//! [`database::DatabaseChannel`] and [`engine::EngineChannel`] surfaces.

pub mod abusech;
pub mod channels;
/// Curated repo-distributed blacklist downloader (repo-curated-DB decision,
/// 2026-06-21). Downloads the maintainer-curated `.bin` from the GitHub
/// release and atomically swaps it into `<feeds_dir>/abusech_sha256.bin`;
/// the raw abuse.ch upstream pull is disabled. Adapter runners live in
/// [`database`] (manual / channel) and [`scheduler`] (periodic).
pub mod curated;
pub mod database;
pub mod delta_sig;
pub mod engine;
/// BYOVD blocklist via loldrivers.io (TASK-139). Daily JSON pull,
/// SHA-256 extraction, sorted-set binary write. Detector lives in
/// [`crate::detect::byovd`].
pub mod loldrivers;
pub mod mirrors;
pub mod nsrl;
pub mod scheduler;
pub mod yara_forge;

pub use channels::{
    ChannelKind, ChannelState, LastCheckOutcome, load_state, save_state, updater_dir,
};
pub use curated::{CuratedBlacklistUpdater, CuratedError, CuratedUpdateReport};
pub use database::{
    AbuseChFeedRunner, CuratedBlacklistFeedRunner, DatabaseChannel, DatabaseChannelState,
    DatabaseFeedRunner, DatabaseUpdatePhase, DatabaseUpdateProgress, DbProgressCallback, FeedMeta,
    FeedRunOutcome, NsrlFeedRunner,
};
pub use engine::{
    DEFAULT_LATEST_JSON_URL, EngineChannel, EngineUpdateAvailable, EngineUpdateError,
    EngineUpdatePhase, EngineUpdateProgress, compare_versions, record_check as record_engine_check,
    verify_signature,
};
