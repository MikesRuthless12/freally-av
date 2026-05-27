//! Persistence helpers (Phase 7C and later).
//!
//! The engine's main store lives in [`crate::db`]; this module owns
//! the small per-feature tables added incrementally — baseline
//! (TASK-226), chunk store (TASK-231), and so on. They live here so
//! the migrations / `Cargo.toml` deps grow in one predictable place.

pub mod baseline;
pub mod chunks;
