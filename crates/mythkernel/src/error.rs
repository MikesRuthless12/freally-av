//! Engine error types. Filled in by TASK-015.

//! Engine error type.
//!
//! TASK-015 (Phase 1) — single `EngineError` enum used by every public
//! mythkernel entry point. Serializable so the Tauri bridge (TASK-028) and
//! `mythctl` (TASK-017) can pass errors across the IPC boundary without
//! losing their categorical kind.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum EngineError {
    #[error("not yet implemented")]
    NotImplemented,

    #[error("io: {0}")]
    Io(String),

    #[error("db: {0}")]
    Db(String),

    #[error("scan: {0}")]
    Scan(String),

    #[error("config: {0}")]
    Config(String),

    #[error("path not found: {0}")]
    PathNotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<std::io::Error> for EngineError {
    fn from(err: std::io::Error) -> Self {
        EngineError::Io(err.to_string())
    }
}

impl From<crate::db::DbError> for EngineError {
    fn from(err: crate::db::DbError) -> Self {
        EngineError::Db(err.to_string())
    }
}
