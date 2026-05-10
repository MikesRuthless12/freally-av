//! Engine error types. Filled in by TASK-015.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("not yet implemented")]
    NotImplemented,
}
