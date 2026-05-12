//! `mythctl quarantine` (TASK-026 / TASK-127).
//!
//! Single binary entry point for the FR-041..047 vault operations:
//!
//! - `list` — show every vault entry, table or JSON
//! - `restore <id>` / `delete <id>` — single-item ops (FR-042 / FR-043)
//! - `restore-all` / `delete-all --confirm` — bulk ops (FR-045 / FR-046)
//! - `restore-many <ids...>` / `delete-many <ids...>` — multi-select (FR-047)
//!
//! `delete-all` is gated on `--confirm` per FR-046 to match the GUI's
//! type-DELETE step. Other destructive ops (`delete`, `delete-many`) don't
//! gate by default but accept `--yes` for symmetry; the GUI surfaces a
//! confirmation modal there.
//!
//! Progress for bulk ops is printed to stderr (one line per item, like
//! `[42/100] ok  restored: /home/u/file.bin`). The JSON output mode emits
//! one NDJSON line per `BatchProgress` event followed by a final
//! `BatchReport` summary line.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{Subcommand, ValueEnum};
use mythkernel::{
    db,
    quarantine::{BatchProgress, BatchReport, ProgressCallback, QuarantineVault},
};

use crate::Format;

#[derive(Subcommand)]
pub enum QuarantineCmd {
    /// List every quarantined file.
    List {
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Restore a single entry to its original path. Refuses to overwrite
    /// an existing file there.
    Restore {
        /// Numeric quarantine row id (from `list`).
        id: i64,
    },
    /// Permanently delete a single entry.
    Delete {
        id: i64,
        /// Skip the confirmation prompt (no-op for now — `delete` never
        /// prompts at the CLI level; the GUI is the only confirmation
        /// surface). Accepted for symmetry with `delete-all --confirm`.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Restore every quarantined entry.
    RestoreAll {
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Permanently delete every quarantined entry. **Requires** `--confirm`
    /// to proceed (per FR-046 the GUI requires the literal word DELETE be
    /// typed; the CLI uses `--confirm` as the equivalent gate).
    DeleteAll {
        #[arg(long, default_value_t = false)]
        confirm: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Restore a multi-select of ids.
    RestoreMany {
        /// One or more numeric quarantine row ids.
        #[arg(required = true, num_args = 1..)]
        ids: Vec<i64>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Delete a multi-select of ids.
    DeleteMany {
        #[arg(required = true, num_args = 1..)]
        ids: Vec<i64>,
        #[arg(long, default_value_t = false)]
        yes: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum BulkVerb {
    Restore,
    Delete,
}

pub fn run(cmd: QuarantineCmd, db_path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match db_path {
        Some(p) => p,
        None => db::default_db_path().context("resolve default db path")?,
    };
    let mut conn = db::open(&path).context("open engine db")?;
    let data_dir = path
        .parent()
        .ok_or_else(|| anyhow!("db path has no parent: {}", path.display()))?
        .to_path_buf();
    let vault = QuarantineVault::new(&data_dir).map_err(|e| anyhow!("open vault: {e}"))?;

    match cmd {
        QuarantineCmd::List { format } => list(&vault, &conn, format),
        QuarantineCmd::Restore { id } => {
            let restored = vault.restore(&mut conn, id).map_err(|e| anyhow!(e))?;
            println!("restored: {}", restored.display());
            Ok(())
        }
        QuarantineCmd::Delete { id, yes: _ } => {
            vault.delete(&mut conn, id).map_err(|e| anyhow!(e))?;
            println!("deleted: id={id}");
            Ok(())
        }
        QuarantineCmd::RestoreAll { format } => {
            let cb = bulk_progress_cb(format);
            let report = vault
                .restore_all(&mut conn, Some(&cb))
                .map_err(|e| anyhow!(e))?;
            print_report(&report, format)
        }
        QuarantineCmd::DeleteAll { confirm, format } => {
            if !confirm {
                return Err(anyhow!(
                    "refusing to delete-all without --confirm (FR-046). \
                     Pass --confirm to acknowledge the destructive action."
                ));
            }
            let cb = bulk_progress_cb(format);
            let report = vault
                .delete_all(&mut conn, Some(&cb))
                .map_err(|e| anyhow!(e))?;
            print_report(&report, format)
        }
        QuarantineCmd::RestoreMany { ids, format } => {
            let cb = bulk_progress_cb(format);
            let report = vault
                .restore_many(&mut conn, &ids, Some(&cb))
                .map_err(|e| anyhow!(e))?;
            print_report(&report, format)
        }
        QuarantineCmd::DeleteMany {
            ids,
            yes: _,
            format,
        } => {
            let cb = bulk_progress_cb(format);
            let report = vault
                .delete_many(&mut conn, &ids, Some(&cb))
                .map_err(|e| anyhow!(e))?;
            print_report(&report, format)
        }
    }
}

fn list(
    vault: &QuarantineVault,
    conn: &rusqlite::Connection,
    format: Format,
) -> anyhow::Result<()> {
    let entries = vault.list(conn).map_err(|e| anyhow!(e))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match format {
        Format::Json => {
            for e in entries {
                writeln!(out, "{}", serde_json::to_string(&serde_entry(&e))?)?;
            }
        }
        Format::Text => {
            if entries.is_empty() {
                writeln!(out, "(no quarantined files)")?;
                return Ok(());
            }
            writeln!(out, "{:>6}  {:>10}  ORIGINAL PATH", "ID", "BYTES")?;
            for e in &entries {
                writeln!(
                    out,
                    "{:>6}  {:>10}  {}",
                    e.id,
                    e.size_bytes,
                    e.original_path.display()
                )?;
            }
        }
    }
    Ok(())
}

fn serde_entry(e: &mythkernel::quarantine::QuarantineEntry) -> serde_json::Value {
    serde_json::json!({
        "id": e.id,
        "finding_id": e.finding_id,
        "original_path": e.original_path,
        "vault_path": e.vault_path,
        "size_bytes": e.size_bytes,
        "xor_key_id": e.xor_key_id,
        "quarantined_at_utc": e.quarantined_at_utc,
    })
}

fn bulk_progress_cb(format: Format) -> ProgressCallback {
    let stderr_format = format;
    Arc::new(move |p: BatchProgress| {
        let stderr = std::io::stderr();
        let mut e = stderr.lock();
        match stderr_format {
            Format::Text => {
                let outcome = match &p.last_error {
                    None => "ok ".to_string(),
                    Some(err) => format!("err (id={}: {})", err.quarantine_id, err.error),
                };
                let _ = writeln!(
                    e,
                    "[{}/{}] {} ({} {})",
                    p.items_done,
                    p.items_total,
                    outcome,
                    p.kind.as_str(),
                    fmt_bytes(p.bytes_done, p.bytes_total)
                );
            }
            Format::Json => {
                let _ = serde_json::to_writer(&mut e, &p);
                let _ = writeln!(e);
            }
        }
    })
}

fn fmt_bytes(done: u64, total: u64) -> String {
    format!("{done}/{total} bytes")
}

fn print_report(report: &BatchReport, format: Format) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match format {
        Format::Json => {
            writeln!(out, "{}", serde_json::to_string(report)?)?;
        }
        Format::Text => {
            writeln!(
                out,
                "batch {} ({}): {}/{} items, {}/{} bytes, {} errors",
                report.batch_id,
                report.kind.as_str(),
                report.items_done,
                report.items_total,
                report.bytes_done,
                report.bytes_total,
                report.errors.len()
            )?;
            for err in &report.errors {
                writeln!(out, "  ! id={}: {}", err.quarantine_id, err.error)?;
            }
        }
    }
    Ok(())
}
