-- 0001_initial.sql — Freally Anti-Virus initial schema (Phase 1 / TASK-011).
--
-- Source of truth: docs/prd.md § 3.1.
--
-- Phase 1 ships only the tables the engine reads/writes during a Phase-1 scan:
-- scans, findings, quarantine, exclusions. Detector-specific tables
-- (file_baseline, persistence_entries, quarantine_batches, etc.) get their
-- own migrations in the phases that introduce them.
--
-- Connection-level PRAGMAs (foreign_keys, journal_mode, synchronous) are set
-- by the engine in `db::configure_connection` BEFORE this migration runs,
-- because PRAGMA journal_mode cannot execute inside a transaction.

CREATE TABLE IF NOT EXISTS scans (
  id              INTEGER PRIMARY KEY,
  started_at_utc  INTEGER NOT NULL,
  ended_at_utc    INTEGER,
  trigger         TEXT NOT NULL,
  target_kind     TEXT NOT NULL,
  target_paths    TEXT NOT NULL,
  exclusions_snap TEXT NOT NULL,
  engine_version  TEXT NOT NULL,
  feed_versions   TEXT NOT NULL,
  files_visited   INTEGER NOT NULL DEFAULT 0,
  files_hashed    INTEGER NOT NULL DEFAULT 0,
  files_yara      INTEGER NOT NULL DEFAULT 0,
  archive_members_visited INTEGER NOT NULL DEFAULT 0,
  bytes_visited   INTEGER NOT NULL DEFAULT 0,
  findings_count  INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL,
  resume_token    BLOB
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at_utc DESC);

CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY,
  scan_id         INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  path            TEXT NOT NULL,
  size_bytes      INTEGER,
  blake3          BLOB,
  sha256          BLOB,
  rule_id         TEXT NOT NULL,
  rule_source     TEXT NOT NULL,
  severity        TEXT NOT NULL,
  detected_at_utc INTEGER NOT NULL,
  action_taken    TEXT NOT NULL DEFAULT 'none',
  evidence        TEXT,
  notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_path ON findings (path);

CREATE TABLE IF NOT EXISTS quarantine (
  id                 INTEGER PRIMARY KEY,
  finding_id         INTEGER REFERENCES findings (id) ON DELETE SET NULL,
  original_path      TEXT NOT NULL,
  vault_path         TEXT NOT NULL,
  size_bytes         INTEGER NOT NULL,
  xor_key_id         INTEGER NOT NULL,
  quarantined_at_utc INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quarantine_finding ON quarantine (finding_id);

CREATE TABLE IF NOT EXISTS exclusions (
  id              INTEGER PRIMARY KEY,
  kind            TEXT NOT NULL,
  value           TEXT NOT NULL,
  scope           TEXT NOT NULL DEFAULT 'both',
  expires_at_utc  INTEGER,
  created_at_utc  INTEGER NOT NULL,
  reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_exclusions_kind ON exclusions (kind);

-- The `schema_migrations` row for this migration is inserted by the engine
-- (`crates/freallykernel/src/db.rs::apply_migrations`) inside the same
-- transaction as the DDL above, so a partially-applied migration leaves no
-- marker.
