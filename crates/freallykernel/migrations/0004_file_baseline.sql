-- 0004_file_baseline.sql — Phase 5 wave 3 (TASK-138).
--
-- Per-scan inventory of "interesting" files — autostart paths, $PATH
-- binaries, scripts — captured at scan time so the next scan can flag
-- mutations. FR-131. Detection logic in `detect/file_mutation.rs`.
--
-- Rows are keyed on (path, blake3) — a single path can accrete multiple
-- baseline rows across scans as the file content changes. Detection
-- compares the *current* (path, blake3) tuple against the most recent
-- prior tuple for the same path; an alert fires when the prior was
-- signed-or-NSRL-known and the current is neither.
--
-- The table is intentionally append-only: we never UPDATE a row, we
-- INSERT a new one. Pruning (e.g. drop > 1y old) is a Phase-14 hardening
-- concern; the scan-history retention sweep covers it implicitly.

CREATE TABLE IF NOT EXISTS file_baseline (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id            INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  path               TEXT NOT NULL,
  -- Lower-case hex BLAKE3 of the file at this snapshot point.
  blake3_hex         TEXT NOT NULL,
  -- Lower-case hex SHA-256 when the engine had a SHA-256-keyed detector
  -- loaded (so the hash was already computed). NULL otherwise; the
  -- mutation detector tolerates a missing prior SHA-256.
  sha256_hex         TEXT,
  size_bytes         INTEGER NOT NULL,
  -- Free-text signer identity from `detect/publisher.rs`. Empty string
  -- on unsigned. The mutation detector treats non-empty as "signed".
  signer_identity    TEXT NOT NULL,
  -- `'authenticode' | 'codesign' | 'gpg' | 'unsigned'`. Mirror of
  -- `publisher_cache.signer_kind`.
  signer_kind        TEXT NOT NULL,
  -- 1 when this file's SHA-256 was on the NSRL goodware allowlist at
  -- scan time; 0 otherwise. The mutation detector treats prior `1` as
  -- "previously known good".
  nsrl_known         INTEGER NOT NULL DEFAULT 0,
  -- `'autostart' | 'path_bin' | 'script' | 'other'`. Surfaced verbatim
  -- in the mutation finding's evidence column.
  source             TEXT NOT NULL,
  recorded_at_utc    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_baseline_path
  ON file_baseline (path, recorded_at_utc DESC);

CREATE INDEX IF NOT EXISTS idx_file_baseline_scan_id
  ON file_baseline (scan_id);
