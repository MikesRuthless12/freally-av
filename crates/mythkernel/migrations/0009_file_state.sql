-- 0009_file_state.sql — TASK-202: differential rescan since last clean.
--
-- Caches a (mtime, size, ctime, inode) tuple for every file that emitted
-- a clean outcome from a previous scan. When the walker re-encounters
-- that path, the engine compares the live stat against the cached tuple;
-- a match short-circuits the hash + detect pipeline (emit `source=diff-
-- cache` clean shortcut). Any tuple change forces a full re-hash.
--
-- Distinct from the verdict_cache (TASK-Phase-6) which caches (path,
-- mtime, size) → verdict — this table caches CLEAN files only and uses
-- the wider 4-tuple so a file restored from backup (mtime preserved,
-- inode + ctime changed) still gets re-hashed.
--
-- Cache invalidation: the `feed_epoch_state` row tracks the feed_epoch
-- last used by a scan; mismatch on launch → wipe `file_state` (a new
-- blocklist epoch means yesterday's clean verdict no longer applies).

CREATE TABLE IF NOT EXISTS file_state (
  path                TEXT PRIMARY KEY,
  size                INTEGER NOT NULL,
  mtime               INTEGER NOT NULL,
  ctime               INTEGER NOT NULL,
  inode               INTEGER NOT NULL,
  last_clean_scan_id  INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_state_scan
  ON file_state (last_clean_scan_id);

CREATE TABLE IF NOT EXISTS feed_epoch_state (
  rowid          INTEGER PRIMARY KEY CHECK (rowid = 1),
  current_epoch  INTEGER NOT NULL
);
