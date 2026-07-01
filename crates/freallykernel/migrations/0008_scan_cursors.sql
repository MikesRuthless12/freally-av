-- 0008_scan_cursors.sql — TASK-201: resumable scans across reboots.
--
-- Persists a periodically-snapshotted scan cursor + walked-set Bloom filter
-- so a scan interrupted by power loss, SIGKILL, or process crash can resume
-- from where it left off on next start.
--
-- Distinct from `scans.resume_token` (Phase 4 / TASK-040): that token handles
-- graceful user-initiated pause/resume via a one-shot JSON write of the full
-- processed-paths set (capped at 100K) into `scans.resume_token`. A row here
-- is updated every ~5s during a live walk and survives abrupt termination.
--
-- The walked_bloom column stores a serialised `detect::bloom::Builder`
-- (header + payload, MYTHBLOM magic) sized for the configured walk budget
-- (default 10M paths at 0.1% FPR ≈ 18 MB).

CREATE TABLE IF NOT EXISTS scan_cursors (
  scan_id      INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
  root         TEXT NOT NULL,
  cursor_path  TEXT NOT NULL,
  walked_bloom BLOB NOT NULL,
  started_at   INTEGER NOT NULL,
  finished_at  INTEGER
);

-- Recovery query at startup is `WHERE finished_at IS NULL ORDER BY started_at
-- DESC LIMIT 1`. A partial index keeps that O(1) even with thousands of
-- historical completed-then-finished rows.
CREATE INDEX IF NOT EXISTS idx_scan_cursors_unfinished
  ON scan_cursors (started_at DESC)
  WHERE finished_at IS NULL;
