-- 0002_quarantine_batches.sql — Bulk quarantine operations (TASK-127, FR-045/046/047).
--
-- Source of truth: docs/prd.md § 3.1.
--
-- Records each batched restore-many / delete-many / restore-all / delete-all
-- run. Engine inserts a row when a batch starts, updates items_done /
-- bytes_done as each item completes, sets status + ended_at_utc when the
-- run finishes. UI subscribers consume `quarantine:batch_progress` events
-- (emitted at ≤ 10 Hz by the engine event bus) rather than polling this
-- table — the table is for audit + restart-recovery after a crash.

CREATE TABLE IF NOT EXISTS quarantine_batches (
  id              INTEGER PRIMARY KEY,
  kind            TEXT NOT NULL,           -- 'restore' | 'delete'
  started_at_utc  INTEGER NOT NULL,
  ended_at_utc    INTEGER,
  items_total     INTEGER NOT NULL,
  items_done      INTEGER NOT NULL DEFAULT 0,
  bytes_total     INTEGER NOT NULL,
  bytes_done      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL,           -- 'running' | 'completed' | 'cancelled' | 'failed'
  error_log       TEXT                     -- JSON array of {id, error} for items that failed
);

CREATE INDEX IF NOT EXISTS idx_quarantine_batches_started_at
  ON quarantine_batches (started_at_utc DESC);
