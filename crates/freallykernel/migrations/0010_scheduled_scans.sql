-- 0010_scheduled_scans.sql — TASK-086 (Phase 10): cron-like scan scheduler.
--
-- Stores user-defined scheduled scans the engine ticks against once a
-- minute. The engine queries `SELECT … WHERE enabled = 1` on each tick,
-- evaluates each row's recurrence against the wall clock + the host's
-- idle-seconds reading, and dispatches the matching scans through the
-- normal `scan::ScanEngine` path. Last-fire stamp persists so an engine
-- restart doesn't re-fire a schedule that already ran in the current
-- window.
--
-- Schedule recurrence is encoded as `kind` + a kind-specific JSON
-- payload in `kind_data` rather than POSIX cron syntax. The four kinds
-- cover every UI-exposed option:
--
--   * 'daily'   — kind_data = '{}', runs at_hour/at_minute every day
--   * 'weekly'  — kind_data = '{"weekdays":[0,1,2,...]}' (0 = Sunday)
--   * 'monthly' — kind_data = '{"day":15}'
--   * 'oneshot' — kind_data = '{"at_unix":1735689600}'
--
-- `idle_min_seconds` enforces the FR-086 idle-only constraint. Engine
-- skips firing when `host idle_seconds < idle_min_seconds`. 0 disables
-- the gate. Per the roadmap the UI default is 60 s (one minute of
-- keyboard / mouse quiet) so a scheduled scan can't elbow a user mid-
-- typing.

CREATE TABLE IF NOT EXISTS scheduled_scans (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  name              TEXT    NOT NULL,
  enabled           INTEGER NOT NULL DEFAULT 1,
  kind              TEXT    NOT NULL CHECK (kind IN ('daily','weekly','monthly','oneshot')),
  kind_data         TEXT    NOT NULL DEFAULT '{}',
  at_hour           INTEGER NOT NULL CHECK (at_hour BETWEEN 0 AND 23),
  at_minute         INTEGER NOT NULL CHECK (at_minute BETWEEN 0 AND 59),
  idle_min_seconds  INTEGER NOT NULL DEFAULT 60,
  scan_roots        TEXT    NOT NULL DEFAULT '[]',
  last_fired_at     INTEGER,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);

-- The tick loop reads only enabled rows; a partial index keeps that
-- O(N enabled) without paying for disabled history rows.
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled
  ON scheduled_scans (enabled)
  WHERE enabled = 1;
