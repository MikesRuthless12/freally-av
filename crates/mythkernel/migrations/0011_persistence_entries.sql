-- 0011_persistence_entries.sql — TASK-144 (FR-137, Phase 10):
-- cross-platform persistence-mechanism inventory.
--
-- One row per OS-level autostart surface (Startup folder file, macOS
-- LaunchAgent / LaunchDaemon, Linux systemd user unit / XDG autostart
-- desktop entry, crontab entry, Windows Run / RunOnce registry value).
-- The Persistence page (TASK-144 frontend) renders this table; TASK-149's
-- persistence-diff joins two scans' snapshots to surface new / removed
-- autostart entries.
--
-- `kind` is a small closed enum:
--   'startup_folder'   - Windows Startup folder file
--   'run_key'          - Windows registry Run / RunOnce value
--   'service'          - Windows service set to auto-start
--   'launch_agent'     - macOS LaunchAgent plist (~/Library/LaunchAgents)
--   'launch_daemon'    - macOS LaunchDaemon plist (/Library/LaunchDaemons)
--   'login_item'       - macOS legacy login item
--   'systemd_unit'     - Linux systemd user / system unit
--   'xdg_autostart'    - Linux ~/.config/autostart/*.desktop
--   'crontab'          - Linux crontab entry
--
-- `identifier` is the canonical name within the kind — e.g. the registry
-- path on Windows, the plist label on macOS, the systemd unit name on
-- Linux. Combined with `kind` it's unique so re-scans upsert the
-- existing row.

CREATE TABLE IF NOT EXISTS persistence_entries (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  kind            TEXT    NOT NULL,
  identifier      TEXT    NOT NULL,
  target_path     TEXT,
  display_name    TEXT,
  signer          TEXT,
  first_seen_at   INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  UNIQUE (kind, identifier)
);

CREATE INDEX IF NOT EXISTS idx_persistence_entries_kind
  ON persistence_entries (kind);
