-- TASK-195 — User-supplied IOC bundles.
--
-- Per-row IOC consumed by the scanner alongside the published
-- blacklist feeds. Designed for paste-and-go: the user drops a
-- CSV / STIX-2.1 / MISP-export JSON / plain hash list into the
-- IOCs editor in Settings, the parser normalises to rows in this
-- table, and the scanner picks them up on the next scan.

CREATE TABLE IF NOT EXISTS user_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Group inside which this row was imported. Free-form label
    -- (typically the original filename or paste-timestamp).
    bundle TEXT NOT NULL,
    -- IOC type. Each row carries exactly one type per `value`:
    --   md5    — 32 lowercase hex
    --   sha1   — 40 lowercase hex
    --   sha256 — 64 lowercase hex
    --   blake3 — 64 lowercase hex
    ioc_type TEXT NOT NULL CHECK (
        ioc_type IN ('md5','sha1','sha256','blake3')
    ),
    value TEXT NOT NULL,
    -- Per-IOC enable/disable from the UI without deleting the row.
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Optional scope (path glob, file-type list). NULL = any path.
    scope_glob TEXT,
    note TEXT,
    created_at_utc INTEGER NOT NULL,
    UNIQUE (ioc_type, value)
);
CREATE INDEX IF NOT EXISTS user_iocs_value  ON user_iocs(value);
CREATE INDEX IF NOT EXISTS user_iocs_bundle ON user_iocs(bundle);
