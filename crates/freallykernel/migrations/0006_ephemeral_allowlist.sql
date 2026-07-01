-- TASK-190 — Ephemeral allowlist ("Trust this once" with auto-expiry).
--
-- One row per (hash, scope, expires_at) triple. The scanner consults
-- this table before the blacklist; expired rows are auto-pruned by
-- the engine on every scan-start (cheap query — indexed on expires_at).
--
-- Distinct from `exclusions` (path/glob/hash patterns the user
-- permanently allowlists from Settings → Exclusions). This table is
-- intentionally separate so a "trust once" never accidentally
-- becomes permanent — the entry self-destructs.

CREATE TABLE IF NOT EXISTS ephemeral_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 64-hex-char SHA-256 of the trusted file's bytes.
    sha256_hex TEXT NOT NULL,
    -- Optional path scope: when set, only that exact path matching
    -- this sha256 honors the trust. When NULL, any path with the
    -- matching hash is trusted (less restrictive).
    scope_path TEXT,
    -- Why the user trusted it (free-form). Surfaced in the audit
    -- trail; never empty (clients must provide a one-liner).
    reason TEXT NOT NULL,
    -- Unix timestamps.
    created_at_utc INTEGER NOT NULL,
    expires_at_utc INTEGER NOT NULL,
    -- Provenance for the audit ledger.
    created_by TEXT NOT NULL DEFAULT 'user'
);

CREATE INDEX IF NOT EXISTS ephemeral_allowlist_sha
    ON ephemeral_allowlist(sha256_hex);
CREATE INDEX IF NOT EXISTS ephemeral_allowlist_expires
    ON ephemeral_allowlist(expires_at_utc);
