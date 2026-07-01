-- 0003_exclusions_publisher_and_baseline.sql — Phase 4 wave 3 (TASK-135 + TASK-136).
--
-- The base `exclusions` table from migration 0001 already has the `scope`
-- and `expires_at_utc` columns FR-134 + TASK-135 promised, so the only
-- schema change required by TASK-135 is the value of `kind` accepting
-- `'publisher'` (TASK-136 — no DDL needed because `kind` is TEXT).
--
-- TASK-136 also persists a per-file signer cache keyed by
-- (path, mtime, size) so we never re-parse the Authenticode / codesign /
-- GPG blob unless the file's metadata changed. The blob itself is the
-- canonical signer-identity string (e.g. "Authenticode: CN=Microsoft
-- Corporation, ..." or "codesign-team-id: ABC123XYZW").
--
-- Note: the engine-only signer columns intentionally use snake_case
-- without a foreign key — the cache is best-effort and survives file
-- moves only as long as the (mtime, size) tuple is stable.

CREATE TABLE IF NOT EXISTS publisher_cache (
  path             TEXT NOT NULL,
  mtime_unix       INTEGER NOT NULL,
  size_bytes       INTEGER NOT NULL,
  signer_identity  TEXT NOT NULL,
  signer_kind      TEXT NOT NULL,  -- 'authenticode' | 'codesign' | 'gpg' | 'unsigned'
  inspected_at_utc INTEGER NOT NULL,
  PRIMARY KEY (path, mtime_unix, size_bytes)
);

CREATE INDEX IF NOT EXISTS idx_publisher_cache_identity ON publisher_cache (signer_identity);
