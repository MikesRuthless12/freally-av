-- 0005_verdict_cache.sql — Phase 5 wave 3 follow-up (perf push).
--
-- Skip-if-unchanged verdict cache keyed on (path, mtime, size). On a
-- repeat scan, every file whose tuple hasn't changed since last scan
-- is served from this table without re-hashing — the canonical
-- commercial-AV pattern (Avast / Malwarebytes / BitDefender all use
-- this shape). Cold scans are unchanged; warm scans go from ~100 files/s
-- to ~10K+ files/s because the disk+hash work is bypassed entirely.
--
-- `pipeline_outcome` carries the verdict the detection pipeline
-- returned the last time we hashed this exact tuple. Format:
--   - `clean` — no detector matched
--   - `skip:<detector_id>` — allowlist verdict (NSRL etc.)
--   - `detected:<rule_source>:<rule_id>` — blacklist match
--
-- Cache invalidation: implicit on mtime change (most file edits
-- update mtime). Manual invalidation: drop the row or call
-- `verdict_cache::clear(conn)`. Quarantine actions DELETE the source
-- file so cache lines for moved files self-prune the next time the
-- engine looks them up and the canonical path is gone.
--
-- A future migration may add a `feed_version` column so a feed
-- update invalidates the cache transitively; for v1 we accept that
-- updating a feed doesn't re-evaluate already-cached files until
-- their mtime changes. Users who want a full re-evaluation can
-- explicitly clear the table via Settings (UI surface lands in a
-- later wave) or by re-installing.

CREATE TABLE IF NOT EXISTS verdict_cache (
  path             TEXT NOT NULL,
  mtime_unix       INTEGER NOT NULL,
  size_bytes       INTEGER NOT NULL,
  -- Lower-case hex BLAKE3 of the file at this snapshot point.
  blake3_hex       TEXT NOT NULL,
  -- Lower-case hex SHA-256 when the engine computed it during the
  -- cached run (because at least one detector required it). NULL
  -- otherwise.
  sha256_hex       TEXT,
  pipeline_outcome TEXT NOT NULL,
  cached_at_utc    INTEGER NOT NULL,
  PRIMARY KEY (path, mtime_unix, size_bytes)
);

-- Pruning by age is a Phase-14 hardening concern; the index lets us
-- run `DELETE FROM verdict_cache WHERE cached_at_utc < ?` efficiently
-- when the time comes.
CREATE INDEX IF NOT EXISTS idx_verdict_cache_age
  ON verdict_cache (cached_at_utc);
