# Changelog

All notable changes to Mythodikal Anti-Virus are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to a 0-based pre-stable [Semantic Versioning](https://semver.org/spec/v2.0.0.html) scheme. The first stable release will be **v0.19.84**.

Each release section lists which `TASK-NNN` items from `docs/product-roadmap.md` shipped in that release. Phase Closeout (per `Mythodikal-Build-Prompts-Guide.md`) populates `[Unreleased]` as work lands and promotes it to a version heading at release time.

---

## [Unreleased]

### Added
- **Phase 7B Wave 2 — Hash-path perf + allowlist intelligence + IOC tools + feed integrity** _(shipped 2026-05-23/24)_

  22 of 23 Wave 2 tasks landed; only TASK-200 (v0.7.13 release tag) remains, gated on TASK-171 smoke + maintainer `git tag`. ~85 new unit tests across the engine + feed-builder.

  **PR-A — Engine foundations** (commit `5d51c25`):
  - **TASK-178** — Bloom filter front-end (`crates/mythkernel/src/detect/bloom.rs`). Sub-microsecond pre-screen consulted before the sorted-`.bin` binary search. 120 MB at 1% FPR / 100M items. Kirsch-Mitzenmacher double-hashing over the input digest's two u64 slices (no SipHash dep — SHA-256/BLAKE3 are uniformly distributed in every byte slice). 9 tests.
  - **TASK-179** — Cuckoo filter alternative (`crates/mythkernel/src/detect/cuckoo.rs`). Same purpose as Bloom plus delete support for the TASK-181 aging job. 4-entry buckets, 12-bit fingerprint, partial-key Cuckoo from Fan et al. (2014). 6 tests.
  - **TASK-180** — Partial-match for files ≥ 256 MB (`crates/mythkernel/src/detect/partial_match.rs`). `(prefix_blake3, size_band)` index. New `MYTHPMI1` on-disk format. 8 tests.
  - **TASK-181** — Hash de-aging (`tools/feed-builder/src/aging.rs` + store.rs migration v6). `samples_aged` + `aging_events` tables; `feed-builder age [--dry-run]` subcommand; `confirm_sample` helper. 5 + 1 migration tests.
  - **TASK-182** — Multi-source hash provenance (store.rs migration v7 + `record_provenance` + hashlist.rs wiring + consolidate.rs copy). New `provenance_events` table; one row per (hash, source, observed_at). Engine-side UI surfacing is a follow-up when the engine reads consolidated artifact directly. 1 test.
  - **TASK-183** — Per-OS NSRL slice load (`detect/goodware_allowlist.rs` + `ui-bridge/commands.rs`). New `resolve_nsrl_slice_paths` helper detects host OS via `std::env::consts::OS` and returns host + `_other` slices; ui-bridge loader iterates the result. Halves install footprint on single-OS machines. 3 tests.
  - **TASK-190** — Ephemeral allowlist / Trust-this-once (migration 0006 + `detect/ephemeral_allowlist.rs`). 7d / 30d / 365d duration presets, optional scope_path, mandatory reason, auto-prune at scan-start. Detector at priority 12 (above goodware, below blacklist). 5 tests.
  - **TASK-199** — BLAKE3 + SHA-256 dual-key gate (`detect/dual_key_gate.rs`). `MatchStrength` enum (GoldMultihash | GoldSingle | Silver | Partial) + `combine()` merger. Silver-tier hits get a one-notch severity downgrade (Critical→High). 9 tests.

  **PR-B — Allowlist intelligence + UI tools + feed integrity** (commit `cbd937d`):
  - **TASK-184** — Vendor-by-package-manager (`detect/package_manager_allowlist.rs`). Cross-platform detector that asks dpkg/pacman/rpm/brew/winget. 24h per-path cache. 4 tests.
  - **TASK-185** — macOS App Store provenance (`detect/platform_store_allowlist.rs::MacosAppStoreDetector`). `/Applications/.app/Contents/_MASReceipt/receipt` path check.
  - **TASK-186** — Windows Microsoft Store provenance. `%ProgramFiles%\WindowsApps\` + `AppxManifest.xml` + `AppxSignature.p7x` check.
  - **TASK-187** — Snap / Flatpak / AppImage. Path-shape detector for the three Linux store formats.
  - **TASK-188** — Cargo / PyPI / npm publisher-key allowlist (`detect/dev_publisher_allowlist.rs`). `classify_dev_path` + TOML-loaded `(ecosystem, package)` → `(publisher_id, key_fingerprint)`. 5 tests.
  - **TASK-189** — SBOM CycloneDX allowlist (`detect/sbom_allowlist.rs`). Parses CycloneDX 1.4 components filtered to SHA-256. 3 tests.
  - **TASK-191** — Confidence-graded findings (`FindingRow.tsx`). MatchStrength → P0/P1/P2 pill with tooltip.
  - **TASK-192** — Feed-freshness widget (`components/FeedFreshnessBadge.tsx`). Age-coloured per bucket.
  - **TASK-195** — User-supplied IOC bundles (migration 0007 + `detect/user_iocs.rs`). Auto-detects plain hash list / CSV with type+value / STIX 2.1 indicator / MISP Event.Attribute[] JSON. 6 tests.
  - **TASK-196** — Per-finding source-citation copy. `Cite` button on FindingRow → Markdown footnote to clipboard.
  - **TASK-197** — Reverse-lookup helper (`detect/hash_lookup_explain.rs::hash_verdict_tree`). Lifetime + 30d counts + N most-recent observations for a given hash.
  - **TASK-198** — Lateral hash search (`hash_lookup_explain.rs::lateral_hash_search`). Returns every prior scan that observed a hash.
  - **TASK-193** — Mirror failover (`updater/mirrors.rs::MirrorPool`). Per-feed URL pool with per-URL error counters + 30-day fallback history + healthy-rotation logic. 5 tests.
  - **TASK-194** — Chained ed25519 epoch sig (`updater/delta_sig.rs`). `Manifest` shape + `verify_chain` enforcing monotonicity + prev_epoch sha256 continuity + signature. 7 tests.

  **/review + /security-review fixes** (after PR-B, applied before push):
  - **CR-CRITICAL #1** — Cuckoo `fingerprint_mask` overflowed when `fingerprint_bits == 16` (panic in debug, accidental wrap in release). Now special-cased.
  - **CR-CRITICAL #2** — Cuckoo `from_mmap_mut` accepted `bucket_count = 0` and any `fingerprint_bits` from disk → out-of-bounds panic on `contains()`. Now rejects with `LengthMismatch` unless `bucket_count.is_power_of_two() && bucket_count != 0` and `fingerprint_bits in 1..=16` and `entries_per_bucket != 0`.
  - **CR-HIGH #1** — Cuckoo kick-chain start picked deterministically from `i1 % 2`. Now uses `rand::thread_rng()` to break the eviction-cycle deadlock.
  - **SR-HIGH #1** — Hash-lookup `LIKE '%hash%'` accepted `%` / `_` / empty input → could dump all findings. Now validates `hash_hex` is 8-64 ASCII hex chars before formatting the needle. New regression test covers wildcard rejection.
  - **SR-HIGH #2** — Cuckoo loader used `MmapMut` (writable) — required write permission on the artifact. Now `Mmap::map` (read-only); the aging-job delete path re-builds in RAM and writes a fresh artifact instead.
  - **SR-MEDIUM #4** — Platform-store + dev-publisher path-shape detectors trusted `path.starts_with("/Applications/")` etc. without canonicalising → a symlink in a user-writable area could spoof the store-install root. Now `canonicalize()` first; symlink-redirected paths no longer match the store roots.

- **Phase 7B Wave 1 — Hash-only blacklist + NSRL whitelist + tier-aware export + first-scan UX** _(shipped 2026-05-23)_

  Why: Detection at scale doesn't require labeling every malware sample with a clean-room family name. Hash-only ingest from public hash lists (VirusShare / ThreatFox / etc.) covers the bulk of detection value at a fraction of the build cost; NSRL whitelist short-circuits 95%+ of scan work on benign OS / app binaries. The "Mythodikal-original family / commentary" effort moves from release-gating to optional polish.

  - **TASK-165** — Migration v5 in `tools/feed-builder/src/store.rs`: relaxed NOT NULL on sha1/sha512/blake3/crc32/family/commentary/rule_matches; switched `severity` from TEXT to INTEGER (0=low → 3=critical); added `coverage_tier TEXT NOT NULL DEFAULT 'gold' CHECK (... IN ('gold','silver'))`. Backfills every existing 864K row from the legacy TEXT severity. Idempotent + interrupt-safe (single transaction). Schema-version tracked via new `schema_migrations` table. Local-only (feed-builder is gitignored maintainer tooling).
  - **TASK-166** — `tools/feed-builder/src/severity.rs`: pure-function severity rule pipeline from MalwareBazaar tag set + vtpercent + optional YARA family. Critical-tag override list (ransomware / wiper / rootkit / bootkit / ransom); high-priority-tag-with-vt-≥50 promotion (trojan / backdoor / rat / stealer / banker / dropper); vt-threshold ladder; family override only promotes. `Reject` verdict for sub-30% VT + no high-priority tag drops the row before insert. LazyLock-cached tag sets (allocation-free hot path).
  - **TASK-167** — `feed-builder hashlist` subcommand reading flat hash-list files. Per-hash MalwareBazaar `query/get_info` (metadata-only — burns no byte-fetch quota); derives severity via TASK-166; inserts as **silver-tier** rows where md5 + sha256 are required and blake3 / crc32 stay NULL. Polite 1.1 s rate limit by default. Clean-room posture preserved: MB tag prose drives severity-derivation but is never persisted (only the INTEGER severity).
  - **TASK-168** — Tier-aware export in `tools/feed-builder/src/export.rs`. New sorted-`.bin` artifacts: `silver_md5.bin`, `silver_sha256.bin` (silver-only), `myth_md5.bin`, `myth_sha256.bin` (gold + silver union). Existing `blake3_blacklist.bin` + `crc32_blacklist.bin` stay gold-only (silver rows lack the byte-derived hashes). `blake3_meta.jsonl` extended with `severity` text mirror + `severity_int` + `coverage_tier`. Export gate extended to `(family != 'unknown' OR vtpercent >= ?1 OR severity >= 2)`.
  - **TASK-172** — `feed-builder nsrl` subcommand. Folds one sha256 across multiple packages into a single `nsrl_samples` row with `source_os` = comma-separated set of {windows, macos, linux, other}. Drops NSRL's `file_name` / `manufacturer` columns; keeps just the hashes + size + OS bucket + product list. Reshapes the 169 GB NIST RDSv3 modern-minimal source into a ~3-5 GB Mythodikal-shape DB. Idempotent re-ingest via `INSERT OR IGNORE`.
  - **TASK-174** — `feed-builder nsrl-export` subcommand. Emits `nsrl_md5.bin` / `nsrl_sha1.bin` / `nsrl_sha256.bin` as sorted-hash files for the engine's mmap binary-search loader. Optional `--os-filter` for per-OS slicing (Wave 2 TASK-183 underlying transport). End users download these via GitHub Release on first scan; they're not bundled into the installer.
  - **TASK-175** — `.github/workflows/whitelist-refresh.yml`: nightly cron checks NIST S3 for new NSRL RDSv3 modern-minimal releases; verifies the `.sha256` sidecar; sanity-checks against a > 2-quarter version-skip; runs `feed-builder nsrl` + per-OS exports; opens a draft PR bumping `.github/state/nsrl-current-version.txt`. Zip-slip mitigations + strict filename regex on the extracted DB.
  - **TASK-176** — `feed-builder consolidate` subcommand. Produces single-file shippable `myth-blacklist.sqlite` + `myth-whitelist.sqlite` artifacts from the maintainer-local feed-builder DB + nsrl.sqlite via ATTACH + indexed INSERT. Each output is VACUUMed and stamped with provenance + version in a `myth_meta` table. Defense: `safely_replace` guard refuses to clobber a target unless its `myth_meta.artifact` matches the expected artifact name (or the file doesn't exist) — prior version moves to `.bak`. Maps to the "no destructive action without per-incident ack" project posture.
  - **TASK-177** — datalake / urlhaus / backlog byte-fetch pipelines: YARA labeling pass becomes opt-in (`--rules` flag). Default path derives severity from MB CSV signature + vtpercent at insert time via TASK-166; rows land gold-tier with NULL family / commentary / rule_matches. Critical tags (ransomware / wiper / rootkit / bootkit / ransom) override the pre-extraction VT threshold so known-ransomware at low VT is not silently pre-filtered. `urlhaus` `--rules` argument flipped from required to optional. Backlog threads MB `signature` through `DownloadJob` + parallel worker pool for severity-at-insert.
  - **First-scan NSRL prompt UI** — `apps/mythodikal/frontend/src/pages/FirstRun.tsx` extended from 3 to 4 steps with a new Step 3 offering three NSRL download choices: per-OS slice (~1.7 GB, recommended default) / full union (~3.4 GB) / skip. Preference persists in `localStorage` via new `apps/mythodikal/frontend/src/stores/nsrlPreference.ts`. The actual download is wired through the existing Tauri Updater plugin separately on first-scan trigger.

  **Engine-side** (TASK-169 + TASK-173 effectively complete via existing detectors): the existing `HashBlacklistDetector` + `GoodwareAllowlistDetector` consume the new sorted-hash artifact filenames (`myth_sha256.bin`, `nsrl_sha256.bin`) with no code change — same `MYTHHASH` format, same SHA-256-keyed lookup. SHA-256 alone covers >99% of NSRL hits on modern files; MD5 + SHA-1 alternate-key lookups stay as a Wave 2 nice-to-have.

  **Review + security-review pass:**
  - Code-review CRITICAL #1: NSRL fold loop in `nsrl.rs` was comparing lowercased `cur_sha256` to unmodified next `sha256`, silently breaking the OS-set accumulation. Now lowercases at the top of the loop.
  - Code-review CRITICAL #2: dead chunking loop removed; comment clarified that the ingest is a single-transaction fold by design.
  - Code-review HIGH (severity hot-path): `critical_tags()` / `high_priority_tags()` no longer rebuilt per `derive` call — wrapped in `LazyLock<HashSet>` (single allocation per process).
  - Code-review HIGH (VT prefilter): datalake + urlhaus pre-extraction gates no longer drop critical-tagged samples regardless of vtpercent — `is_critical_tag()` shortcut keeps known-ransomware at low VT flowing into the severity rule.
  - Code-review HIGH (DB error swallow): `store.is_labeled(...).unwrap_or(true)` replaced with `matches!(..., Ok(false))` — a transient SQLite error no longer masks an unlabeled row as labeled.
  - Code-review HIGH (path encoding): ATTACH DATABASE in `consolidate.rs` now refuses non-UTF-8 paths instead of `to_string_lossy` mangling them.
  - Security-review HIGH (zip integrity): `whitelist-refresh.yml` now downloads + verifies NIST's `.sha256` sidecar before unpacking; fails the workflow if the sidecar is absent. Adds `unzip -t` integrity test and a strict filename regex on the extracted DB.
  - Security-review HIGH (zip-slip): `unzip -j` strips directory components; post-extract filename regex blocks any traversal or shell-metachar payload that survives.
  - Security-review HIGH (destructive write): `consolidate.rs` `safely_replace` checks the existing file's `myth_meta.artifact` before clobbering; backs up to `.bak` rather than `remove_file`.
  - Security-review HIGH (version skip): new "Guard against version skipping" workflow step refuses to auto-ingest > 2 quarters ahead of the shipped sentinel, defeating an S3-listing-poisoning attack that points at a future-dated key.
  - Security-review MEDIUM (LIKE substring): `nsrl-export --os-filter` now strict-whitelisted to {windows, macos, linux, other} and switched from `LIKE '%bucket%'` to comma-anchored `LIKE '%,bucket,%'` against the CSV column for exact token match.
  - Security-review MEDIUM (ANSI injection): `hashlist.rs::fetch_info` JSON-parse error context sanitizes the response snippet so adversarial MB responses can't smuggle ANSI escapes into the maintainer's log scrollback.
  - Security-review MEDIUM (Auth-Key log leak): `hashlist.rs` swapped `tracing::warn!(..., error = ?err)` → `error = %err` to avoid future reqwest Debug formats embedding header context.

  **Tests:** 37 feed-builder unit tests passing (added 4 during the review pass: `is_critical_tag_recognises_set`, `os_filter_strictly_whitelisted`, `consolidate_refuses_to_clobber_non_artifact`, `consolidate_refuses_to_clobber_non_sqlite`). `mythkernel` builds clean; frontend `tsc --noEmit` clean.

  **Local-only artifacts** (never committed): `MythAV-HashDB.sqlite`, `nsrl.sqlite`, the derived `myth_*.sqlite` shippable bundles, and all `nsrl_*.bin` / `myth_*.bin` / `silver_*.bin` slices. `.gitignore` extended to cover the hash-database / NSRL / slice-bin patterns so a stray `git add .` can't accidentally stage a multi-GB file.

## [0.6.0] — 2026-05-22

> First formally-tagged release. Consolidates Phase 4 wave-6 + Phase 5
> waves 1–4 + Phase 5 closeout + Phase 6 wave 1 work, none of which
> shipped a tag in its own phase per the maintainer's "phase-close-out
> deferred until macOS port lands" plan. Phase 6 wave 1 (TASK-059 / 060 /
> 061 / 062) closes out the macOS universal-binary release path with
> unsigned-but-Updater-verified bundles, hardened-runtime entitlements,
> first-run Gatekeeper docs, and the platform-aware Modal component.
> Per `docs/prd.md` § 1.5.3 / 1.5.4, this release remains unsigned on
> all three OSes — no Apple Developer Program, no Windows OV/EV cert.

### Added
- **Phase 6 wave 1 — macOS port: universal binary + unsigned bundle + first-run UX + platform-aware Modal (v0.6.0)** _(shipped 2026-05-15 → 2026-05-22)_
  - **TASK-059** — macOS universal binary in the release matrix. `.github/workflows/release.yml`'s prior per-arch macOS entries collapsed into a single `macos-universal` build hosted on `macos-14`: the rust-toolchain step installs both `aarch64-apple-darwin` and `x86_64-apple-darwin`, `tauri-action` is invoked with `--target universal-apple-darwin` so `cargo build` lipos the two Mach-O slices into one fat binary, and the resulting `.app` / `.dmg` runs on every supported Mac without per-arch downloads. `latest.json` merge step's `ALLOWED_PLATFORMS` allowlist dropped per-arch `darwin-aarch64` / `darwin-x86_64` / `macos-aarch64` / `macos-x86_64` keys; added `darwin-universal` + `macos-universal`. Tauri-Action's `updaterJsonPreferUniversal: true` resolves the only available macOS key. `ci.yml` continues to exercise `macos-14` + `macos-13` for typecheck/lint/test (kept as-is for arch-coverage).
  - **TASK-060** — macOS unsigned bundle + first-run UX documentation. `apps/mythodikal/src-tauri/tauri.conf.json` gains a `bundle.macOS` block with `signingIdentity: null`, `providerShortName: null`, `minimumSystemVersion: "11.0"`, and an `entitlements` pointer (see TASK-061). `docs/macos-first-run.md` documents the Gatekeeper right-click → Open workaround for both Ventura-and-earlier and Sonoma-and-later dialog variants, the `System Settings → Privacy & Security → Open Anyway` fallback, and the Tauri Updater ed25519 + optional Sigstore manifest integrity-verification channels users can run before bypassing Gatekeeper. **No paid notarization, no `notarytool`** per `docs/prd.md` § 1.5.3.
  - **TASK-061** — macOS .dmg (unsigned) + hardened-runtime entitlements. New `apps/mythodikal/src-tauri/entitlements.plist` ships the "secure-default" hardened-runtime keys all set to `<false/>` (no JIT, no unsigned-executable memory, no dyld env-var injection; library validation stays on, executable page protection stays on). yara-x is pure Rust so library validation costs nothing. These keys are advisory on an unsigned binary but document the security posture and become enforced if any downstream consumer notarizes a fork at their own cost. `bundle.macOS.dmg` adds windowSize 660×400 with `app`/`Applications` icons positioned at the typical drag-to-install layout. No `com.apple.security.cs.*` entitlement that requires the paid Apple Developer Program is requested.
  - **TASK-062** — macOS UI parity polish: platform-aware `Modal` Solid component. `apps/mythodikal/frontend/src/components/Modal.tsx` (new) selects a `.modal--sheet` variant (macOS — top-anchored slide-down with `cubic-bezier(0.16, 1, 0.3, 1)` HIG-style spring easing; top corners squared because the sheet is conceptually attached to the title bar) or `.modal--center` variant (Windows / Linux — centered fade+scale-in). Platform detection via `navigator.userAgentData.platform` (modern) with `navigator.platform` + `userAgent` fallback (works inside Tauri's WKWebView + WebView2 + WebKitGTK without pulling in `@tauri-apps/plugin-os` as a dep). `apps/mythodikal/frontend/src/styles/index.css` adds `.modal-backdrop`, `.modal`, `.modal__header/__title/__close/__body`, both variants, and the three keyframe animations. Backdrop click-to-dismiss + ARIA dialog semantics built in. SF Symbols intentionally NOT used — they're macOS-native and not directly renderable in HTML/CSS without licensed SVG copies; Unicode close glyph `✕` renders identically across all platforms and fits the cross-platform posture. Page integration of the `Modal` component (replacing inline modal markup in `pages/*`) is a Phase 6 wave 2 follow-up; the component is callable today.
  - **TASK-063 — REMOVED.** Apple ESF entitlement application is permanently out of scope per `docs/prd.md` § 1.5.4 / FR-031 — macOS real-time is NOTIFY-only. The paid Apple Developer Program is never required.
- **CRC32 fast-screen pre-pass for the hash-blacklist detector (pre-v0.5.0)** _(shipped 2026-05-13)_
  - New on-disk artifact format `MYTHCRC3` (versioned, sorted-u32 set; structural twin of the existing `MYTHHASH` BLAKE3 set). Mythkernel mmaps the file and binary-searches u32 CRC32 values in O(log N). Hardware-accelerated CRC32 (x86 / ARMv8) is ~2-4× faster per byte than BLAKE3; combined with a 1-in-4,300 collision rate on a 1M-hash gate, the engine can short-circuit BLAKE3 + SHA-256 + the entire detection pipeline on ~99.977% of scanned files. On a CPU-bound NVMe scanner this collapses per-file hashing wall time by 40-80%.
  - `crates/mythkernel/src/detect/crc32_set_file.rs` — `Crc32SetFile` loader. Same `Send + Sync` pattern as the already-vetted `HashSetFile`. 8 unit tests covering empty / single / many-value / bad-magic / truncated / length-mismatch / unsorted-detected / boundary lookups.
  - `crates/mythkernel/src/hasher.rs` — `Hasher::with_crc32_gate(Arc<Crc32SetFile>)` setter, `crc32_only_pass(path) -> (u32, u64)` streaming helper, `hash_file_with_crc32_gate(path) -> MaybeHashResult` returning `GatedMiss { crc32, size }` (no BLAKE3 / SHA-256 work) or `Hashed { crc32, result }`. 8 new unit tests cover all gate paths (empty file zero-crc / single-chunk / multi-chunk / abort-flag / no-gate / hit / miss / empty-gate-misses-everything).
  - `crates/mythkernel/src/engine.rs` — scan worker auto-loads the gate from `opts.crc32_gate_path` (gracefully falls back to "hash everything" on load failure), routes through `hash_file_with_crc32_gate`, and on `GatedMiss` emits a `<crc32-skip>` sentinel `File` event + bumps `files_hashed` so the dashboard ETA + throughput chart stay accurate.
    - Review fix: the `GatedMiss` arm does **not** re-bump `files_visited` / `bytes_visited` (those are incremented unconditionally at function entry); double-counting would have inflated dashboard totals by ~2× on CRC32-gated scans.
    - Review fix: `GatedMiss` now emits `ScanProgress::File` via the same `emit_file_event` helper the MS-signed fast-path uses, so the UI's authoritative `files_visited_total` snapshot advances on every visited file rather than freezing during a gated scan.
  - `crates/mythkernel/src/scan.rs` — `ScanOptions::crc32_gate_path: Option<PathBuf>` with `None` default. Backward compatible: every existing caller continues to hash every file. The `crc32_blacklist.bin` artifact is also intentionally absent from `ResumeToken` so resumed scans re-derive the gate path from `data_dir` on resume rather than getting stuck on a stale snapshot.
  - `crates/ui-bridge/src/commands.rs` — `start_scan` auto-detects `feeds_dir/crc32_blacklist.bin` and passes the path through to `ScanOptions::crc32_gate_path` on every scan request. Drop the bin into `%LOCALAPPDATA%\Mythodikal\feeds\` and the next scan picks it up; absent file → transparent fallback to legacy "hash everything" behavior.
  - Workspace dep: `crc32fast = "1"` added at the workspace level + pulled into `crates/mythkernel/Cargo.toml`.
  - The companion artifact-builder tool that produces the `MYTHCRC3` + `MYTHHASH` files is maintainer-only and lives outside the public repo (see `.gitignore`). The engine consumes the published bins generically — any tool that emits the documented sorted-set format works.
- **Phase 5 wave 3 — Concurrent enumerate/scan + file-mutation baseline + BYOVD blocklist (pre-v0.5.0)** _(shipped 2026-05-12)_
  - **TASK-137** — Producer/consumer engine restructure (FR-135). `crates/mythkernel/src/engine.rs` now spawns a dedicated `mythkernel/scan-producer` thread that streams `(PathBuf, u64)` into an unbounded `crossbeam_channel::unbounded` worklist while the hash + detect consumer drains concurrently from t=0. The walker tracks `files_running` / `bytes_running` in shared `AtomicU64`s the consumer reads on every `File` event; an `enum_complete` `AtomicBool` flips when enumeration finishes, swapping `files_total_running` for `files_total_locked` in the wire payload.
    - New `ScanProgress::EnumerationComplete { scan_id, files_total_locked, bytes_total_locked }` variant emitted exactly once per scan. Forwarded as `scan:enumeration_complete` Tauri event.
    - `ScanProgress::File` gains `files_total_running` + `files_total_locked` Option fields (`#[serde(default)]` for back-compat).
    - Frontend (`stores/scan.ts` + `pages/Scan.tsx`) renders `1,234 · 8,910 · counting…` during enumeration, locks to `1,234,567 / 1,234,580` at the `enumeration_complete` event.
    - Consumer uses `recv_timeout(100ms)` so a Pause click between two slow-to-arrive files doesn't block on a long `recv()`. The producer also checks the pause flag between files; both threads exit cleanly.
    - mythctl Text mode emits `· enumeration complete: N files, M bytes` to stderr; JSON mode emits the new event verbatim to stdout.
  - **TASK-138** — File-mutation baseline + detection (FR-131).
    - `migrations/0004_file_baseline.sql` introduces the `file_baseline` table (`(scan_id, path, blake3_hex, sha256_hex, size_bytes, signer_identity, signer_kind, nsrl_known, source, recorded_at_utc)`). Append-only; `FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE` so retention sweeps drop baselines alongside scans.
    - `detect/file_mutation.rs` — `FileBaseline` struct + per-scan enumeration of autostart + `$PATH` files. `record_and_check` INSERTs a new baseline row every call and emits a `MutationFinding` (severity `Medium`, rule id `mythodikal:file_mutation:<source>`) when the prior snapshot was signed-or-NSRL-known and the current BLAKE3 differs.
    - Per-platform autostart enumerators: `platform/linux/autostart.rs` (XDG `.desktop`, systemd units, shell rc files), `platform/mac/autostart.rs` (Launch{Agents,Daemons} plists, BackgroundItems.btm, shell rc files), `platform/win/autostart.rs` (per-user + all-users Startup folders, PowerShell `profile.ps1`).
    - Cross-platform `path_binaries()` shim walks `PATH` (Windows additionally filters by `PATHEXT`) and dedupes via `canonicalize`.
    - Engine integration: `engine.rs::run_file_mutation_hook` is called for every successfully-hashed file when `FileBaseline::is_enabled()` is true. Reuses the publisher signer the engine already extracted for exclusion matching (no extra shell-out).
  - **TASK-139** — BYOVD blocklist via loldrivers.io (FR-141 static portion).
    - `updater/loldrivers.rs` — `LolDriversUpdater` (Local / Url source) with `parse_drivers_json` that accepts both the canonical array shape and older `{ "drivers": [...] }` wrapper. Extracts SHA-256 from each driver's `KnownVulnerableSamples`; writes `<feeds_dir>/byovd_sha256.bin` via the same sorted-set format the abuse.ch and NSRL feeds use.
    - `detect/byovd.rs` — `ByovdDetector` (priority 110, severity `Critical`, rule source `"loldrivers"`, rule id prefix `loldrivers:byovd:<8-hex>`). Fails clean when SHA-256 isn't computed (engine misconfigured); a hit emits a Critical verdict with the SHA-256 in `evidence`.
    - License posture: loldrivers.io data is MIT-licensed — commercial-clean per `docs/prd.md` § 1.5.1. Driver-load-time enforcement via WDAC is **deferred** to TASK-154 (Phase 12).
  - **Wave 3 review fixes (`/review` + `/security-review` Phase 5 wave 3):**
    - Sec-review H1: `LolDriversUpdater::fetch` now enforces a 32 MiB cap on the response body via `Content-Length` pre-check + drained `Response::chunk()` accumulator; new `LolDriversError::BodyTooLarge { limit }` variant. A malicious mirror or compromised CDN can no longer OOM the engine with a multi-GB JSON.
    - Sec-review H2: `crossbeam_channel::unbounded` in the producer/consumer engine swapped for `crossbeam_channel::bounded(32_768)`; producer back-pressures naturally when the hash consumer falls behind. Caps resident-set growth on multi-million-file scans at ~2 MB of queued tuples instead of the prior ~300 MB worst case.
    - Sec-review M1 / code-review M5: defensive `signer.clone().truncated()` in `FileBaseline::record_and_check` before the `INSERT params!` block — the 512-byte cap holds even when a future direct caller bypasses the publisher cache.
    - Sec-review M4 / code-review M3: `FileBaseline::record_and_check` wraps the diff-read + INSERT in `conn.transaction_with_behavior(TransactionBehavior::Immediate)` so two concurrent scans against the same path can't observe the same prior and produce duplicate findings.
    - Sec-review M5: corrected the loldrivers.io license claim — upstream is Apache-2.0, not MIT. Doc updates in `updater/loldrivers.rs` + `detect/byovd.rs` headers. Both licenses are commercial-clean per § 1.5.1; the rule about redistributing only hashes (no rule text) is unchanged.
    - Sec-review M6: scan-producer thread spawn no longer `.expect`s — a thread-spawn failure (EAGAIN under RLIMIT_NPROC) now flips the scans row to `failed` and returns `EngineError::Config` rather than panicking the tokio runtime.
    - Code-review H2: `scan_start` now discards the caller-supplied `target_path` when `all_volumes = true` and substitutes a fixed `<all-volumes>` sentinel into the engine's `ScanTarget::Path`. A compromised renderer can't smuggle `/etc` into the History row via the `all_volumes` shortcut.
    - Code-review H3: producer adds a RAII `ProducerCompletionGuard` so `EnumerationComplete` fires exactly once on every exit path — clean completion, pause-mid-walk, consumer-dropped, panic. The UI's "swap to X/Y at lock" presentation contract now holds end-to-end.
    - Code-review M7: `run_file_mutation_hook` derives `SignerKind` from the host OS (`Authenticode` on Windows / `Codesign` on macOS / `Gpg` on Linux / `Unsigned` elsewhere) instead of hard-coding `Authenticode`. The `signer_kind` column in the `file_baseline` row now reports the right platform on every host.
  - **Validation (Windows host):** `cargo fmt --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo test --workspace` (233 mythkernel + 2 e2e + 6 tray + 5 policy passing; 3 ignored for live MFT/USN/multi-volume), `cargo deny check`, `pnpm typecheck`, `pnpm build` — all green.
- **Phase 5 wave 2 — Windows installer + scan-target UX + benchmarks + v0.5.0 release wiring (pre-v0.5.0)** _(shipped 2026-05-12)_
  - **TASK-054** — `apps/mythodikal/src-tauri/tauri.conf.json` Windows bundle config:
    - `bundle.windows.wix.language = ["en-US"]` and `bundle.windows.nsis.installMode = "perMachine"` (with `languages = ["English"]`, `displayLanguageSelector = false`).
    - Per-machine install lands at `%ProgramFiles%\Mythodikal Anti-Virus\` with an all-users Start menu shortcut.
    - **Unsigned** per `docs/prd.md` § 1.5.3 — no `certificateThumbprint`, no `digestAlgorithm`, no `timestampUrl`, no SignTool wiring. SmartScreen + Mark-of-the-Web workarounds documented in `README.md`'s new "First-run on Windows (unsigned bundle)" section. The updater `.sig` files attached to the GitHub Release continue to be ed25519-verified end-to-end by the in-app Tauri Updater plugin (FR-152); only the OS-level Authenticode signature is absent.
  - **TASK-056** — Windows scan-target chooser UX:
    - `apps/mythodikal/src-tauri/src/lib.rs` + `crates/ui-bridge/src/commands.rs`: new `enumerate_volumes` Tauri command. Windows returns `Vec<VolumeView>` (mount_path, all_mount_paths, fs_name, serial, is_ntfs, is_removable); non-Windows returns `[]` so the UI degrades to its path-only chooser.
    - `apps/mythodikal/frontend/src/pages/Scan.tsx`: per-volume buttons under the target input — drive icon (`💽` fixed / `🔌` removable), mount path, and a filesystem-type pill (`NTFS` highlighted; FAT32/exFAT/ReFS muted). New "Scan all volumes (per-volume parallel fan-out — TASK-053)" checkbox that disables the path input and triggers TASK-053's multi-volume fan-out via `ScanOptions.all_volumes = true`.
    - Engine integration: `crates/mythkernel/src/engine.rs` now drives every scan through `MultiVolumeWalker` (was `PosixWalker`). Single-root scans pass through to `NtfsWalker` (the platform-fast walker — NTFS MFT on Windows, raw `getdents64` on Linux, FSEvents-driven `read_dir` on macOS — with `PosixWalker` fallback when the per-OS fast path can't open the volume). `all_volumes(true)` fans out across every detected Windows volume.
    - `ScanRequest.all_volumes` field flows from FE → `scan_start` → `ScanOptions.all_volumes` → engine. `ResumeToken` schema gains a `#[serde(default)]` `all_volumes` field so paused multi-volume scans resume across the same volume set (back-compat with v0.4.x tokens preserved — defaults to `false`).
  - **TASK-057** — Benchmarks:
    - `scripts/bench-1m-files.ps1` — Windows mirror of `scripts/bench-1m-files.sh`. Generates 1000×1000 tree, builds `mythctl --release`, runs cold + warm scans, asserts NFR-001 (v0.5 lenient ≤ 6 min) and NFR-002 (interim ≤ 30 s).
    - `crates/mythkernel/benches/win_mft.rs` — criterion bench comparing `NtfsWalker` vs `PosixWalker` on the same trees at 1K / 10K / 50K file fan-outs. Cross-platform: on non-Windows hosts the bench still exercises `NtfsWalker`'s OS-native bootstrap walker (getdents64 / FSEvents-driven read_dir) so the comparison stays meaningful.
    - `crates/mythkernel/Cargo.toml`: `[[bench]] name = "win_mft"` registered with criterion `harness = false`.
  - **TASK-058** — Release wiring:
    - `docs/launch-checklists/v0.5.md` (gitignored): pre-flight / cryptographic / benchmarks / smoke-test / tag procedure mirroring the v0.4 checklist, retuned for Windows-first focus.
    - README's "First-run on Windows (unsigned bundle)" section explains the SmartScreen workaround, the Mark-of-the-Web Unblock toggle, the per-machine install path, and clarifies that the `.sig` files on the Release are ed25519 updater signatures (not Authenticode).
- **Phase 5 wave 1 — Cross-platform fast walker + Windows volume detection + per-volume parallelism (pre-v0.5.0)** _(shipped 2026-05-12)_
  - **Vendored from sister project `Sourcerer` (`crates/sourcerer-journal-{win,mac,lin}/`):** the entire three-OS journal subscriber tree now lives at `crates/mythkernel/src/platform/{win,mac,linux}/journal/`.
    - **Windows**: hand-wrapped `FSCTL_ENUM_USN_DATA` + `FSCTL_READ_USN_JOURNAL` + `FSCTL_QUERY_USN_JOURNAL` via the official `windows = "0.62"` crate. JSON cursor in `<LOCALAPPDATA>\Mythodikal\journal\<volume_serial>.json` with atomic tmp+rename writes. Rotation detection on every open: journal_id mismatch or first_usn > cursor triggers a full MFT walk fallback.
    - **macOS**: FSEvents subscriber (`FSEventStreamCreate` / `Schedule` / `Start` + `CFRunLoopRunInMode`) via `core-foundation = "0.10"` + `core-foundation-sys = "0.8"` + `fsevent-sys = "4"` + `libc`. Per-batch rename pairing with inode-pre-stat dedup. `seen_paths` HashSet demotes sticky `ItemCreated` re-events to `Modify`. StreamCursor JSON in `~/Library/Application Support/Mythodikal/journal/<root_hash>.json`. Bootstrap walk uses recursive `read_dir` (Sourcerer's Phase-2 trade-off; `getattrlistbulk(2)` is a Phase-13 perf-pass follow-up).
    - **Linux**: inotify (default, no privileges) + fanotify (`FAN_REPORT_DFID_NAME`, requires CAP_SYS_ADMIN) subscribers via `libc = "0.2"`. Backend chosen at open() time from `/proc/self/status :: CapEff:` parse. Bootstrap walk uses raw `getdents64(2)` with `(st_dev, st_ino)` cycle dedup — 5-15s on a 1M-file ext4 tree, far faster than `std::fs::read_dir`. EPERM/EINVAL/ENOSYS on `fanotify_init` falls through to the inotify path so the subscriber stays useful on stripped-down kernels (containers, Linux < 5.17). WatchCursor JSON in `$XDG_DATA_HOME/mythodikal/journal/`.
  - **TASK-050** — `crates/mythkernel/src/walker/ntfs.rs` is now a "fast platform-native walker" (the historical `NtfsWalker` type name preserved). Picks NTFS MFT on Windows, FSEvents-driven `read_dir` on macOS, raw `getdents64` on Linux, with `PosixWalker` as the safety net when the per-OS fast walker can't open the volume (admin denied, non-NTFS, dropped permissions). Adapter uses `futures::executor::block_on` to bridge the vendored `mpsc::Stream<JournalEvent>` into the existing `crossbeam_channel<WalkEvent>` shape so the rest of the engine — ETA, throttle, hash, detect, record, history — sees the same `WalkEvent::File` events regardless of platform.
  - **TASK-051** — `crates/mythkernel/src/walker/incremental.rs` adds `IncrementalWalker`. New `drain_until(end_usn)` helper on the Windows subscriber returns a bounded `Stream<JournalEvent>` that stops at the journal snapshot point (vs. `subscribe()`'s long-running stream). Translates `JournalEvent::{Create, Modify, Rename}` → `WalkEvent::File`, drops `Delete` / `RenameOld` / `AttrChange`. Rotation gate refuses with `None` and the walker falls back to `NtfsWalker` for a full MFT walk so the engine still gets a complete file list. **No SQL migration** — vendored cursor stays JSON for full parity with Sourcerer's behavior. On non-Windows: delegates to `PosixWalker` (full real-time wiring lands with Phase 8 / Phase 9 daemons; the inotify/FSEvents subscribe streams already exist via the vendored code).
  - **TASK-052** — `crates/mythkernel/src/platform/win/volumes.rs` adds `enumerate_volumes() -> io::Result<Vec<VolumeInfo>>` via `FindFirstVolumeW` + `FindNextVolumeW` + `GetVolumePathNamesForVolumeNameW` (grow-and-retry on ERROR_MORE_DATA) + `GetVolumeInformationW` + `GetDriveTypeW`. `VolumeInfo` carries `mount_path`, `all_mount_paths`, `fs_name`, `serial`, `is_ntfs`, `is_removable`. Volumes without a mounted path (system-reserved, detached) are skipped. Closes the `FindVolumeClose` handle on every exit path including ERROR_NO_MORE_FILES termination.
  - **TASK-053** — `crates/mythkernel/src/walker/multi_volume.rs` adds `MultiVolumeWalker` implementing `FileWalker`. Single-root call passes through to `NtfsWalker` directly (no aggregator overhead for the common case); multi-root call spawns one walker thread per volume, each draining into a shared `crossbeam_channel<WalkEvent>`. Aggregator thread joins all per-volume workers and closes the sender so `rx` reports completion cleanly. Per-volume parallelism is enumeration-only — `AdaptiveThrottle` (TASK-039) still governs total hash-worker count. Builder: `.with_volumes(iter)` (explicit list) or `.all_volumes(true)` (Windows-host discovery via TASK-052). Engine integration is TASK-056 + TASK-058 territory; the walker itself is callable today.
  - **Workspace deps added:**
    - `futures = "0.3"` (workspace-level): drives the vendored mpsc Stream API the Sourcerer subscribers emit on.
    - `windows = "0.62"` (Windows-only target dep): direct FSCTL bindings.
    - `core-foundation` + `core-foundation-sys` + `fsevent-sys` + `libc` (macOS-only target dep).
    - `libc` (Linux-only target dep).
    - All MIT/Apache-2.0 — license-clean per `deny.toml` allow-list.
  - **Validation (Windows host):** `cargo fmt --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test -p mythkernel` (215 passed; 0 failed; 3 ignored — live-MFT/USN-incremental/multi-volume tests against real `C:\` are admin-only and gated behind `--ignored`) + `cargo deny check` + `pnpm typecheck` + `pnpm build` all green. macOS + Linux paths cfg-gated; cross-OS verification via the Phase 5 wave 2 CI matrix.
- **Phase 4 wave 6 — System tray + autostart wired live (pre-v0.4.0)** _(shipped 2026-05-12)_
  - TASK-157 (live UI wiring): Settings → General "Start with OS" toggle is now real — `onChange` calls `autostart_set`. Helper text shows the OS mechanism (`~/.config/autostart/mythodikal.desktop` on Linux, `SMAppService LoginItem` on macOS, `HKCU\...\Run` value with `--start-minimized` on Windows). Toggle reads OS state on every render via `autostart_get` (no local truth).
  - TASK-158: `apps/mythodikal/src-tauri/src/tray.rs` — `TrayManager` with the FR-162.5 normative menu (Show / Hide, Shields submenu with timed-pause, Run quick scan, Check for app updates, Check for virus database updates, Quit). State machine priority `shields_off` > `update_available` > `scanning` > `idle`; tray icons baked in via `include_bytes!`. macOS uses 22×22 monochrome template (`icon_as_template = cfg!(target_os = "macos")`); Linux + Windows use 32×32 color variants.
  - **Wave 6 review fixes (`/review` + `/security-review` Phase 4 wave 6):**
    - Sec-review H1 + code-review CR-I6: new `tray_quick_scan_default_path` Tauri command resolves the *current user's* home dir server-side via the `dirs` crate. Frontend's tray quick-scan no longer hard-codes `C:/Users` or `/home`, eliminating the cross-user metadata leak path.
    - Sec-review M1: `app_quit` takes `force: Option<bool>`. Defaults to refusing the exit when `active_pause_flags` is non-empty (in-flight scan), so a renderer XSS can't kill the app mid-scan. Renderer surfaces the mid-scan modal and passes `force = true` after user confirmation.
    - Sec-review M2: dropped `core:tray:default` from `capabilities/main.json`. The tray icon is constructed entirely in the Rust `setup()` hook; the renderer only calls typed `tray_set_*` shell commands.
    - Sec-review M3: `CloseRequested` handler switched from `s.config.lock().ok()` to `s.config.try_lock().ok()` so a slow `settings_update` mid-flight no longer freezes the window-event thread.
    - Sec-review L2: tray store's `catch (err)` blocks now log a generic message; raw error detail (which can include canonical paths) stays in Rust tracing.
    - Code-review CR-B1 + CR-B2: new three-phase publisher cache API (`cache_lookup` → `extract_io_unlocked` → `cache_store`) in `crates/mythkernel/src/detect/publisher.rs`. The DB lock is held only for the cache hit/miss and the cache write — never across the slow shell-out to PowerShell / `codesign` / `dpkg`. Engine + `publisher_signer_for_path` Tauri command refactored. `scan_status` polling stays responsive during a publisher-enabled scan.
    - Code-review CR-I3: tray menu's quit handler now shows the main window + emits `tray:quit_requested` (no synchronous `app.exit(0)`). The renderer brokers the mid-scan confirmation via `app_quit`.
- **Phase 4 waves 3–5 — Release infra + updater channels + scan QoL + publisher whitelist (pre-v0.4.0)** _(shipped 2026-05-12)_
  - TASK-044 + TASK-048: Tauri Updater plugin wired + `.github/workflows/release.yml` ships the `v*`-tag-driven build matrix. Every third-party action is pinned to a commit SHA (sec-review H1); per-job `contents: write` instead of workflow-level (sec-review L3); inline Python merge step has a hard platform-key allowlist and fails loud on zero `latest*.json` artifacts (code-review I4 + sec-review L4). `apps/mythodikal/src-tauri/tauri.conf.json` carries the real ed25519 public key generated by `scripts/gen-signing-key/` (out-of-workspace crate; private half lives only in `TAURI_SIGNING_PRIVATE_KEY` + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` GH secrets; `private/` is gitignored).
  - TASK-047: Bundle targets set to `[deb, rpm, appimage, msi, nsis, dmg, app]` + `createUpdaterArtifacts: true`. Window starts hidden so `--start-minimized` (TASK-157) doesn't flash; the Tauri shell's `setup()` hook shows it unless that argv is present (sec-review L6).
  - TASK-049: `docs/launch-checklists/v0.4.md` is the v0.4.0 tag playbook (key-gen, GH-secret setup, benchmark targets, smoke-test grid). Gitignored — internal to the maintainer.
  - TASK-129: `crates/mythkernel/src/updater/channels.rs` introduces the engine vs database channel split per FR-151. `ChannelKind`, `ChannelState`, `LastCheckOutcome`. Per-channel state persists atomically to `<data_dir>/updater/{engine,database}_state.json`.
  - TASK-130: `crates/mythkernel/src/updater/engine.rs` — `EngineChannel` with HTTPS-only `check_for_updates()`, semver pre-release-aware `compare_versions()` (alpha < beta < rc < final; garbage strings rejected as zero — sec-review M6), and `verify_signature()` backed by the `minisign-verify` crate so key-id binding + magic-byte dispatch + legacy/pre-hashed mode all behave correctly (sec-review C1 + C2). Tauri-shell command `engine_install_update` drives `tauri-plugin-updater`'s `download_and_install` and emits `engine_update:progress` events with phases `download | verify | install | restart_pending`.
  - TASK-131: `crates/mythkernel/src/updater/database.rs` — `DatabaseChannel`, `DatabaseFeedRunner` trait, `AbuseChFeedRunner` / `NsrlFeedRunner` adapters. Emits `db_update:progress` events with phases `download | decompress | rebuild_index | swap`. Outcome semantics (code-review R-B3): any feed failed → `Failed`, any feed swapped bytes → `Installed`, else `UpToDate` (so a 304 short-circuit doesn't masquerade as an install). Per-feed metadata persists `last_check_at_utc`, `last_install_at_utc`, `entry_count`, `last_modified`, `etag` for future `If-Modified-Since` short-circuits.
  - TASK-132: `definition_count()` extended with `abusech_last_updated_utc` / `nsrl_last_updated_utc` mtime fields. About page now lists per-source breakdown with last-updated timestamps + a `Check for app updates` button that drives the engine channel.
  - TASK-133: `apps/mythodikal/frontend/src/pages/Settings.tsx` Updates sub-tab — dual-pane Engine + Virus database. Each pane shows channel state (last check, last install, outcome, last error), an Auto-update toggle, a Check now button, and a phase-aware progress strip. Per-feed status table under the database pane. "No rate limit" copy implied by the FR-156 free-pull architecture.
  - TASK-134: `ScanProgress::PartialHash` event variant + `ScanOptions::emit_partial_hash` + `hash_file_with_partial_events` helper. Scan dashboard gets an "Operator mode (live hash preview)" toggle that persists in localStorage; events throttled at ≤ 10 Hz. `ResumeToken` schema bumped to 2 (with `#[serde(default)]` back-compat) so a paused operator-mode scan resumes with the same event cadence (code-review R-B2).
  - TASK-135: `exclusions` table already supports `scope` + `expires_at_utc`; the UI gains a "24 h" quick-action button next to the expiry field and a tooltip-explained scope dropdown. Engine wiring already done in TASK-042.
  - TASK-136: Publisher whitelist (FR-146). New `crates/mythkernel/src/detect/publisher.rs` with cache-backed signer extraction + periodic prune (90 d age / 250 k row defaults — sec-review M5). Platform extractors at `crates/mythkernel/src/platform/{linux,mac,win}/codesign.rs` (PATH-pinned absolute binaries to resist shadowing — sec-review M4; Linux `dpkg-query` multi-arch parser — sec-review M1; RPM `%{SIGGPG}` instead of `%{SIGPGP}` to avoid stuffing the full PGP blob into the cache — sec-review M2/M3; `SignerIdentity::truncated()` caps `signer_identity` at 512 UTF-8-boundary-safe bytes). New `ExclusionKind::Publisher` variant + `MatchCtx.publisher` field. Engine extracts the signer per-file only when at least one active publisher exclusion exists (zero overhead otherwise). Tauri commands `publisher_signer_for_path` (Exclusions page's "Probe" workflow) + `publisher_prune_cache` (manual purge). Migration `0003_exclusions_publisher_and_baseline.sql` adds the `publisher_cache` table.
  - TASK-157: `tauri-plugin-autostart` registered. Tauri-shell commands `autostart_get` / `autostart_set` mirror OS state every render. Settings → General toggle flips between live and disabled-during-flip. Mechanism string surfaced in the toggle's helper text (`~/.config/autostart/...` on Linux, `SMAppService LoginItem` on macOS, `HKCU\...\Run` on Windows).
  - **Plugin capabilities** at `apps/mythodikal/src-tauri/capabilities/main.json` were extended with scoped grants (`updater:allow-check`, `updater:allow-download`, `updater:allow-install`, `updater:allow-download-and-install`, `autostart:allow-{enable,disable,is-enabled}`, `process:allow-{restart,exit}`) — no `*:default` over-grant per sec-review H2.
  - **CSP tightening (sec-review H3):** removed `https://github.com`, `https://api.github.com`, `https://objects.githubusercontent.com` from `connect-src`. All updater network goes through the Tauri Updater plugin from Rust; the renderer never needs direct GitHub access.
  - **Engine plumbing:** `ScanProgress` gains `PartialHash { scan_id, path, blake3_partial, bytes_done }`; `ScanOptions` gains `emit_partial_hash`. `ResumeToken::CURRENT_SCHEMA` bumped to 2. `MatchCtx` gains a `publisher: Option<&str>` field that the engine populates only when `has_publisher_excl` is true at scan start.
  - **AppState:** gains `updater_engine: Arc<EngineChannel>` and `updater_db: Arc<DatabaseChannel>`. The database channel is built at startup with whichever feeds the user has configured via `MYTHODIKAL_ABUSECH_AUTH_KEY` / `MYTHODIKAL_NSRL_LOCAL` env vars; runners that are missing simply aren't registered and Settings → Updates surfaces an empty per-feed table for that case.
  - **Code-review + security-review fixes (`/review` + `/security-review` Phase 4 waves 1+2 + waves 3-5):** verify_signature switched from hand-rolled byte slicing to `minisign-verify` (C1 + C2); every GH Action pinned to SHA (H1); plugin permissions scoped, not `*:default` (H2); CSP no longer allows GitHub origins (H3); `dpkg-query` multi-arch parse fix (M1); `SignerIdentity::truncated()` UTF-8-boundary-safe 512-byte cap (M2/M3); PATH-pinned signer binaries on Linux/macOS (M4); `publisher::prune_cache` with 90-day / 250 k-row defaults (M5); `compare_versions` orders pre-release suffixes + rejects garbage as zero (I5/M6); `gen-signing-key` chmods secret to 0600 on Unix + surfaces existing pubkey prefix on collision (L1/L2); release.yml per-job perms + platform allowlist + fail-loud-on-zero-artifacts (L3/L4); `window.visible = false` + setup-hook shows window unless `--start-minimized` (L6); `scan_start` now pipes `emit_partial_hash` through (R-B1); ResumeToken preserves the flag (R-B2); DatabaseChannel outcome semantics fixed (R-B3); engine wires publisher extraction only when needed.
- **Phase 4 wave 2 — Settings + pause/resume + auto-updater (pre-v0.4.0)** _(shipped 2026-05-12)_
  - TASK-041: Settings sub-tabs full impl. `settings_get` returns a live snapshot of the loaded TOML config; `settings_update` merges a partial patch into the in-memory config and persists atomically via `config::save`. Editable today: General → close_action; Scanning → archives_enabled / follow_symlinks / skip_hidden; Privacy → telemetry_enabled. `start_with_os` / `show_tray_icon` remain read-only stubs awaiting TASK-157 / TASK-158 (OS-state owned by Tauri autostart + tray plugins). `config.scanning` gains `archives_enabled` (default ON per FR-018) + `skip_hidden`. New `Toggle` + `Radio` components in `pages/Settings.tsx` keep the UI light.
  - TASK-040: Pause / resume across restart. `ScanHandle::pause_flag` is an `Arc<AtomicBool>` the worker observes between files; on flip the worker writes a `ResumeToken` JSON to `scans.resume_token`, flips the row to `paused`, emits `ScanProgress::Paused`, and exits cleanly. `engine.resume(scan_id)` reads the token, re-walks the original target paths, skips files in the token's `processed_paths` set (capped at 100K — over-cap files re-hash but findings dedupe at the DB layer), and continues from the persisted counters. Tauri commands `scan_pause` / `scan_resume` register / look up pause flags via a new `active_pause_flags` registry on `AppState`. Scan dashboard gains Pause + Resume buttons. CLI + mythctl handle the new `Paused` variant in their progress-event match arms.
  - TASK-043: Feed auto-updater. New `mythkernel::updater::scheduler` module with `ScheduledFeed` trait + `AbuseChScheduledFeed` adapter + `spawn(feeds, feeds_dir, interval) -> SchedulerHandle`. Default 24 h interval with 1 h retry on failure; persists a `last_run.json` summary next to the feed binaries. Tauri shell spawns the scheduler at startup from the user's TOML `[updater] auto_update_enabled / interval_hours / abusech_auth_key` section. New `updater_status` Tauri command surfaces the last-run summary in Settings → About. Documents the future ed25519 signature hook (TASK-129/130/131) without shipping it yet — rustls TLS pinning covers Phase 4 wave 2. 4 unit tests (status file, failure outcome, kick triggers immediate run, missing file).
  - Engine plumbing: `ScanProgress` gains a `Paused { scan_id, files_visited, files_hashed, bytes_visited, findings_count }` variant; `ScanOptions` derives `Clone` so the worker can stash it into a resume token; `history` gains `set_resume_token` / `read_resume_token`.
  - `AppState` gains `config: Arc<Mutex<Config>>`, `config_path: PathBuf`, `active_pause_flags: Arc<Mutex<HashMap<i64, Arc<AtomicBool>>>>`. Tauri shell holds a `SchedulerSlot` so the scheduler handle survives the app lifetime.
- **Phase 4 wave 1 — Linux MVP & Magic Moment groundwork (pre-v0.4.0)** _(shipped 2026-05-11)_
  - TASK-038: Calibrated ETA estimator (`mythkernel::eta`) — EMA-smoothed bytes-per-second velocity with a 3 % baseline-monotone-non-increasing clamp per FR-085. `EtaEstimator::observe(&Progress) → Option<f64>` returns seconds; below baseline the estimator returns `None` so the UI shows "calibrating…" rather than a meaningless number. 8 unit tests.
  - TASK-039: Adaptive CPU/IO throttle (`mythkernel::sysload` + `mythkernel::throttle`) — `SysLoadSampler` wraps `sysinfo` with a 500 ms cache, refreshes only our own process (not every PID on the box), and takes a warm-up sample in `new()` so the first `observe()` is never the misleading 0 % first-refresh figure. `AdaptiveThrottle::policy(max_workers, load)` is a pure function: ≥ 70 % external CPU collapses to 1 worker, < 30 % runs at `max_workers`, linear ramp between. 12 unit tests.
  - TASK-042: Exclusions CRUD + matcher (`mythkernel::exclusions`) — four kinds (`path`, `glob`, `hash_blake3`, `hash_sha256`) and three scopes (`scan_only`, `realtime_only`, `both`) per FR-060/061/134. Insert-time validation rejects `..` segments in path values, hash values that aren't 64 hex chars, and values longer than 4 KiB / reasons longer than 1 KiB. Glob matcher distinguishes `*` (segment-local, POSIX) from `**` (deep wildcard across `/`) per security-review fix; the previous matcher silently downgraded `**` to `*`. `list_active(conn, now)` pushes expiry filtering into SQL. 14 unit tests.
  - TASK-042: Engine wiring — every per-file iteration calls `exclusions::matches()` with the canonical path; path/glob hits short-circuit the hash + detector pipeline. `scans.exclusions_snap` is populated via `exclusions::snapshot_active_json(&conn)` at scan start, closing the FR-062 reproducibility contract.
  - TASK-156: Shields kill-switch (`mythkernel::realtime::shields`) — persistent state at `<data_dir>/shields.json` with append-only `shields.log` audit trail. `ShieldsBroker::set()` now holds the mutex across the disk write + audit append + broadcast send (security-review H2: prior version dropped the lock before persisting, so racing callers could observe state out of order). `ShieldsActor` enum tags every transition with `{Ui, Cli, Tray, AutoResume, Tauri, Engine}`. 9 unit tests.
  - TASK-045: Throughput line chart in the Scan dashboard (`apps/mythodikal/frontend/src/components/ThroughputChart.tsx`) — zero-dependency SVG sparkline rendered from a 30-sample rolling ring fed by a 1 Hz interval in `stores/scan.ts`. Deliberately avoids uPlot/d3/recharts; one polyline + one baseline, ~70 LOC, no new bundle weight or supply-chain surface.
  - TASK-046: First-run flow (`apps/mythodikal/frontend/src/pages/FirstRun.tsx`) — three-step welcome → defaults summary → CTA, gated behind a `mythodikal.firstRunComplete` flag persisted in localStorage. App router shows `FirstRun` on every route until the flag flips. **No telemetry opt-in** because the product ships with zero telemetry by design.
  - Engine: `ScanProgress::File` payload gained `eta_secs: Option<f64>` (with `#[serde(default)]` for backwards-compat); engine seeds `EtaEstimator` from the Phase-A enumeration totals before Phase-B hashing begins.
  - Engine: Phase-A enumeration walks the tree once (counts files + bytes) and Phase-B hashes against the prepared work list. Both phases run on the same `ScanEngine::run` call; UI sees the live `files_total` figure as Phase-A progresses without waiting for it to finish.
  - CLI: `mythctl shields {on, off, pause <minutes>, status}` per FR-160.7. Captures prior state before `set()` so the user-facing "was X, now Y" message is accurate even when the broker resolved an expired pause mid-call.
  - Tauri commands: `shields_get`, `shields_set`, `exclusion_list`, `exclusion_add`, `exclusion_remove`. Exclusions page renders the four kinds with a kind-aware editor.
  - Frontend: ShieldsBadge gains a 1 Hz wall-clock ticker so the "PAUSED · N min" countdown updates without a fresh `shields:changed` event. EtaDisplay distinguishes "starting…" (no files hashed yet) from "calibrating…" (hashes coming in but below 3 % baseline) so the empty state isn't misread.
  - **Code-review + security-review fixes (`/review` + `/security-review` Phase 4 wave 1):** ShieldsBroker mutex held across disk write + audit + broadcast (H2); exclusions reject `..` path segments at insert time (M2); exclusions value/reason length caps prevent degenerate inputs (M3/L2); sysload warm-up sample on construction; sysload `ProcessesToUpdate::All` → `ProcessesToUpdate::Some(&[me])` (L3 — avoid enumerating every PID); `list_active` pushes expiry filter into SQL; glob `**` semantics implemented correctly; `eq_ignore_ascii_case` hash compares documented as non-constant-time-acceptable since file hashes are public inputs.
- **Phase 0 — Foundation & Setup (v0.0.x)** _(shipped 2026-05-09)_
  - TASK-001: Cargo workspace + Tauri v2 shell with single-instance plugin
  - TASK-002: Solid + TypeScript + Vite + Tailwind v3 frontend on port 1420
  - TASK-003: Design tokens (CSS variables + Tailwind extension) per PRD § 9, with restricted spacing scale (`4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 56 / 80`)
  - TASK-004: `mythkernel`, `ui-bridge`, `mythctl` crate skeletons matching PRD § 2.3 module layout
  - TASK-005: GitHub Actions CI matrix (Windows, macOS arm64+x86_64, Linux x86_64+arm64) running fmt + clippy + test + pnpm typecheck/build
  - TASK-006: `cargo-deny` config (license allow-list, advisory check, source registry pinning)
  - TASK-007: `SECURITY.md` (90-day coordinated disclosure inbox `mythodikalone@gmail.com`) and `THIRD-PARTY-DATA.md` (abuse.ch, NSRL, YARA-Forge, loldrivers, LOLBAS, OSV.dev license posture)
  - TASK-008: Baby-blue 3D `M` glyph + wordmark, cross-platform app icon set (PNG ladder, `.ico`, `.icns`), and 16 tray icon variants per FR-162 (`tray-{idle,scanning,shields_off,update_available}-{16,22,32}.png` + 4 macOS template variants)
- **Phase 1 — Engine Core (v0.1.0..v0.1.5)** _(shipped 2026-05-10)_
  - TASK-009: `FileWalker` trait + `PosixWalker` (`walkdir` + `rayon` `par_bridge`, channel-based event stream)
  - TASK-010: BLAKE3 always / SHA-256 lazy streaming hasher (1 MiB chunks, mid-flight `partial()` snapshot for FR-136, in-memory skip-if-unchanged cache)
  - TASK-011: SQLite migration runner + initial schema (`scans`, `findings`, `quarantine`, `exclusions`, `schema_migrations`) + typed CRUD on scans/findings
  - TASK-012: `ScanEngine` top-level with `tokio::broadcast` progress events and DB writeback
  - TASK-013: Static throttle baseline (`available_parallelism / 2`)
  - TASK-014: `tracing` + JSON daily-rolling logs at `<data_dir>/logs/`, level via `MYTH_LOG`
  - TASK-015: `EngineError` enum (serializable for IPC) with `From<io::Error>` and `From<DbError>`
  - TASK-016: TOML config loader (`<config_dir>/config.toml`) with FR-110 (telemetry off) and shields-default-on
  - TASK-017: `mythctl scan <path> [--format text|json] [--sha256] [--follow-symlinks]`
  - TASK-018: criterion benches for walker + hasher; `scripts/bench-1m-files.sh` end-to-end harness asserting NFR-001 budget
- **Phase 3 — UI Alpha (v0.3.0..v0.3.5)** _(shipped 2026-05-11)_
  - Engine pipeline integration: `ScanEngine::with_detection_pipeline` lets the engine evaluate a `DetectionPipeline` inline for every hashed file; `ScanProgress::Finding` event variant added; `findings_count` propagated through `Completed` event and `scans` row.
  - TASK-028: 20 typed `#[tauri::command]` async wrappers in `crates/ui-bridge/src/commands.rs` covering scan (start / status / cancel), history (list / get), findings (list / action), quarantine (list / restore / delete / restore-all / delete-all / restore-many / delete-many), feed (status / update_now / definition_count), settings (get / update stub), system (engine_version).
  - TASK-028: per-scan event forwarder (`run_scan_event_forwarder`) drains the engine's `tokio::broadcast` receiver into Tauri events with a 100 ms throttle on `scan:progress` per FR-085, and reconciles a terminal event from the DB if the channel dropped Completed/Failed on lag.
  - TASK-028: `AppState { engine, db, vault, data_dir, engine_version }` initialized in `apps/mythodikal/src-tauri/src/lib.rs`; pipeline built from `<data_dir>/feeds/` at startup via `build_pipeline_from_feeds`; missing feed files skipped silently for first-run users.
  - TASK-029: Rust IPC payloads in `crates/ui-bridge/src/types.rs` (ScanRequest / ScanSummary / ScanDetail / FindingView / FindingAction / QuarantineItem / BatchOpReport / BatchKindWire / BatchProgressEvent / FeedState / FeedUpdateResult / DefinitionCount / SettingsSnapshot + sub-types / EngineVersionInfo); hand-written TS mirror at `apps/mythodikal/frontend/src/ipc/types.ts` kept in lockstep manually.
  - TASK-029: typed `invoke()` wrapper at `apps/mythodikal/frontend/src/ipc/invoke.ts` — one function per command, one `onScan*` / `onQuarantine*` helper per event topic.
  - TASK-030: Solid signal stores (`stores/scan.ts`, `stores/history.ts`, `stores/quarantine.ts`) attached at app-mount time (not per-page) so a scan kicked off from `/scan` keeps streaming events into the singleton stores while the user is on `/history` or `/quarantine`.
  - TASK-031: components — `ProgressBar`, `FindingRow`, `PathDisplay` (FR-085a subset; full middle-out truncation is Phase 10 TASK-085b), `StatusPill` (token-driven variants for scan status + severity; `detected` / `none` cases map to `warn` not `neutral`), `ThroughputPill` with SI-suffix bytes/sec.
  - TASK-032: Scan dashboard — single primary action, live counters, current path, findings list with action menu. Pause / cancel UI returns a clear "Phase 4 (TASK-040)" error.
  - TASK-033: History page — table per PRD § 8.2; click-through detail view showing the scan's findings.
  - TASK-034: Quarantine page — list with multi-select checkboxes; bulk Restore-All / Delete-All / Restore-Selected / Delete-Selected. Delete-All requires typing `DELETE` in a confirm input per FR-046 (mirrors the CLI's `--confirm`). Live progress bar binds to `quarantine:batch_progress`.
  - TASK-035: Settings page skeleton — General / Scanning / Privacy / About sub-tabs read-only (full editing Phase 4 / TASK-041). About tab embeds an "Update feeds now" form so users can trigger `feed_update_now` from the UI (FR-094).
  - TASK-036: Sidebar nav + AppFrame + `@solidjs/router` wiring; routes `/scan`, `/history`, `/quarantine`, `/settings`; `/` redirects to `/scan`. Sidebar surfaces a placeholder Shields-ON badge (live wiring lands in Phase 4 / FR-160 / TASK-156).
  - TASK-037: Tauri smoke verified via `cargo check --workspace` + `pnpm --filter mythodikal-frontend run build` (no `cargo tauri build` in CI yet — Phase 4).
  - **Security-review fixes (`/security-review` Phase 3):** Strict CSP (`default-src 'self' tauri:`) in `tauri.conf.json`; explicit Tauri capabilities manifest at `apps/mythodikal/src-tauri/capabilities/main.json`; `validate_scan_target` / `validate_restore_target` canonicalize and refuse a denylist of system directories on Windows (`C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `\\?\GLOBALROOT`) and Unix (`/etc /bin /sbin /usr /var /boot /sys /proc /lib /lib64 /System /private`); `scan_start` / `quarantine_restore` / `finding_action` apply the gate before any FS op; `feed_update_now` rejects non-HTTPS `nsrl_url`.
  - **Code-review fixes (`/review` Phase 3):** scan event forwarder throttles `scan:progress` to ≤ 10 Hz and reconciles terminal events on lag; event subscriptions moved to App-level lifetime; `StatusPill` `detected` / `none` cases mapped to `warn`; `BatchOpReport.kind` / `BatchProgressEvent.kind` narrowed to a `BatchKindWire` enum closing field drift with TS; misleading "shares Connection" comment in `lib.rs` corrected (engine + commands hold separate connections to the same WAL DB file).
  - Workspace deps: `ui-bridge` gains `tokio`, `tracing`, `hex`, `rusqlite`, `thiserror`, `tempfile (dev)`. Frontend gains `@solidjs/router` 0.15.x.
- **Phase 2 — Detection Pipeline (v0.2.0..v0.2.5)** _(shipped 2026-05-11)_
  - TASK-019: Detection pipeline core (`Detector` trait, `FileCtx`, `DetectorVerdict` { Clean | SkipFile | Malicious }, `PipelineOutcome`, `Severity` enum, `DetectionPipeline` with priority-ordered short-circuit evaluation)
  - TASK-020: Hash blacklist detector (mmap-loaded sorted-32-byte-key file with O(log N) binary-search lookup; SHA-256 by default with optional BLAKE3 override; emits `Malicious` verdicts with `abusech:hash:<prefix>` rule IDs)
  - TASK-021: NSRL goodware allowlist detector (same on-disk format as TASK-020; emits `SkipFile` at priority 10 so allowlist hits short-circuit before any blacklist runs)
  - TASK-022: abuse.ch feed updater pulling MalwareBazaar + ThreatFox concurrently via `reqwest` (rustls-only, no openssl), Auth-Key header (free key from `https://auth.abuse.ch/`), atomic tmp+rename write of `<feeds_dir>/abusech_sha256.bin`
  - TASK-023: NSRL feed updater (`NsrlSource::Local(path)` or `NsrlSource::Url(url)`) with a generous TSV/CSV/plain-text parser (first 64-char hex run per line); no ZIP/ISO inline dep
  - TASK-024: Quarantine vault — per-install 32-byte random XOR key stored in OS keychain via `keyring` (libsecret / Keychain / Credential Manager) with a 0600 file fallback for CI/headless Linux; atomic move-into-vault with DB-transaction rollback on write failure; refuses to overwrite on restore
  - TASK-025: Findings CRUD + state machine (`FindingState` Detected→Quarantined→{Restored|Deleted|Ignored}); `apply_action`, `current_state`, `list_by_scan / list_by_state / list_by_state_and_min_severity`, `set_notes / set_evidence`
  - TASK-127: Bulk quarantine ops (`restore_many / delete_many / restore_all / delete_all`) with `quarantine_batches` migration (`0002_quarantine_batches.sql`); per-item atomic semantics, `BatchReport.errors`, `ProgressCallback` invoked once per item
  - TASK-026: `mythctl quarantine {list, restore, delete, restore-all, delete-all --confirm, restore-many <ids...>, delete-many <ids...>}` + `mythctl feed update [--abusech-auth-key|env] [--nsrl-local|--nsrl-url]`; global `--db <path>` override
  - TASK-027: End-to-end smoke test — drop synthetic payload → hash → build feed → detect → record finding → apply Quarantine action → vault move (XOR'd) → restore (byte-for-byte recovery)
- **Phase 2 spec changes that landed alongside the build**
  - PRD: **new § 1.5 Cost & Distribution Constraints (HARD)** — 100% free for end users (commercial use included) and 100% free for the maintainer; GitHub-only hosting; no paid OS code-signing; no kernel drivers; no Lemon Squeezy.
  - PRD: **FR-031** macOS real-time is NOTIFY-only permanently (no AUTH); **FR-032** Windows real-time is user-mode ETW + AMSI + WDAC + Defender bridge (no kernel minifilter); **FR-133** block-on-detect implemented per-platform via the free stacks; **FR-141** BYOVD via WDAC; **FR-160** Shields broadcasts to user-mode daemons only.
  - PRD: **FR-135** revised — enumeration and scanning run **concurrently** (producer-consumer worklist); scanning begins on the first enumerated file; `files_total` is unlocked during enumeration, locks at `enumeration:complete`; UI shows three-piece `X scanned · Y enumerated · counting…` then transitions to `X/Y`. The earlier serial "enumerate-then-scan" model is retired.
  - PRD § 10/§ 11: payment-integration deferred indefinitely; if launched, **Gumroad** replaces Lemon Squeezy; the free product must remain fully functional regardless.
  - Roadmap: Phase 11 renamed to "macOS Real-time Enhancement (NOTIFY + XProtect-Style Cleanup)"; Phase 12 renamed to "Windows Real-time Enforcement Stack (ETW + AMSI + WDAC)"; Phase 13 renamed to "Donor / Pro Tier (optional, deferred)". TASK-159 (Defender bridge) and TASK-160 (Sysmon ingest) added to Phase 12.
  - Build-Prompts Guide: every Phase 11/12/13 prompt rewritten to match the new architecture; FR-135 / TASK-137 prompt rewritten to the concurrent producer-consumer model; preface paragraph pins the zero-cost / GitHub-only contract.

### Changed
- License/attribution scrub across project docs to canonical `Mike Weaver <mythodikalone@gmail.com>` and GitHub URLs to `MikesRuthless12/mythodikal-av`.
- **deny.toml** — added `[advisories] ignore = […]` for 16 transitive RUSTSEC advisories all rooted in the tauri 2.x dep tree (proc-macro-error / gtk-rs GTK3 bindings / unic-* via urlpattern); enabled `[bans] allow-wildcard-paths = true` so internal path deps don't trip the wildcard ban; enabled `[licenses] private = { ignore = true }` so workspace crates aren't flagged as unlicensed.
- **Workspace deps added in Phase 2:** `memmap2` 0.9, `reqwest` 0.12 (rustls-only), `keyring` 3, `rand` 0.8. Clap gains the `env` feature so feed-update can fall back to `MYTHODIKAL_ABUSECH_AUTH_KEY`.

### Fixed
-

### Removed
-

### Security
- Telemetry off by default per FR-110.
- Quarantine vault XOR key never leaves the OS keychain (primary) or 0600-permissioned `<data_dir>/quarantine.key` (fallback); fallback warns to tracing log.
- All feed fetches go through rustls (`reqwest` built without default features); no openssl / native-tls in the dep tree.

---

## Pre-stable release plan

The following entries are placeholders aligned with the Version → Phase Map in `docs/product-roadmap.md`. Each becomes a real release section as the corresponding phase ships. Until then, the `[Unreleased]` section above is the source of truth.

### [0.0.x] — Phase 0 — Foundation & Setup _(scheduled)_

- Initialized Cargo workspace and Tauri v2 app shell (TASK-001).
- Frontend scaffold with Solid.js, TypeScript, Vite, Tailwind (TASK-002).
- Design token layer (CSS variables + Tailwind extension) per PRD § 9 (TASK-003).
- Workspace crate skeletons: mythkernel, ui-bridge, mythctl (TASK-004).
- GitHub Actions CI matrix: windows-latest, macos-14, macos-13, ubuntu-22.04, ubuntu-22.04-arm (TASK-005).
- cargo-deny license + advisory enforcement (TASK-006).
- Repository governance files: LICENSE.md, README.md, CHANGELOG.md, SECURITY.md, THIRD-PARTY-DATA.md (TASK-007).
- Brand mark + cross-platform app icon set (TASK-008).

### [0.1.x] — Phase 1 — Engine Core _(scheduled)_

- Cross-platform file walker (rayon + walkdir) with exclusion support (TASK-009).
- BLAKE3 + lazy SHA-256 streaming hasher (TASK-010).
- SQLite-backed scan history layer with refinery migrations (TASK-011).
- ScanEngine top-level with broadcast progress events (TASK-012).
- Static-concurrency throttle baseline (TASK-013).
- Structured `tracing` JSON logs with daily rotation (TASK-014).
- Centralized EngineError types (TASK-015).
- Persisted Config (TOML) with telemetry off by default (TASK-016).
- `mythctl scan` command with text/json output (TASK-017).
- Canonical 1M-file benchmark scaffolding (TASK-018).

### [0.2.x] — Phase 2 — Detection Pipeline _(shipped 2026-05-11; see `[Unreleased]` above for the full entry)_

- Detection pipeline core trait + priority-ordered short-circuit evaluation (TASK-019).
- Hash blacklist detector backed by mmap'd sorted-32-byte-key binary file (TASK-020).
- NSRL allowlist detector (skip-verdict, priority 10) (TASK-021).
- abuse.ch feed updater pulling MalwareBazaar + ThreatFox via rustls-only `reqwest` (TASK-022).
- NIST NSRL feed updater accepting local file or HTTPS URL (TASK-023).
- Quarantine vault (XOR-keyed via `keyring` with 0600 file fallback) with restore + delete (TASK-024).
- Findings persistence + action state machine (TASK-025).
- Bulk quarantine ops + `quarantine_batches` migration (TASK-127).
- `mythctl quarantine` and `mythctl feed` subcommands (TASK-026).
- End-to-end drop → detect → quarantine → restore smoke test (TASK-027).

### [0.3.x] — Phase 3 — UI Alpha _(shipped 2026-05-11; see `[Unreleased]` above for the full entry)_

- Engine + DetectionPipeline integration: scan emits `ScanProgress::Finding` inline; findings_count propagated.
- Tauri commands: Scan, History, Findings, Quarantine, Settings stub, Feed, Engine version (TASK-028).
- Hand-written TS mirror of Rust IPC types (TASK-029).
- Solid stores: scan + history + quarantine attached at App-mount (TASK-030).
- Components: ProgressBar, FindingRow, ThroughputPill, StatusPill, PathDisplay (TASK-031).
- Page: Scan dashboard with live counters + findings list (TASK-032).
- Page: History table with detail drill-in (TASK-033).
- Page: Quarantine with bulk Restore/Delete + typed-DELETE gate (TASK-034).
- Page: Settings skeleton + "Update feeds now" form (TASK-035).
- Sidebar nav + AppFrame + `@solidjs/router` (TASK-036).
- Tauri smoke via `cargo check` + `pnpm build` (TASK-037).
- Security-review fixes: strict CSP, capabilities allowlist, path-policy gate (deny-list of system paths), HTTPS-only `nsrl_url`.
- Code-review fixes: ≤ 10 Hz `scan:progress` throttle, terminal-event reconciliation from DB on broadcast lag, app-level event subscription lifetime, BatchKind wire type narrowed.

### [0.4.x] — Phase 4 — Linux MVP & Magic Moment _(scheduled)_

- Calibrated, monotone-after-baseline ETA estimator (TASK-038).
- Adaptive CPU/IO throttle responsive to system load (TASK-039).
- Pause/resume across full app restart and OS reboot (TASK-040).
- Settings sub-tabs full implementation (TASK-041).
- Exclusions CRUD: path / glob / hash with per-scan snapshot (TASK-042).
- Auto-updater for signature feeds, ed25519-verified (TASK-043).
- Tauri Updater plugin wired (engine self-update) (TASK-044).
- Throughput chart (uPlot) on Scan dashboard (TASK-045).
- First-run flow per PRD § 8.6 (TASK-046).
- Linux packaging: .deb, .rpm, AppImage (TASK-047).
- Release pipeline driven by `v*` tags (TASK-048).
- v0.4.0 launch checklist + tag (TASK-049).

### [0.5.x] — Phase 5 — Windows MFT Superpowers _(scheduled)_

- NTFS walker via `usn-journal-rs` with PosixWalker fallback for non-NTFS (TASK-050).
- USN-journal incremental scan with rotation-aware fallback (TASK-051).
- Volume detection + per-volume worker pools (TASK-052, TASK-053).
- WiX-based .msi installer (TASK-054).
- Windows OV code-signing in CI (TASK-055).
- Windows scan-target UX with per-volume chooser (TASK-056).
- Windows benchmarks (TASK-057).
- v0.5.0 release: Windows + Linux (TASK-058).

### [0.6.x] — Phase 6 — macOS Port _(scheduled)_

- macOS universal binary (lipo arm64 + x86_64) (TASK-059).
- macOS unsigned bundle + first-run UX documentation per `docs/prd.md` § 1.5.3 (TASK-060). **No Apple Developer Program, no notarization.**
- macOS .dmg (unsigned, runtime restrictions where free) (TASK-061).
- macOS UI parity polish (sheets, native chrome) (TASK-062).
- ~~Apple ESF entitlement application playbook~~ — REMOVED per § 1.5.4 (macOS real-time is NOTIFY-only permanently).
- v0.6.0 release: Win + Mac + Linux (TASK-064).

### [0.7.x] — Phase 7 — YARA & Rule Manager _(scheduled)_

- yara-x integration with per-rule timeout + per-scan memory caps (TASK-065).
- YARA-Forge `core` bundle ingestion with license-scrubber gate (TASK-066).
- Nightly license-scrub CI workflow (TASK-067).
- Rule Manager UI per PRD § 8.4 (TASK-068).
- User-loadable rulesets via file picker / URL (TASK-069).
- Per-finding YARA evidence (matched strings, byte ranges) (TASK-070).
- Scan diff between two scans of the same target (TASK-071).
- v0.7.5 release (TASK-072).

### [0.8.x] — Phase 8 — Linux Real-time _(scheduled)_

- `mythd-linux` fanotify daemon with systemd unit (TASK-073).
- Engine ↔ daemon CBOR IPC over `/run/mythd/mythd.sock` (TASK-074).
- Real-time UI surface with back-pressured event log (TASK-075).
- Watchdog + autostart with crash-budget alerting (TASK-076).
- Inotify fallback for kernels < 5.1 (observe-only mode) (TASK-077).
- v0.8.0 release (TASK-078).

### [0.9.x] — Phase 9 — macOS Real-time (NOTIFY) _(scheduled)_

- FSEvents fallback (no entitlement required) (TASK-079).
- ESF NOTIFY-only mode (entitled) (TASK-080).
- Engine ↔ ES extension XPC bridge (TASK-081).
- macOS Real-time UI parity with mode indicator (TASK-082).
- v0.9.0 release (TASK-083).

### [0.10.x] — Phase 10 — Polish & Public Launch _(scheduled)_

- Behavioral heuristics for ransomware-shape detection (TASK-084).
- Archive scanning (zip/7z/rar/tar/iso) with depth + size caps (TASK-085).
- Cron-like scheduler with idle-only constraint (TASK-086).
- Auto-scan on USB / removable mount (Linux + Windows) (TASK-087).
- Diagnostic bundle export (path-redacted) (TASK-088).
- Localization scaffolding (Fluent format) (TASK-089).
- Marketing / docs site (Astro on **GitHub Pages**) per `docs/prd.md` § 1.5.2 (TASK-090).
- v0.10.0 public launch — Show HN, Reddit, dev-Twitter, reviewer outreach (TASK-091).

### [0.11.x – 0.12.x] — Phase 11 — macOS Real-time Enhancement (NOTIFY + XProtect-Style Cleanup) _(scheduled)_

- Enriched ESF NOTIFY subscription + event-stream forensic depth (TASK-092).
- Verdict cache LRU keyed on (path, mtime, size) (TASK-093).
- XProtect-Remediator-style launchd cleanup task `com.mythodikal.cleanup` (TASK-094).
- v0.12.0 release: macOS real-time NOTIFY + post-hoc cleanup live (TASK-095).

### [0.13.x – 0.15.x] — Phase 12 — Windows Real-time Enforcement Stack (ETW + AMSI + WDAC + Defender bridge) _(scheduled)_

- User-mode real-time service skeleton `mythd-windows` (TASK-096). **No kernel driver.**
- Engine ↔ mythd-windows IPC over authenticated named pipe (TASK-097).
- ETW Threat Intelligence subscriber (TASK-098).
- AMSI provider registration `MythodikalAmsiProvider` (TASK-099).
- WDAC policy generator + apply (TASK-100).
- Service in product installer + uninstaller (Windows MSI, no driver) (TASK-101).
- Real-time UI: Windows parity (no driver telemetry fields) (TASK-102).
- Windows real-time stress + recovery tests (fail-open) (TASK-103).
- v0.15.0 release: Windows real-time live (user-mode stack) (TASK-104).
- Microsoft Defender bridge (Set-MpPreference + quarantine push) (TASK-159).
- Optional Sysmon ingest (bundled, signed-by-Microsoft) (TASK-160).

### [0.16.x – 0.17.x] — Phase 13 — Donor / Pro Tier (optional, deferred) _(scheduled)_

- License-key engine (offline ed25519 verification) (TASK-105). **No P0/P1/P2 feature gated by it.**
- Payment-provider integration (Gumroad-leading; founder admin) (TASK-106). Lemon Squeezy removed per `docs/prd.md` § 1.5.5.
- Settings > Activation page (TASK-107).
- Donor extra: signed scan reports (PDF + JSON) with verifier CLI (TASK-108).
- Donor extra: multi-device policy sync via private GitHub Gist (opt-in) (TASK-109). **No `sync.mythodikal.com` endpoint.**
- Donate flow for free users (GitHub Sponsors / Gumroad link) (TASK-110).

### [0.18.x] — Phase 14 — Hardening _(scheduled)_

- WCAG AA accessibility audit + fixes across all pages (TASK-111).
- cargo-fuzz harnesses for USN, archive, and feed parsers (TASK-112).
- Memory-leak audit (long-scan stress, ASan/Valgrind nightly) (TASK-113).
- Performance push: cold 1M-file scan ≤ 4 minutes (NFR-001 final) (TASK-114).
- Localization completion: de, fr, es, ja, zh (TASK-115).
- User docs / in-app Help (TASK-116).

### [0.19.0 – 0.19.83] — Phase 15 — Stable Run-up _(scheduled)_

- v0.19.0 RC1 cut and shipped to beta channel (TASK-117).
- Third-party reviewer outreach (TASK-118).
- Detection efficacy validation methodology + corpus (NFR-011 ≥ 98%) (TASK-119).
- Reproducible-build investigation (decision documented) (TASK-120).
- 7-day P0/P1 freeze before tag (TASK-121).
- v0.19.83 RC tagged (TASK-122).

### [0.19.84] — Phase 16 — **Stable Release** _(scheduled)_

- Release notes drafted (TASK-123).
- Marketing site refreshed for stable (TASK-124).
- v0.19.84 stable tag and ship (TASK-125).
- Public announcement: blog, Show HN, Reddit, dev Twitter, reviewer coverage (TASK-126).

---

## Versioning policy

- Pre-stable releases (`0.x.y`): minor (`x`) bumps each phase; patch (`y`) bumps for hotfixes within a phase.
- The first stable release is `0.19.84`. Subsequent stable releases follow strict SemVer 2.0.
- Feature feeds (signature databases, YARA rule packs) are versioned independently and visible in `Settings → Updates`.

## How to add an entry

When you complete a TASK-NNN, add a line to the matching `[Unreleased]` subsection (`Added`, `Changed`, `Fixed`, `Removed`, `Security`). The Phase Closeout protocol (see `Mythodikal-Build-Prompts-Guide.md`) enforces this.

When a phase ships its release, promote `[Unreleased]` to the version heading and create a fresh empty `[Unreleased]` section above it.

[Unreleased]: https://github.com/MikesRuthless12/mythodikal-av/compare/v0.0.0...HEAD
