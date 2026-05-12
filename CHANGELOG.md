# Changelog

All notable changes to Mythodikal Anti-Virus are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to a 0-based pre-stable [Semantic Versioning](https://semver.org/spec/v2.0.0.html) scheme. The first stable release will be **v0.19.84**.

Each release section lists which `TASK-NNN` items from `docs/product-roadmap.md` shipped in that release. Phase Closeout (per `Mythodikal-Build-Prompts-Guide.md`) populates `[Unreleased]` as work lands and promotes it to a version heading at release time.

---

## [Unreleased]

### Added
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

### [0.3.x] — Phase 3 — UI Alpha _(scheduled)_

- Tauri commands: Scan, History, Findings, Quarantine, Settings skeleton (TASK-028).
- Generated TS IPC types from Rust source-of-truth (TASK-029).
- Solid stores: scan + history with throttled event consumption (TASK-030).
- Components: ProgressBar, FindingRow, ThroughputPill, StatusPill (TASK-031).
- Page: Scan dashboard with idle/running/paused/completed/failed states (TASK-032).
- Page: History (TASK-033).
- Page: Quarantine (TASK-034).
- Page: Settings skeleton — General + Privacy + About (TASK-035).
- Sidebar nav + app frame (TASK-036).
- Cross-platform Tauri dev/build smoke (TASK-037).

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
