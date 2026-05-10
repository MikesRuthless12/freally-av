# Changelog

All notable changes to Mythodikal Anti-Virus are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to a 0-based pre-stable [Semantic Versioning](https://semver.org/spec/v2.0.0.html) scheme. The first stable release will be **v0.19.84**.

Each release section lists which `TASK-NNN` items from `docs/product-roadmap.md` shipped in that release. Phase Closeout (per `Mythodikal-Build-Prompts-Guide.md`) populates `[Unreleased]` as work lands and promotes it to a version heading at release time.

---

## [Unreleased]

### Added
- _(populated by Phase Closeout as work lands; entries appear here keyed to TASK-NNN)_

### Changed
-

### Fixed
-

### Removed
-

### Security
-

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

### [0.2.x] — Phase 2 — Detection Pipeline _(scheduled)_

- Detection pipeline core trait + sequential evaluation (TASK-019).
- Hash blacklist detector backed by mmap'd perfect-hash file (TASK-020).
- NSRL allowlist detector (skip-verdict) (TASK-021).
- abuse.ch feed updater (manual `mythctl feed update`) (TASK-022).
- NIST NSRL feed updater (TASK-023).
- Quarantine vault (XOR-keyed via OS keychain) with restore (TASK-024).
- Findings persistence + action state machine (TASK-025).
- `mythctl quarantine` and `mythctl feed` subcommands (TASK-026).
- End-to-end EICAR smoke test wired into CI (TASK-027).

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
- Apple Developer ID signing + notarization in CI (TASK-060).
- macOS .dmg with hardened runtime (TASK-061).
- macOS UI parity polish (sheets, native chrome) (TASK-062).
- Apple ESF entitlement application playbook (TASK-063).
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
- Marketing site at `mythodikal.com` (Astro on Cloudflare Pages) (TASK-090).
- v0.10.0 public launch — Show HN, Reddit, dev-Twitter, reviewer outreach (TASK-091).

### [0.11.x – 0.12.x] — Phase 11 — macOS ESF AUTH _(scheduled)_

- ESF subscription switched to AUTH events (after entitlement granted) (TASK-092).
- Verdict cache LRU keyed on (path, mtime, size) (TASK-093).
- Stress + crash-recovery on macOS AUTH path (fail-open semantics) (TASK-094).
- v0.12.0 release: macOS real-time AUTH live (TASK-095).

### [0.13.x – 0.15.x] — Phase 12 — Windows Minifilter Driver _(scheduled)_

- C/C++ minifilter driver project skeleton (mythflt) (TASK-096).
- User-mode service ↔ driver IPC over Filter Communication Port (TASK-097).
- Driver test-signing in CI (TASK-098).
- Microsoft Hardware Dev Center attestation submission (TASK-099).
- Windows EV cert procurement (TASK-100).
- Driver in product installer + uninstaller (TASK-101).
- Real-time UI: Windows parity with driver telemetry (TASK-102).
- Windows real-time stress + recovery tests (fail-open) (TASK-103).
- v0.15.0 release: Windows real-time live (TASK-104).

### [0.16.x – 0.17.x] — Phase 13 — Pro Tier _(scheduled)_

- License-key engine (offline ed25519 verification) (TASK-105).
- Lemon Squeezy integration for Pro purchase flow (TASK-106).
- Settings > Activation page (TASK-107).
- Pro: signed scan reports (PDF + JSON) with verifier CLI (TASK-108).
- Pro: end-to-end-encrypted multi-device policy sync (opt-in) (TASK-109).
- Donate flow for free users (TASK-110).

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
