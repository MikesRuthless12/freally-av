# Mythodikal Anti-Virus

> The fastest source-visible anti-virus for Windows, macOS, and Linux — no bloat, no telemetry, no upsell.

Read every line. Time every scan. Trust the result.

| | |
|---|---|
| Status | Pre-alpha (pre-v0.4.0). Active development toward stable v0.19.84. |
| Platforms | Windows 11+, macOS 13+ (universal), Linux (kernel ≥ 5.1, x86_64 + aarch64) |
| Engine | Rust 2024 (`mythkernel` crate) |
| UI | Tauri v2 + Solid.js + TypeScript + Tailwind |
| License | All Rights Reserved (source-visible). See [LICENSE.md](LICENSE.md). |
| Maintainer | Mike Weaver (`mythodikalone@gmail.com`) — solo developer |

---

## Why Mythodikal exists

The consumer anti-virus market in 2026 has drifted into bundles that nobody asked for: VPNs, password managers, "PC speed-up" tools, browser toolbars. Telemetry is on by default. The actual security software has full filesystem access — and the source is closed.

Mythodikal is the AV the maintainer wants to use on his own machines. It does AV. Only AV. Source is on GitHub. Telemetry is off by default. Defaults are sane. The progress bar tells the truth.

The full strategic foundation is in [`docs/product-vision.md`](docs/product-vision.md). The technical blueprint is [`docs/prd.md`](docs/prd.md). The phased build plan is [`docs/product-roadmap.md`](docs/product-roadmap.md). The launch playbook is [`docs/gtm.md`](docs/gtm.md).

---

## What it does (target features at v0.19.84 stable)

- **Fast.** A 1-million-file cold scan completes in under 4 minutes on a 2024-class consumer NVMe machine. The second scan, via NTFS USN journal delta, completes in under 5 seconds. An optional CRC32 fast-screen pre-pass (`MYTHCRC3` sorted-u32 set) lets the engine skip BLAKE3 + SHA-256 + the full detection pipeline on files whose 32-bit CRC isn't in the malware set — ~99.977% of scanned files at typical corpus sizes — collapsing per-file hashing wall time another 40-80% on CPU-bound NVMe scans.
- **Honest progress.** Time-remaining estimates are calibrated and monotone-non-increasing after the first 3% of work — no "stuck at 99%."
- **Cross-platform parity.** Same feature set on Windows, macOS, and Linux unless platform constraints forbid.
- **Source-visible.** Every line of the engine, the UI, and the build pipeline is here on GitHub. License forbids redistribution; reading and learning is welcome.
- **Real-time on-access protection.** **All user-mode, zero kernel drivers, zero paid signing** (see [`docs/prd.md`](docs/prd.md) § 1.5.4). Windows: ETW Threat Intelligence + AMSI + WDAC + Microsoft Defender bridge. macOS: ESF NOTIFY-only + XProtect-Remediator-style launchd cleanup. Linux: `fanotify` daemon.
- **Layered detection.** abuse.ch hash blacklist (commercial-clean per [their FAQ](https://bazaar.abuse.ch/faq/)), NIST NSRL goodware allowlist, YARA-Forge `core` permissively-licensed rule pack, original behavioral heuristics.
- **User-loadable YARA.** First-class rule manager. Add your own rules. Validate, license-scrub, run.
- **Quarantine with restore + per-finding explanation.** When a file is flagged, you see the exact rule, the exact bytes (for YARA), the source feed, and the action options.
- **Scan history with one-click rerun.** Re-run any past scan against its original target paths and exclusions snapshot.
- **Smart exclusions.** Path, glob, hash, signing key. Snapshot per-scan so history is reproducible.
- **Adaptive throttle.** Scans yield to interactive load. Your video call survives a full-disk scan.
- **Pause / resume across reboots.** Long scans persist their state.
- **Ed25519-signed auto-updates.** Engine and signature feeds.
- **No bloat.** No bundled VPN, password manager, "PC speedup," browser toolbar, or affiliate offers — ever.
- **No telemetry by default.** If telemetry is ever opted-into, the scope is anonymous version + scan-count counter — no paths, no hashes, no IPs.

The current state of the codebase is far short of this list. See [`docs/product-roadmap.md`](docs/product-roadmap.md) for the phase the project is currently in.

---

## License posture (please read)

Mythodikal is **source-visible, All Rights Reserved**. See [`LICENSE.md`](LICENSE.md) for the operative text. In short:

- You may read, study, and reference the source for personal learning and security review.
- You may not copy, modify, redistribute, sublicense, or run derivative works.
- You may not include any portion of this code in your own products, open or closed.
- You may not train machine-learning models on this source code.
- You may not use this source code, in whole or in part, to create a competing product.
- Bug reports and security disclosures via [`SECURITY.md`](SECURITY.md) are warmly welcomed and do not require any rights grant beyond reading and reporting.

If you want a custom commercial arrangement (embedding, OEM, white-label, etc.), email `mythodikalone@gmail.com`.

This license posture is unusual for an AV product. The reasoning is in [`docs/product-vision.md`](docs/product-vision.md) § 1 and [`RESEARCH-DOSSIER.md`](RESEARCH-DOSSIER.md) § 9.

---

## Status & roadmap

The roadmap targets stable **v0.19.84**, sequenced across 16 phases. Current phase status is tracked live in [`docs/product-roadmap.md`](docs/product-roadmap.md).

**Current state:** Phases 0, 1, 2, 3 are shipped. **Phase 6 shipped 2026-05-22 (v0.6.0)** — macOS universal-binary release pipeline + unsigned bundle + hardened-runtime entitlements + platform-aware Modal component all in the tree. **Phase 7B Wave 1 code-complete 2026-05-23** — two-tier samples schema (gold + silver), hash-only ingest subcommand, tier-aware export, NSRL RDSv3 whitelist ingest + sorted-`.bin` export, consolidated single-file shippable artifacts, simplified byte-fetch pipelines with severity derived from MB metadata at insert time, first-scan UX with three NSRL download choices, and the nightly NIST refresh workflow (with integrity verification + version-skip guard). **Phase 7B Wave 2 merged to `main` 2026-05-27 (squash `71e3300` via PR #6)** — Bloom + Cuckoo filter front-ends, partial-match for ≥ 256 MB files, hash de-aging, per-OS NSRL slicing, package-manager / App Store / Microsoft Store / Snap/Flatpak/AppImage / dev-publisher / SBOM allowlists, ephemeral trust-this-once with auto-expiry, confidence-graded findings, feed-freshness widget, mirror failover + chained ed25519 epoch sig, in-app user-IOC editor (CSV / STIX 2.1 / MISP), per-finding citation-copy, reverse-lookup + lateral-search, BLAKE3 + SHA-256 dual-key gate on P0 promotions, and ~85 new unit tests. 22 of 23 Wave 2 tasks landed (TASK-178..199); only **TASK-200** — the v0.7.13 release tag — remains, with release notes and a staging directory already drafted on disk.

**Phase 7C ("Engine Enhancement", v0.7.14 → v0.7.20) shipped 2026-05-27.** All four waves are foundation-complete on `phase-7c/task-201-resumable-scans`. Wave 1 (orchestration): resumable scans (TASK-201), file-state diff cache + epoch invalidation (TASK-202), multi-root parallel producers (TASK-203), foreground-aware throttle (TASK-204), dev exclude pack + project detect (TASK-205/206), LoopGuard (TASK-210). Wave 2 (file policy + content): packer ID (TASK-217), entropy heatmap (TASK-225), file-policy modules (TASK-227/228/229), hot zones + mmap hash + archive bomb guard (TASK-230/232/233). Wave 3 (format-aware detectors, this release): header parser (TASK-216), dual-arch / fat binary (TASK-209), sparse-aware hashing (TASK-211), reparse-point policy (TASK-212), APFS clones (TASK-213), Btrfs/ZFS reflinks (TASK-214), snapshot abstraction (TASK-215), UPX unpacker (TASK-218), .NET IL extractor (TASK-219), Java bytecode parser (TASK-220), Android DEX / AXML (TASK-221), Mach-O code-signature (TASK-222), Authenticode validator (TASK-223), ELF hardening inventory (TASK-224). Wave 4 (power + stats + deltas + remote, this release): wake gate (TASK-207), battery-aware throttle (TASK-208), statistical anomaly engine + baseline (TASK-226), FastCDC selective rehash + chunk store (TASK-231), remote-mount scan mode (TASK-234). The release-ceremony tag (TASK-235) bumps `Cargo.toml` workspace + `tauri.conf.json` to **0.7.20** and adds `docs/launch-checklists/v0.7.20.md`. ~115 new unit tests across the wave; `cargo test -p mythkernel --lib` runs 638 tests green.

**Phase 8 foundation 2026-05-27** — all 24 wave-1 + wave-2 tasks landed: `daemon/mythd-{linux,macos,windows}` crates added to the workspace, length-prefixed CBOR IPC (`mythkernel::ipc::linfan`), block-on-detected index + verdict policy, browser-credential-store detector, honeyfile tripwires with SIGSTOP, eBPF observe-only scaffold, audit NETLINK fallback, per-mount real-time toggle, container bind-mount dedupe, WSL distro bridge, and the cross-platform USB stack (`mythkernel::usb::*`: allowlist, BadUSB HID anomaly, power-only override, autorun.inf reader, RTL-override heuristic, write event log, per-device scan history) wired through `crates/ui-bridge/src/commands_{usb,mount}.rs` and six new frontend pages (`Realtime`, `UsbInsertModal`, `Settings/UsbAllowlist`, `Settings/UsbPolicy`, `History/UsbWrites`, `UsbDevices`).

**Phase 9 foundation 2026-05-27** — all Phase 9 Wave 1 + Wave 2 tasks landed: `daemon/mythd-macos` real-time stack with `fsevents.rs` (primary NOTIFY-only surface), `esf_notify.rs` (opportunistic ES system extension — **no `endpoint-security.client` entitlement**, falls back to FSEvents on stock consumer macOS), `esf_failover.rs` (50 ms `(inode,mtime,size)` dedupe, prefers ESF, recovers gracefully on `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`), `exemption_keychain.rs` + `crates/mythkernel/src/exempt/per_app.rs` (per-app exemptions stored in Keychain behind `BiometryCurrentSet | Or | DevicePasscode`; bundle ID + team ID composite key — pure path-based exemption rejected), `launchd.rs` + `Settings/MacExemptions.tsx` + `MacRealtimeHeartbeat.tsx` (atomic-write heartbeat JSON, green/amber/red chip), `crates/mythkernel/src/ipc/macesf.rs` (JSON-over-XPC `IpcFrame { NotifyEvent, Heartbeat, ShieldsPush, ActiveFindingsPush }` — **no Verdict variant; NOTIFY-only proven by `on_wire.contains("verdict")` test**), and `rules/honey.rs` (`proc_listpids` + `proc_pidinfo` process-tree walk + SIGSTOP, mac-side variant of TASK-142). Daemon binaries on Windows ship as Phase-8 scaffolds; full Windows ETW+AMSI+WDAC lands Phase 12.

**Phase 4 is code-complete (waves 1–6 committed 2026-05-12)** — ETA, adaptive throttle, pause/resume, Shields kill-switch, Exclusions CRUD (incl. publisher kind), throughput chart, first-run flow, feed auto-updater, release pipeline + GH-Releases-signed Tauri Updater, dual-channel (engine vs database) update architecture, About page per-source definition counts, Settings → Updates dual pane, operator-mode live BLAKE3 partial-hash display, per-exclusion 24-hour quick-action, cross-platform publisher whitelist (Authenticode / codesign / GPG), Tauri-plugin-autostart wiring with live Settings toggle (TASK-157), and the FR-162.5 system tray with state-machine icon (TASK-158) all in the tree. Only TASK-049 (launch-checklist sign-off — benchmarks rerun + screenshots + tag procedure) gates the `[Unreleased]` → `v0.4.0` promotion. **Phase 5 is code-complete (waves 1 + 2 + 3 committed 2026-05-12)** — TASK-050 (cross-platform fast walker via vendored Sourcerer journal subscribers — NTFS MFT on Windows, raw `getdents64` on Linux, FSEvents-driven `read_dir` on macOS, `PosixWalker` fallback everywhere), TASK-051 (USN incremental walker on Windows with rotation-detect-then-fallback-to-MFT), TASK-052 (Windows volume detection + enumeration via `FindFirstVolumeW`/`GetVolumeInformationW`), TASK-053 (`MultiVolumeWalker` per-volume parallel scan aggregator), TASK-054 (per-machine WiX + NSIS Windows installer, unsigned per § 1.5.3), TASK-056 (Windows per-volume scan-target chooser + "scan all volumes" checkbox driving multi-volume fan-out), TASK-057 (criterion `win_mft` bench comparing `NtfsWalker` vs `PosixWalker` + `scripts/bench-1m-files.ps1` Windows end-to-end harness), TASK-058 (v0.5.0 launch checklist), TASK-137 (concurrent producer/consumer engine with `EnumerationComplete` event + locked-Y UI presentation, FR-135 revision), TASK-138 (file-mutation baseline detector — `file_baseline` table + per-platform autostart enumerators + `$PATH` binary inventory + per-file diff with signed-or-NSRL-known prior gate, FR-131), and TASK-139 (BYOVD blocklist via loldrivers.io — daily JSON pull + `ByovdDetector` at severity `Critical`, FR-141 static portion) are all in the tree. The `Phase 5 Smoke Test` (admin Win 11 VM, 500K+ NTFS C:, throughput ≥ 8K files/s, USN rescan ≤ 30 s, multi-volume aggregator across a USB stick) gates the `[Unreleased]` → `v0.5.0` promotion alongside `v0.4.0`.

| Phase | Goal | Version | Status |
|---|---|---|---|
| 0 | Foundation & Setup | v0.0.x | ✅ Shipped |
| 1 | Engine Core | v0.1.x | ✅ Shipped |
| 2 | Detection Pipeline | v0.2.x | ✅ Shipped |
| 3 | UI Alpha | v0.3.x | ✅ Shipped |
| 4 | Linux MVP & Magic Moment | v0.4.x | 🟢 Code-complete (tag gated on TASK-049) |
| 5 | Windows MFT Superpowers | v0.5.x | 🟢 Code-complete (waves 1+2 shipped 2026-05-12; tag gated on TASK-058 smoke test) |
| 6 | macOS Port (unsigned, see `docs/prd.md` § 1.5.3) | v0.6.x | ✅ Shipped 2026-05-22 (v0.6.0 consolidated tag) |
| 7 | YARA & Rule Manager | v0.7.x | Reclassified to optional / Pro / post-MVP per TASK-177 — no longer release-gating |
| 7B | Hash-Only Blacklist + NSRL Whitelist (Wave 1) | v0.7.x | 🟢 Wave 1 code-complete 2026-05-23 — tag-cut gated on launch checklist |
| 7B-W2 | Hash-Path Perf + Allowlist Intelligence + IOC Tools (Wave 2) | v0.7.x | 🟢 Wave 2 merged to `main` 2026-05-27 via PR #6 (squash `71e3300`); 22/23 tasks landed (TASK-178..199); TASK-200 v0.7.13 release tag in flight (release notes + staging dir drafted) |
| 7C | Engine Enhancement: resumable scans + diff rescan + multi-root parallel + adaptive/battery/wake throttle + sparse/clone/reflink/snapshot correctness + PE/ELF/Mach-O/.NET-IL/Java/DEX/Authenticode parsers + entropy + UPX unpacker + stale-temp auto-quarantine + per-extension/hot-zone/zero-trust policy + FastCDC selective rehash + mmap large-file hash + remote-mount slow-mode | v0.7.x | ✅ Foundation-complete 2026-05-27 (v0.7.20 tag, TASK-235) |
| 8 | Linux Real-time (fanotify daemon) + Wave 2 USB stack | v0.8.x | 🟢 Foundation 2026-05-27 — all 24 tasks (TASK-073..078, TASK-140..142, TASK-236..250); tag gated on the v0.8.0 launch checklist Linux-runtime smoke |
| 9 | macOS Real-time (FSEvents + opportunistic ESF NOTIFY) + Wave 2 (failover, biometric exemptions, launchd watchdog) | v0.9.x | 🟢 Foundation 2026-05-27 — all 10 implemented tasks (TASK-079..083, TASK-161, TASK-252..255); TASK-251 BLOCKED (NetworkExtension needs paid Apple Dev Program); tag gated on the v0.9.0/v0.9.7 launch checklist macOS-runtime smoke |
| 10 | Polish & Public Launch | v0.10.x | Pending |
| 11 | macOS Real-time Enhancement (NOTIFY + XProtect-Style Cleanup) | v0.11.x – v0.12.x | Pending |
| 12 | Windows Real-time Enforcement Stack (ETW + AMSI + WDAC) | v0.13.x – v0.15.x | Pending |
| 13 | Donor / Pro Tier (optional, deferred) | v0.16.x – v0.17.x | Pending |
| 14 | Hardening | v0.18.x | Pending |
| 15 | Stable Run-up | v0.19.x | Pending |
| 16 | **Stable Release** | **v0.19.84** | Pending |

**What works today (after Phase 3):** Both the `mythctl` CLI **and** the Tauri GUI can scan a directory, ingest abuse.ch and NSRL feeds into local `.bin` files, detect known-bad files by SHA-256, quarantine them (XOR'd, with the key in your OS keychain), and restore them byte-for-byte. The GUI ships four pages — Scan, History, Quarantine, Settings — wired through 20 typed Tauri commands. Scan progress streams to the UI as live events at ≤ 10 Hz per `docs/prd.md` § 4.2. Path-policy gate + strict CSP + Tauri capabilities allowlist are in place per the Phase-3 security review.

---

## Building from source

Mythodikal is built with Rust + Tauri v2 + pnpm + Solid.js. You will need:

- Rust ≥ 1.85 (`rustup default stable`)
- Node 20 + `pnpm` (`corepack enable && corepack prepare pnpm@latest --activate`)
- Tauri v2 prerequisites for your OS — see [tauri.app/v2/start/prerequisites](https://v2.tauri.app/start/prerequisites/).
- **No** Windows WDK, **no** Apple Developer Program — per [`docs/prd.md`](docs/prd.md) § 1.5 the project ships with zero paid OS code-signing infrastructure. Windows real-time uses ETW + AMSI + WDAC (Phase 12); macOS real-time uses ESF NOTIFY-only (Phase 11). Neither requires paid tooling.

Once you've cloned the repo:

```bash
pnpm -C apps/mythodikal/frontend install --frozen-lockfile
cargo check --workspace
pnpm -C apps/mythodikal/frontend tauri dev
```

The first run opens a Mythodikal window with the brand mark and the design tokens applied. From there, follow the active phase's smoke test in [`Mythodikal-Build-Prompts-Guide.md`](Mythodikal-Build-Prompts-Guide.md).

You may build locally for personal learning. You may not redistribute the resulting binaries. See [`LICENSE.md`](LICENSE.md).

---

## First-run on Windows (unsigned bundle)

Mythodikal ships **unsigned** per [`docs/prd.md`](docs/prd.md) § 1.5.3 — the project's zero-cost / no-paid-signing constraint forbids OV or EV code-signing certificates. On Windows 11 the first launch therefore triggers SmartScreen and (depending on how the file was downloaded) the Mark-of-the-Web "blocked" attribute. Both are expected. Workarounds:

1. **SmartScreen Defender prompt** ("Windows protected your PC"):
   - Click **More info**.
   - Click **Run anyway**.
   - The MSI installer launches normally.
2. **"This file came from another computer and might be blocked"** (Mark-of-the-Web):
   - Right-click the downloaded `.msi` → **Properties**.
   - Tick **Unblock** at the bottom of the General tab → **OK**.
   - Re-launch the MSI.
3. **Per-machine install** lands at `%ProgramFiles%\Mythodikal Anti-Virus\` with a Start menu shortcut under `Mythodikal Anti-Virus`. Uninstall via **Settings → Apps → Installed apps → Mythodikal Anti-Virus**.

The published `latest.json` and per-bundle `.sig` files on the GitHub Release are ed25519 signatures consumed by the in-app auto-updater (Tauri Updater plugin, FR-152), **not** Authenticode signatures — Windows does not natively verify them. The in-app updater verifies them against the public key compiled into the binary, so subsequent updates are cryptographically authenticated end-to-end even though the original bundle is unsigned at the OS level.

If a sponsor ever covers an OV/EV cert, code-signing would land as a Phase 13 (donor) extra — never as a P0/P1 release-gate. Until then the workarounds above are the canonical path.

---

## Contributing

Mythodikal is a closed contribution model — no PRs accepted at this time, with two exceptions:

1. **Security disclosures.** See [`SECURITY.md`](SECURITY.md). Coordinated disclosure within 90 days. Hall-of-fame credit if requested.
2. **Translations of UI strings** once the localization scaffolding lands at v0.10. Translation contributions are accepted under a Contributor Agreement that grants Mythodikal the right to incorporate the translation into the product. The translation contributor receives credit and a free Pro license.

The closed contribution model exists because Mythodikal is opinionated — solo-architected, single-vision, source-visible-not-source-open. If you want to fork the philosophy: more power to you, build your own AV, take ideas freely. Just don't take the code.

---

## Third-party data feeds

Mythodikal pulls public threat intelligence from sources documented in [`THIRD-PARTY-DATA.md`](THIRD-PARTY-DATA.md). Headline:

- **abuse.ch family** — MalwareBazaar, ThreatFox, URLhaus. Free for commercial use [per their FAQ](https://bazaar.abuse.ch/faq/). Donations to abuse.ch encouraged.
- **NIST NSRL** — US Government public domain. Used as a goodware allowlist.
- **YARA-Forge `core` tier** — YARA rules with metadata licensing scrubbed in CI to permit only MIT / Apache-2.0 / BSD / CC0 / MPL-2.0.

Mythodikal does NOT use ClamAV signatures or libclamav (license incompatibility — see [`RESEARCH-DOSSIER.md`](RESEARCH-DOSSIER.md) § 3.4).

---

## Reporting a vulnerability

Email `mythodikalone@gmail.com`. PGP key TBD. Coordinated disclosure with a 90-day window. See [`SECURITY.md`](SECURITY.md).

---

## Contact

- Project: github.com/MikesRuthless12/mythodikal-av
- Maintainer email: `mythodikalone@gmail.com`
- Licensing inquiries: `mythodikalone@gmail.com`
- Security disclosures: `mythodikalone@gmail.com`
- Marketing site: `mythodikal.com` (live from Phase 10)

---

*Mythodikal Anti-Virus is a project of Mike Weaver. All Rights Reserved.*
