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

- **Fast.** A 1-million-file cold scan completes in under 4 minutes on a 2024-class consumer NVMe machine. The second scan, via NTFS USN journal delta, completes in under 5 seconds.
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

**Current state:** Phases 0, 1, 2, 3 are shipped. Phase 4 waves 1, 2, 3, 4, 5 are committed pre-tag — ETA, adaptive throttle, pause/resume, Shields kill-switch, Exclusions CRUD (incl. publisher kind), throughput chart, first-run flow, feed auto-updater, release pipeline + GH-Releases-signed Tauri Updater, dual-channel (engine vs database) update architecture, About page per-source definition counts, Settings → Updates dual pane, operator-mode live BLAKE3 partial-hash display, per-exclusion 24-hour quick-action, cross-platform publisher whitelist (Authenticode / codesign / GPG), and Tauri-plugin-autostart wiring all in the tree. Final wave 6 (system tray icon + menu — TASK-158) plus the v0.4.0 launch checklist (TASK-049 sign-off, screenshots, benchmark rerun) gate the promotion from `[Unreleased]` to `v0.4.0`.

| Phase | Goal | Version | Status |
|---|---|---|---|
| 0 | Foundation & Setup | v0.0.x | ✅ Shipped |
| 1 | Engine Core | v0.1.x | ✅ Shipped |
| 2 | Detection Pipeline | v0.2.x | ✅ Shipped |
| 3 | UI Alpha | v0.3.x | ✅ Shipped |
| 4 | Linux MVP & Magic Moment | v0.4.x | 🟡 Wave 1 in-flight |
| 5 | Windows MFT Superpowers | v0.5.x | Pending |
| 6 | macOS Port (unsigned, see `docs/prd.md` § 1.5.3) | v0.6.x | Pending |
| 7 | YARA & Rule Manager | v0.7.x | Pending |
| 8 | Linux Real-time (fanotify daemon) | v0.8.x | Pending |
| 9 | macOS Real-time (FSEvents + opportunistic ESF NOTIFY) | v0.9.x | Pending |
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
