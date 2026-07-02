# Third-Party Data Sources

Freally Anti-Virus pulls public threat intelligence and goodware allowlists from the sources documented below. Every source is selected for **commercial redistribution-friendly licensing** so that compiled binaries shipped under `LICENSE.md` are clean. The alternatives that were considered and rejected are summarized at the end of this document.

---

## Active sources

### abuse.ch (MalwareBazaar, ThreatFox, URLhaus)

| | |
|---|---|
| Vendor | abuse.ch (Bern University of Applied Sciences) |
| Used for | Hash blacklist (MalwareBazaar bulk dumps + ThreatFox JSON), C2 IOC matching (ThreatFox), URL hashes (URLhaus) |
| License posture | **Free for commercial use** per the [abuse.ch FAQ](https://bazaar.abuse.ch/faq/). Donations to abuse.ch are encouraged and the project has done so. |
| Update frequency | Hourly (mirrored to our feed CDN) |
| Freally entry points | `crates/freallykernel/src/updater/abusech.rs` (TASK-022); `crates/freallykernel/src/detect/hash_blacklist.rs` (TASK-020); `crates/freallykernel/src/detect/net_ioc.rs` (TASK-148) |

### NIST NSRL (National Software Reference Library)

| | |
|---|---|
| Vendor | National Institute of Standards and Technology (NIST), U.S. Department of Commerce |
| Used for | Goodware allowlist — known-good system-binary hashes that are skipped during scans |
| License posture | **U.S. Government public domain.** No license restrictions. Citation appreciated. |
| Update frequency | NIST publishes RDS dumps quarterly; we mirror with each release. |
| Freally entry points | `crates/freallykernel/src/updater/nsrl.rs` (TASK-023); `crates/freallykernel/src/detect/goodware_allowlist.rs` (TASK-021) |

### YARA-Forge — `core` tier only

| | |
|---|---|
| Vendor | The YARA-Forge community |
| Used for | Bundled YARA-rule pack covering common consumer malware families |
| License posture | YARA-Forge aggregates rules under multiple licenses. We ship **only** the `core` tier and additionally **license-scrub in CI** (`scripts/license-scrub-yara.ts`, TASK-066/067). Rules whose metadata license is **not** one of MIT / Apache-2.0 / BSD / CC0 / MPL-2.0 / Unicode-3.0 are **rejected at build time**. |
| Update frequency | Pinned per release; nightly drift check posts a GitHub issue if upstream relicenses. |
| Freally entry points | `crates/freallykernel/src/updater/yara_forge.rs` (TASK-066); `crates/freallykernel/src/detect/yara_engine.rs` (TASK-065); `.github/workflows/license-scrub.yml` (TASK-067) |

### loldrivers.io

| | |
|---|---|
| Vendor | The LOLDrivers community project |
| Used for | BYOVD (Bring-Your-Own-Vulnerable-Driver) blocklist — hashes of known-abused signed drivers |
| License posture | Permissive aggregator. Ingested as a hash blacklist; rule text is not redistributed. |
| Update frequency | Daily JSON pull |
| Freally entry points | `crates/freallykernel/src/updater/loldrivers.rs` (TASK-139); `crates/freallykernel/src/detect/byovd.rs` |

### LOLBAS (Living Off The Land Binaries and Scripts)

| | |
|---|---|
| Vendor | The LOLBAS Project |
| Used for | Suspicious parent-child invocation chains (e.g., Office spawning `certutil`, `mshta`, `wmic`) |
| License posture | MIT-licensed YAML index. Indexed by hash, not redistributed verbatim. |
| Freally entry points | `crates/freallykernel/src/updater/lolbas.rs` (TASK-146); `crates/freallykernel/src/detect/lolbin.rs` |

### OSV.dev malicious package feed

| | |
|---|---|
| Vendor | Google / OpenSSF |
| Used for | Supply-chain detection — npm / PyPI / Cargo malicious-package match |
| License posture | OSV data is licensed CC-BY-4.0; we consume the JSON feed only, do not embed verbatim records into compiled binaries. |
| Freally entry points | `crates/freallykernel/src/updater/osv.rs` (TASK-147); `crates/freallykernel/src/detect/supply_chain.rs` |

---

## Sources we considered and rejected

| Source | Why rejected |
|---|---|
| ClamAV signatures (`main.cvd`, `daily.cvd`) | License: GPLv2 — incompatible with our closed binary redistribution. |
| Microsoft Defender threat feed | Closed source, no public API for third-party AVs. |
| Commercial threat-intel APIs (Recorded Future, Mandiant, etc.) | Cost and per-seat licensing model conflict with our free-for-everyone guarantee. |
| YARA-Forge `extended` and `full` tiers | Contain rules with metadata licenses that fail our scrubber (GPL, AGPL, unspecified). Users may opt into individual rules via the User Rule Manager (TASK-068). |

---

## How license-scrubbing works in CI

`scripts/license-scrub-yara.ts` (TASK-066, TASK-067) parses every YARA rule's `meta:` block, extracts the declared license, and matches it against the allow-list (`MIT | Apache-2.0 | BSD-* | CC0-* | MPL-2.0 | Unicode-3.0`). Any rule with a missing, ambiguous, or denied license is **rejected at build time** — the CI job fails the release. The job runs nightly so we catch upstream relicensing within 24 hours.

Rust dependency licenses are independently checked by `cargo-deny` per `deny.toml` and `.github/workflows/ci.yml`.

---

## How to report a feed concern

If you believe a third-party source listed above has changed its license terms, or is being misrepresented here, please email `freallyone@gmail.com` with the subject `THIRD-PARTY-DATA:` and a link to the upstream notice.

---

*Last revised: 2026-05-09.*
