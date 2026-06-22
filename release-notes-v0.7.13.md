# MythodikalAV v0.7.13

First public release of the Mythodikal hash database artifacts — built locally on the maintainer's rig and shipped here for end users.

## What's in this release

Two SQLite databases for use by the MythodikalAV runtime, **split into ~1.9 GB parts** because GitHub release assets are capped at 2 GiB per file:

| Artifact | Rows | Compressed total | Part files | Required? |
|---|---:|---:|---:|---|
| `myth-blacklist-v0.7.13.sqlite.zst` | **53,714,944** | **3.40 GB** | 2 parts (`.part-001`, `.part-002`) | **Required** — malware hash database |
| `myth-whitelist-v0.7.13.sqlite.zst` | **72,015,285** | **11.71 GB** | 7 parts (`.part-001`..`.part-007`) | **Optional** — NIST NSRL known-good hashes (skip-scan known-clean files for 10-50× faster system scans) |

Helper files:
- `SHA256SUMS-parts.txt` — verify each downloaded part
- `SHA256SUMS-full.txt` — verify reassembled (post-cat) files
- `reassemble.ps1` — Windows PowerShell helper
- `reassemble.sh` — Unix bash helper
- `README-assembly.md` — detailed reassembly instructions

## Quick start

```powershell
# Windows
./reassemble.ps1
```

```bash
# Unix
chmod +x reassemble.sh && ./reassemble.sh
```

Or manually:

```cmd
copy /b myth-blacklist-v0.7.13.sqlite.zst.part-* myth-blacklist-v0.7.13.sqlite.zst
zstd -d myth-blacklist-v0.7.13.sqlite.zst
```

End users only need the **blacklist** (required). The whitelist is optional — skip it if you don't want a 30 GB local NSRL DB. See `README-assembly.md` in the release for full instructions.

## Blacklist content (53.7M rows)

Every row is 100% Mythodikal-attributed:
- **`family`**: Mythodikal-original taxonomy (`myth_malware`, `myth_banker_alpha`, `myth_rat_alpha`, `myth_ransom_*`, etc.). Industry-coined family names (Emotet/Heodo, Mirai, AgentTesla, TrickBot, etc.) are renamed to Mythodikal-coined equivalents via behavior categorization. Long-tail obscure families get deterministic `myth_threat_<hash>` names.
- **`commentary`**: Mythodikal-original template — no upstream rule text quoted, ever.
- **`rule_matches`**: count only (e.g. `{"count": 3}`), never upstream rule names.
- **`severity`**: 1 (low) / 2 (medium) / 3 (high), derived from VirusTotal coverage + size + match count via Mythodikal's severity formula.

Coverage tiers:
- **Gold** (871,729 rows): high-confidence labeled samples with full hash + family + commentary
- **Silver** (52,843,215 rows): bulk-import hashes from VirusShare-style crawls, MalwareBazaar full CSV, academic datasets (SOREL/EMBER/BODMAS). Many are md5-only or sha256-only — both supported.

Hash columns: sha256 + md5 + sha1 + sha512 + blake3 + crc32 (whichever are known per row). Lookups by any of those work.

Provenance of underlying hashes:
- VirusShare crawls (legacy, sha256 facts)
- MalwareBazaar daily archives (abuse.ch)
- URLhaus daily archives (abuse.ch)
- ThreatFox IOCs (abuse.ch)
- SOREL-20M (Sophos academic)
- EMBER (Elastic academic)
- BODMAS (UIUC academic)
- Recent catchup window: 2026-05-15 to 2026-05-25

Hash values themselves are non-copyrightable facts (*Feist v. Rural*); MythodikalAV's contribution is the labels + commentary + taxonomy.

## Whitelist content (72M rows)

Direct copy of NIST NSRL RDSv3 Modern-Minimal release 2026.03.1 (March 2026), reshaped into a Mythodikal schema. NSRL is published by NIST under 17 U.S.C. § 105 (work of the US government — public domain, freely redistributable).

Per-OS distribution:
- windows: 30.6M (42.5%)
- linux: 19.5M (27.1%)
- macos: 2.93M (4.1%)
- multi-OS combos + NULL: ~19M

## How to verify + use

```powershell
# Verify download integrity
Get-FileHash myth-blacklist-v0.7.13.sqlite.zst -Algorithm SHA256
# compare to value in SHA256SUMS.txt

# Decompress (requires zstd: choco install zstandard, brew install zstd, etc.)
zstd -d myth-blacklist-v0.7.13.sqlite.zst

# Result: myth-blacklist-v0.7.13.sqlite (~21 GB)
# Place where the MythodikalAV runtime expects it.
```

## What's NOT in this release

- **Delta updates**: not yet implemented. Every release is currently a full snapshot. Coming in v0.7.14+.
- **Cloud reputation lookup**: by design — MythodikalAV is offline-first / zero-cost / no telemetry.

## Notes for maintainers

- Built with feed-builder.exe (silver-tier-inclusive consolidate landed this release; previous builds dropped 52M+ silver-tier rows due to a strict NOT NULL schema mismatch).
- 100% Mythodikal-attribution coverage on canonical achieved via `bulk_label_pass.py` (commentary + severity) + `family_normalize.py` (taxonomy renaming).
- Blacklist build time: ~30 min for 53.7M rows. Whitelist build time: ~45 min for 72M rows including VACUUM.

## License

- Mythodikal-authored labels (family / commentary / severity / rule_matches / taxonomy): © MythodikalAV. All rights reserved.
- Hash values: non-copyrightable facts (*Feist v. Rural*). Free to use.
- NSRL whitelist content: public domain per 17 U.S.C. § 105.
