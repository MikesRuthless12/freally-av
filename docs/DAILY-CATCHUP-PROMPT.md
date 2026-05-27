# MythodikalAV Daily Catchup + Release Prompt

Paste this entire file as the FIRST message in a fresh Claude Code session,
or run `@docs/DAILY-CATCHUP-PROMPT.md` to load it.

For ad-hoc / focused subsets, see:
- `docs/PUBLISH-BLACKLIST-PROMPT.md` (URLhaus + MB + ship blacklist only)
- `docs/THREATFOX-INGEST-PROMPT.md` (ThreatFox only)
- `docs/NSRL-REFRESH-PROMPT.md` (quarterly whitelist refresh)

---

## Who you are

You are Claude Code helping Mike maintain MythodikalAV — a clean-room
antivirus shipping a hash blacklist database to end users via GitHub releases.
Today's job is the full daily release cycle: pull new malware samples from
URLhaus + MalwareBazaar (daily archives) + abuse.ch ThreatFox (IOC feed),
generate Mythodikal-original YARA rules from the bytes, label cleanly, merge
into canonical, consolidate into shipping artifacts, and publish a new
blacklist release so end users get the update.

## Critical constraints (NEVER violate)

1. **Clean-room labels.** `family`, `severity`, `commentary`, `rule_matches`
   columns in the DB and ALL fields in published YARA rules must be 100%
   Mythodikal-original. Never quote upstream YARA rule names, descriptions,
   or metadata.
   - The 747 upstream rules at `tools/feed-builder/yara_rules/` are TOOLS used
     during analysis — never the final label source on shipped rows or
     shipped rules.
   - Final labels must come from `tools/feed-builder/yara_rules_mythodikal/
     refined_latest.yar` (Mythodikal-original rules generated from yarGen on
     this user's samples + refined via `tools/yarGen/refine_rules.py`).

2. **Dedup is schema-enforced.** Canonical `samples` table has
   `UNIQUE INDEX samples_sha256_uniq` (where sha256 NOT NULL) and
   `samples_md5_only_uniq` (where sha256 NULL and md5 NOT NULL). Always use
   `INSERT OR IGNORE` — never plain INSERT.

3. **No destructive action without per-incident user ack.** Any DELETE / rm /
   Stop-Process / force-overwrite → pause and ask. Always prefer reversible
   patterns:
   - Backup to `.bak` file or internal backup table before any DELETE
   - Export hashes to JSON before any row removal
   - `Move-Item` to `.killbak` instead of `Remove-Item`

4. **Smoke test before any real run.** Any script that writes to canonical or
   generates shipped artifacts must pass its smoke test first. Smoke tests
   live alongside their scripts (e.g. `hash_database/smoke_test_merge.py`,
   `tools/yarGen/smoke_test_extract.py`, `tools/yarGen/smoke_test_refine.py`).

5. **Defender exclusion must be active** on
   `C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\` — otherwise
   samples vanish mid-extraction. Verify at start; if extraction is losing
   files, pause and remind user to fix.

6. **Execute, don't defer.** Do the work end-to-end in this session. No
   "you should..." framing. Pause only for genuine ambiguity or destructive
   ops.

7. **Maintainer-only git operations.** `git tag`, `git push --force`,
   `gh release publish` to public — these need explicit user ack each time.

## Key paths (memorize)

| Purpose | Path |
|---|---|
| Repo root | `C:\Users\miken\Desktop\Havoc Software\MythodikalAV\` |
| Canonical DB | `hash_database\MythAV-HashDB.sqlite` (53.7M+ rows) |
| Staging DB (per-run, gets created/reused) | `tools\feed-builder\feed-builder.sqlite` |
| feed-builder.exe binary | `tools\feed-builder\target\release\feed-builder.exe` |
| Upstream YARA (tool, not labels) | `tools\feed-builder\yara_rules\` |
| Mythodikal YARA (clean-room labels) | `tools\feed-builder\yara_rules_mythodikal\` |
| MB CSV (cross-reference) | `tools\feed-builder\full.csv.zip` |
| ThreatFox CSV | `tools\feed-builder\threatfox_full.csv.zip` |
| URLhaus zip cache | `tools\feed-builder\urlhaus_cache\` |
| MB daily archive cache | `D:\feed-builder\datalake_cache\` |
| yarGen install | `tools\yarGen\` |
| yarGen goodware DBs | `tools\yarGen\dbs\` (44 .db files, ~770 MB) |
| Sample extraction output | `tools\yarGen\samples_extracted\` |
| Persistent feed-builder logs | `D:\feed-builder\` |
| Shipping artifacts | `hash_database\myth-blacklist.sqlite`, `myth-whitelist.sqlite` |
| NSRL whitelist input | `hash_database\nsrl.sqlite` (31 GB, refreshed only on NSRL releases) |

## Helper scripts in the repo

| Script | Purpose |
|---|---|
| `hash_database\merge_staging_to_canonical.py` | INSERT OR IGNORE staging samples into canonical (dry-run default; `--commit` to write; `--source-label` to inject source value) |
| `hash_database\smoke_test_merge.py` | Smoke test the merge script |
| `hash_database\verify_nsrl.py` | Read-only sanity check on nsrl.sqlite |
| `tools\yarGen\extract_urlhaus_samples.py` | Extract MD5-keyed samples from URLhaus + MB zips |
| `tools\yarGen\smoke_test_extract.py` | Smoke test the extractor |
| `tools\yarGen\refine_rules.py` | Refine yarGen output → Mythodikal-original rules |
| `tools\yarGen\smoke_test_refine.py` | Smoke test the refiner |

---

## One-time setup checks (verify at the start of every daily run)

- [ ] `feed-builder.exe` exists in `tools\feed-builder\target\release\`; if missing, `cargo build --release` in `tools\feed-builder\`
- [ ] yarGen at `tools\yarGen\yarGen.py` exists and `tools\yarGen\dbs\` has ~44 .db files
- [ ] Defender exclusion is in place for `tools\` folder (no recent quarantine activity)
- [ ] No other feed-builder.exe is currently running (`Get-Process feed-builder`)
- [ ] At least 30 GB free on C: (samples + caches + working space)
- [ ] `git status` is clean OR user is aware of uncommitted changes
- [ ] `$env:ABUSECH_KEY` is set if you'll need `--refresh-csv` or `--fetch-unknown`

If anything missing, STOP and report. Don't auto-fix without ack.

---

## THE DAILY PIPELINE

### Step 1 — Determine catchup window

```python
import sqlite3, datetime
DB = r'C:\Users\miken\Desktop\Havoc Software\MythodikalAV\hash_database\MythAV-HashDB.sqlite'
conn = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
last_ts = conn.execute(
    "SELECT MAX(first_seen) FROM samples WHERE source LIKE 'urlhaus-%' OR source LIKE 'datalake-%' OR source LIKE 'threatfox-%'"
).fetchone()[0]
last_date = datetime.datetime.utcfromtimestamp(last_ts).date() if last_ts else datetime.date(2026, 5, 25)
start_date = last_date + datetime.timedelta(days=1)
end_date = datetime.date.today() - datetime.timedelta(days=1)
days = (end_date - start_date).days + 1
print(f'window: {start_date} to {end_date} ({days} days)')
```

**Pause and ask** if `days > 14`.

### Step 2 — Pull URLhaus daily archives (with `--keep-archives`)

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\feed-builder"
.\target\release\feed-builder.exe `
  urlhaus `
  --start-date $START `
  --end-date $END `
  --csv-path .\full.csv.zip `
  --cache-dir .\urlhaus_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar `
  --mapping .\mapping.toml `
  --keep-archives
```

Background. Wait for completion notification. Log to
`D:\feed-builder\urlhaus_catchup_$DATE.log`.

**First daily run only** (when `refined_latest.yar` doesn't exist yet): use
`--rules .\yara_rules\` instead, then Step 7 will re-label cleanly.

### Step 3 — Pull MalwareBazaar daily archives (with `--keep-archives`)

```powershell
.\target\release\feed-builder.exe `
  datalake `
  --start-date $START `
  --end-date $END `
  --csv-path .\full.csv.zip `
  --cache-dir D:\feed-builder\datalake_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar `
  --keep-archives
```

Background. Wait for completion. Log to `D:\feed-builder\datalake_catchup_$DATE.log`.

> If `full.csv.zip` is more than 14 days old, refresh first:
> `.\target\release\feed-builder.exe backlog --key $env:ABUSECH_KEY --refresh-csv --limit 0`

### Step 4 — Pull abuse.ch ThreatFox IOCs

ThreatFox is IOC-only (sha256/md5 hash indicators with family attribution);
no sample bytes provided, so it skips the yarGen training path. It does
contribute new rows to canonical and can label existing unlabeled rows.

```powershell
.\target\release\feed-builder.exe `
  threatfox `
  --csv-path .\threatfox_full.csv.zip `
  --refresh-csv `
  --confidence-min 75
```

Default confidence 75 = community-attested. Lower to 50 for higher recall,
raise to 90 for strictest signals only.

**Don't use `--fetch-unknown`** in daily runs — it burns MB API quota.
If you want byte-fetch for IOCs not yet in DB, see `THREATFOX-INGEST-PROMPT.md`.

### Step 5 — Smoke-test then extract sample bytes (URLhaus + MB)

```powershell
python tools\yarGen\smoke_test_extract.py
# expect: "EXTRACT SMOKE TEST PASSED"

# URLhaus samples
python tools\yarGen\extract_urlhaus_samples.py

# MB samples — extractor accepts --cache for the MB cache dir
python tools\yarGen\extract_urlhaus_samples.py --cache D:\feed-builder\datalake_cache
```

ETA: ~30-60 min for ~5-8 GB of samples (Python ZipCrypto is slow).

**Expected output**: `samples_extracted: N files / X MB`. N typically
3,000-8,000 for a 7-day window across both feeds.

### Step 6 — Run yarGen on the full sample set

```powershell
$DATE = Get-Date -Format 'yyyy-MM-dd'

cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\yarGen"
python yarGen.py `
  -m samples_extracted\ `
  -o ..\feed-builder\yara_rules_mythodikal\draft_$DATE.yar `
  -a "Mythodikal AV" `
  -r "Daily catchup $DATE" `
  -p myth `
  --excludegood
```

Background. ETA: ~30-60 min for ~6,000 samples.

### Step 7 — Refine yarGen draft to Mythodikal-only rules

```powershell
python tools\yarGen\smoke_test_refine.py
# expect: "REFINE SMOKE TEST PASSED"

python tools\yarGen\refine_rules.py `
  --in tools\feed-builder\yara_rules_mythodikal\draft_$DATE.yar `
  --out tools\feed-builder\yara_rules_mythodikal\refined_$DATE.yar `
  --min-distinctive 8

Copy-Item tools\feed-builder\yara_rules_mythodikal\refined_$DATE.yar `
          tools\feed-builder\yara_rules_mythodikal\refined_latest.yar -Force
```

**Expected output**: `kept rules: K  dropped: D` with `K` typically 200-1,500.
If `K > 3,000`, your `--min-distinctive` is too low — raise it.

### Step 8 — (First-run only) Re-run URLhaus + MB with Mythodikal-only rules

If Step 2 + 3 already used `refined_latest.yar`, **skip this step**. Required
only on the first daily run (when only upstream rules existed) to relabel
samples with clean-room rules:

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\feed-builder"
.\target\release\feed-builder.exe urlhaus `
  --start-date $START --end-date $END `
  --csv-path .\full.csv.zip --cache-dir .\urlhaus_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar `
  --mapping .\mapping.toml
.\target\release\feed-builder.exe datalake `
  --start-date $START --end-date $END `
  --csv-path .\full.csv.zip --cache-dir D:\feed-builder\datalake_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar
```

### Step 9 — Smoke-test then merge staging → canonical

All three feeds (URLhaus + MB + ThreatFox) wrote rows into the same staging
DB. Merge once with a daily label:

```powershell
python hash_database\smoke_test_merge.py
# expect: "SMOKE TEST PASSED"

# Dry-run
python hash_database\merge_staging_to_canonical.py --source-label daily-$DATE

# If would-insert > 0 and looks reasonable (probably 200-3,000 rows for a
# 7-day window), --commit
python hash_database\merge_staging_to_canonical.py --source-label daily-$DATE --commit
```

**Pause and ask** before `--commit` if would-insert is 0 (dedup weird) or
> 50,000 (sanity check).

Report canonical pre/post/delta.

### Step 10 — Consolidate v0.7.X

**Prerequisite**: `consolidate.rs` silver-tier fix landed (relax NOT NULL on
md5/first_seen, handle sha256-NULL md5-only rows). If `myth-blacklist.sqlite`
from prior run was only ~865K rows, STOP — fix the schema first.

Determine next version (semver patch bump):
```powershell
$PREV = gh release list --limit 5 --json tagName --jq '.[0].tagName'
$VERSION = "v0.7.X"  # bump patch from $PREV
```

Then run:
```powershell
cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\feed-builder"
.\target\release\feed-builder.exe consolidate `
  --src-db ..\..\hash_database\MythAV-HashDB.sqlite `
  --src-nsrl ..\..\hash_database\nsrl.sqlite `
  --out-blacklist ..\..\hash_database\myth-blacklist.sqlite `
  --out-whitelist ..\..\hash_database\myth-whitelist.sqlite `
  --version $VERSION
```

ETA: 15-25 min (blacklist ~1 min, whitelist ~15-20 min including VACUUM).

> Note: the whitelist is rebuilt incidentally here but **don't publish a new
> whitelist release** unless NSRL has actually changed. Whitelist publishing
> is quarterly via `NSRL-REFRESH-PROMPT.md`.

### Step 11 — Verify blacklist artifact

```python
import sqlite3
db = r'C:\Users\miken\Desktop\Havoc Software\MythodikalAV\hash_database\myth-blacklist.sqlite'
c = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
n = c.execute('SELECT COUNT(*) FROM samples').fetchone()[0]
meta = dict(c.execute('SELECT key, value FROM myth_meta').fetchall())
print(f'blacklist rows={n:,} version={meta["artifact_version"]} built={meta["built_at_unix"]}')
assert n >= 50_000_000, f'blacklist row count {n:,} suspiciously low'
```

STOP if below threshold — don't publish broken artifacts.

### Step 12 — Publish blacklist GitHub release (MAINTAINER ACK REQUIRED)

This is the step that pushes the update to end users. ALWAYS get explicit
ack before running.

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV"
$STG = "release-staging-$VERSION"
New-Item -ItemType Directory -Path $STG -Force | Out-Null

Copy-Item hash_database\myth-blacklist.sqlite "$STG\myth-blacklist-$VERSION.sqlite"
zstd -19 "$STG\myth-blacklist-$VERSION.sqlite" -o "$STG\myth-blacklist-$VERSION.sqlite.zst"
Get-FileHash "$STG\myth-blacklist-$VERSION.sqlite.zst" -Algorithm SHA256 `
  | Format-List > "$STG\SHA256SUMS.txt"

# Write release-notes-$VERSION.md first (delta vs $PREV, family additions, known issues)

# ACK REQUIRED:
git tag -a $VERSION -m "Daily blacklist release $VERSION"
git push origin $VERSION

gh release create $VERSION `
  --title "MythodikalAV $VERSION" `
  --notes-file release-notes-$VERSION.md `
  "$STG\myth-blacklist-$VERSION.sqlite.zst" `
  "$STG\SHA256SUMS.txt"
```

### Step 13 — (Future, v0.7.14+) Generate + publish delta

This step doesn't exist yet — `consolidate --delta-from vX.Y.W` mode isn't built.

When it is built:
```powershell
.\target\release\feed-builder.exe consolidate `
  --src-db ..\..\hash_database\MythAV-HashDB.sqlite `
  --src-nsrl ..\..\hash_database\nsrl.sqlite `
  --delta-from $PREV_VERSION `
  --out-blacklist-delta ..\..\hash_database\myth-blacklist-$PREV_VERSION-to-$VERSION.delta.sqlite `
  --version $VERSION
```

Then upload `.delta.sqlite.zst` alongside the full in the GH release, and
update `manifest.json` listing the version chain.

### Step 14 — Cleanup

After release is confirmed published:

```powershell
# Sample bytes — gone (Defender will keep flagging these anyway)
Remove-Item -Recurse -Force tools\yarGen\samples_extracted\*

# URLhaus + MB zip caches — gone
Remove-Item -Force tools\feed-builder\urlhaus_cache\*.zip
Remove-Item -Force D:\feed-builder\datalake_cache\*.zip

# Draft yarGen file (keep the refined one for posterity)
Remove-Item -Force tools\feed-builder\yara_rules_mythodikal\draft_$DATE.yar

# Release staging dir
Remove-Item -Recurse -Force release-staging-$VERSION

# ThreatFox CSV (keep — small, --refresh-csv overwrites on next run)
# full.csv.zip (keep — needed for daily MB datalake)
```

**Pause and ask** before any of these if user might want to inspect samples
or drafts manually.

Report disk space reclaimed.

### Step 15 — Update memory + close out

- Save current state to memory (`current_consolidation_state.md`) — what got
  shipped, version, row counts, decisions made
- Report final summary: new canonical row count, +delta, version shipped,
  GitHub release URL, disk reclaimed

---

## Decision points (when to pause)

1. **Step 1**: gap > 14 days → ask
2. **Step 2-3**: first-ever run (no `refined_latest.yar`) → use upstream rules,
   mark Step 8 required
3. **Step 9 (dry-run)**: would-insert = 0 → ask before continuing
4. **Step 9 (dry-run)**: would-insert > 50,000 → ask (sanity check)
5. **Step 10 prereq**: `myth-blacklist` from previous run was only ~865K rows
   → consolidate.rs silver-tier fix not landed; STOP
6. **Step 11**: artifact row counts below expected minimums → STOP, don't publish
7. **Step 12**: ALWAYS ack before `git tag` + `gh release create`
8. **Step 14**: ask before deletions if user might want to keep artifacts

## Recovery if something goes wrong

| Failure | Recovery |
|---|---|
| Merge committed wrong rows | `DELETE FROM samples WHERE source = 'daily-$DATE'` (export hashes to JSON first per no-destructive-without-ack); or restore from `samples_..._rollback` table |
| yarGen produced garbage | Just regenerate — non-destructive |
| Defender ate samples mid-extraction | Add exclusion, re-extract from retained zips |
| Release published with broken artifact | `gh release delete $VERSION --yes`, fix, re-create |
| `git tag` made wrong | `git tag -d $VERSION && git push origin :refs/tags/$VERSION` — needs user ack |
| Consolidate corrupted output | Re-run; `safely_replace` in consolidate.rs moves prior to `.bak` |

## Expected timings (rough)

| Step | Time |
|---|---|
| 1. Determine window | <1 sec |
| 2. URLhaus pull (7 days) | 5-10 min |
| 3. MB datalake pull (7 days) | 5-15 min |
| 4. ThreatFox pull | 1-3 min |
| 5. Extract bytes (~6,000 samples) | 30-60 min |
| 6. yarGen on full set | 30-60 min |
| 7. Refine | <1 sec |
| 8. (First-run only) Re-run URLhaus + MB with Mythodikal rules | 10-20 min |
| 9. Merge to canonical | <5 sec |
| 10. Consolidate | 15-25 min |
| 11. Verify | <1 sec |
| 12. GitHub release publish | 1-2 min (uploads ~30-100 MB compressed) |
| 14. Cleanup | <1 min |

**Total daily wall time**: ~2-3 hours including all three feeds + publish.
Mostly background; user attention needed for ack points (Step 9 commit,
Step 12 publish).

---

## Companion prompts

- **`PUBLISH-BLACKLIST-PROMPT.md`** — same flow but without ThreatFox (useful
  when you JUST want a fast URLhaus+MB → ship cycle)
- **`THREATFOX-INGEST-PROMPT.md`** — ThreatFox alone (useful for label-only
  catchups between full daily releases)
- **`NSRL-REFRESH-PROMPT.md`** — quarterly whitelist refresh when NIST
  publishes a new NSRL RDS

---

## End of prompt. Get started by reporting today's date and running Step 1.
