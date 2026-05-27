# Publish-Blacklist Prompt (URLhaus + MalwareBazaar)

Focused subset of `DAILY-CATCHUP-PROMPT.md` for when you JUST want to pull new
samples from URLhaus + MalwareBazaar daily archives, label cleanly, merge into
canonical, and republish the blacklist artifact. **No NSRL refresh. No ThreatFox.
No whitelist republish.**

For the full daily release cycle (URLhaus + MB + ThreatFox + consolidate +
publish both artifacts), use `DAILY-CATCHUP-PROMPT.md` instead.

---

## You are Claude Code

Your job today: pull URLhaus + MalwareBazaar samples for the catchup window,
generate Mythodikal-original YARA rules from the bytes, re-label cleanly, merge
into the canonical hash DB, run consolidate, and publish a new blacklist release
to GitHub for end users.

**Read the "Critical constraints", "Key paths", and "Helper scripts" sections of
`docs/DAILY-CATCHUP-PROMPT.md` first** — those apply here too. The clean-room
labeling rule (`refined_latest.yar` only, never `yara_rules/` for label gen),
dedup-via-UNIQUE-indexes, smoke-test-before-real-run, no-destructive-without-ack,
Defender exclusion, and execute-don't-defer all apply.

---

## Pipeline

### Step 1 — Determine catchup window

```python
import sqlite3, datetime
DB = r'C:\Users\miken\Desktop\Havoc Software\MythodikalAV\hash_database\MythAV-HashDB.sqlite'
conn = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
last_ts = conn.execute(
    "SELECT MAX(first_seen) FROM samples WHERE source LIKE 'urlhaus-%' OR source LIKE 'datalake-%'"
).fetchone()[0]
last_date = datetime.datetime.utcfromtimestamp(last_ts).date() if last_ts else datetime.date(2026, 5, 25)
start = last_date + datetime.timedelta(days=1)
end = datetime.date.today() - datetime.timedelta(days=1)
print(f'window: {start} to {end} ({(end - start).days + 1} days)')
```

Pause and ask if `days > 14`.

### Step 2 — URLhaus pull with `--keep-archives`

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\feed-builder"
.\target\release\feed-builder.exe `
  urlhaus `
  --start-date $START --end-date $END `
  --csv-path .\full.csv.zip `
  --cache-dir .\urlhaus_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar `
  --mapping .\mapping.toml `
  --keep-archives
```

Background. Wait for completion.

### Step 3 — MalwareBazaar daily archives

```powershell
.\target\release\feed-builder.exe `
  datalake `
  --start-date $START --end-date $END `
  --csv-path .\full.csv.zip `
  --cache-dir D:\feed-builder\datalake_cache `
  --rules .\yara_rules_mythodikal\refined_latest.yar `
  --keep-archives
```

Background. Wait for completion.

> If `full.csv.zip` is more than 14 days old, refresh first:
> `.\target\release\feed-builder.exe backlog --key $env:ABUSECH_KEY --refresh-csv --limit 0`

### Step 4 — Extract sample bytes from both caches

```powershell
python tools\yarGen\smoke_test_extract.py
python tools\yarGen\extract_urlhaus_samples.py
# extract MB caches too (extractor accepts --cache):
python tools\yarGen\extract_urlhaus_samples.py --cache D:\feed-builder\datalake_cache
```

### Step 5 — Run yarGen + refine to Mythodikal-only rules

```powershell
$DATE = Get-Date -Format 'yyyy-MM-dd'

cd C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\yarGen
python yarGen.py `
  -m samples_extracted\ `
  -o ..\feed-builder\yara_rules_mythodikal\draft_$DATE.yar `
  -a "Mythodikal AV" `
  -r "Daily catchup $DATE" `
  -p myth `
  --excludegood

python smoke_test_refine.py
python refine_rules.py `
  --in ..\feed-builder\yara_rules_mythodikal\draft_$DATE.yar `
  --out ..\feed-builder\yara_rules_mythodikal\refined_$DATE.yar `
  --min-distinctive 8

Copy-Item ..\feed-builder\yara_rules_mythodikal\refined_$DATE.yar `
          ..\feed-builder\yara_rules_mythodikal\refined_latest.yar -Force
```

### Step 6 — Re-run URLhaus + MB with Mythodikal-only rules

(only needed if Step 2/3 used upstream rules; otherwise skip)

### Step 7 — Smoke-test then merge staging → canonical

```powershell
python hash_database\smoke_test_merge.py

# URLhaus rows
python hash_database\merge_staging_to_canonical.py `
  --source-label urlhaus-catchup-$DATE
# If reasonable, --commit:
python hash_database\merge_staging_to_canonical.py `
  --source-label urlhaus-catchup-$DATE --commit

# MalwareBazaar rows (same staging, different source label per ingest)
# (Actually they're in the same staging DB; commit again with different label
# only if you ran datalake into a separate staging DB)
```

Report canonical pre/post/delta.

### Step 8 — Consolidate v0.7.X

**Prerequisite**: `consolidate.rs` silver-tier fix must be landed. If
`myth-blacklist.sqlite` from prior run was only ~865K rows, STOP — fix the
schema first.

```powershell
$PREV = (gh release list --limit 1 --json tagName --jq '.[0].tagName')
$VERSION = "v0.7.X"  # bump patch from $PREV

cd C:\Users\miken\Desktop\Havoc Software\MythodikalAV\tools\feed-builder
.\target\release\feed-builder.exe consolidate `
  --src-db ..\..\hash_database\MythAV-HashDB.sqlite `
  --src-nsrl ..\..\hash_database\nsrl.sqlite `
  --out-blacklist ..\..\hash_database\myth-blacklist.sqlite `
  --out-whitelist ..\..\hash_database\myth-whitelist.sqlite `
  --version $VERSION
```

Wait ~15-25 min.

### Step 9 — Verify blacklist artifact

```python
import sqlite3
db = r'C:\Users\miken\Desktop\Havoc Software\MythodikalAV\hash_database\myth-blacklist.sqlite'
c = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
n = c.execute('SELECT COUNT(*) FROM samples').fetchone()[0]
meta = dict(c.execute('SELECT key, value FROM myth_meta').fetchall())
print(f'rows={n:,} version={meta["artifact_version"]}')
assert n >= 50_000_000, f'blacklist row count {n} suspiciously low'
```

STOP if below threshold — don't publish broken artifacts.

### Step 10 — Publish blacklist GitHub release (MAINTAINER ACK REQUIRED)

```powershell
cd C:\Users\miken\Desktop\Havoc Software\MythodikalAV
$STG = "release-staging-$VERSION"
New-Item -ItemType Directory -Path $STG -Force | Out-Null

Copy-Item hash_database\myth-blacklist.sqlite "$STG\myth-blacklist-$VERSION.sqlite"
zstd -19 "$STG\myth-blacklist-$VERSION.sqlite" -o "$STG\myth-blacklist-$VERSION.sqlite.zst"
Get-FileHash "$STG\myth-blacklist-$VERSION.sqlite.zst" -Algorithm SHA256 `
  | Format-List > "$STG\SHA256SUMS.txt"

# Write release-notes-$VERSION.md first (row count delta vs $PREV, family additions)

# Ack required before this:
git tag -a $VERSION -m "Daily blacklist release $VERSION"
git push origin $VERSION

gh release create $VERSION `
  --title "MythodikalAV $VERSION (blacklist only)" `
  --notes-file release-notes-$VERSION.md `
  "$STG\myth-blacklist-$VERSION.sqlite.zst" `
  "$STG\SHA256SUMS.txt"
```

### Step 11 — Cleanup

```powershell
Remove-Item -Recurse -Force tools\yarGen\samples_extracted\*
Remove-Item -Force tools\feed-builder\urlhaus_cache\*.zip
Remove-Item -Force D:\feed-builder\datalake_cache\*.zip
Remove-Item -Force tools\feed-builder\yara_rules_mythodikal\draft_$DATE.yar
Remove-Item -Recurse -Force release-staging-$VERSION
```

Ask before deleting if user might want to keep anything.

### Step 12 — Report + save state

- Canonical row count + delta
- Released $VERSION URL
- Disk reclaimed
- Save current state to memory if anything notable

---

## Quick-reference variations

| If you want… | …do this |
|---|---|
| URLhaus only (skip MB) | Skip Step 3, skip MB extraction in Step 4 |
| MB only (skip URLhaus) | Skip Step 2, skip URLhaus extraction in Step 4 |
| No new release (just merge into canonical, defer publish) | Stop after Step 7 |
| Test without publishing | Run all steps but skip Step 10 |
