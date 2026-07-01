# ThreatFox Ingest Prompt

Pull abuse.ch ThreatFox community IOC feed into canonical. ThreatFox is an
IOC (indicator-of-compromise) feed — gives sha256/md5/sha1 hash indicators
attributed to malware families, but DOES NOT provide sample bytes for new
YARA rule generation. Use it to **label** existing canonical rows + add
high-confidence IOCs.

**Read constraints section of `docs/DAILY-CATCHUP-PROMPT.md` first** —
clean-room, dedup, smoke-test, no-destructive-without-ack, etc.

---

## You are Claude Code

Today's job: pull ThreatFox CSV, INSERT OR IGNORE new IOC sha256/md5s into
staging, merge to canonical. Optionally fetch bytes for previously-unseen
sha256s via MalwareBazaar API (burns MB API quota — gated behind --fetch-unknown).

## Prereqs

- feed-builder.exe built and runnable
- `D:\feed-builder\feed-builder.sqlite` exists (staging DB)
- If using `--fetch-unknown`: `$env:ABUSECH_KEY` is set

## Pipeline

### Step 1 — Run ThreatFox ingest (label-only mode, no API spend)

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\FreallyAV\tools\feed-builder"
.\target\release\feed-builder.exe `
  threatfox `
  --csv-path .\threatfox_full.csv.zip `
  --refresh-csv `
  --confidence-min 75
```

Defaults explained:
- `--csv-url` defaults to ThreatFox's published full CSV URL
- `--refresh-csv` forces fresh CSV download (recommended every run)
- `--confidence-min 75` keeps only community-attested rows (default; lower to 50 for more recall, raise to 90 for strictest)
- No `--fetch-unknown` → label-only mode, no MB API quota spent

Logs to stdout — capture with `> D:\feed-builder\threatfox_$DATE.log 2>&1` if running in background.

### Step 2 — (Optional) Byte-fetch mode for sha256 IOCs

If you also want bytes for sha256 IOCs not yet in your DB (so they can be
hashed + run through your Freally YARA rules):

```powershell
.\target\release\feed-builder.exe `
  threatfox `
  --csv-path .\threatfox_full.csv.zip `
  --confidence-min 75 `
  --fetch-unknown `
  --fetch-limit 500 `
  --key $env:ABUSECH_KEY
```

`--fetch-limit 500` caps API spend at 500 byte-fetches per run. Adjust to your
quota. Set 0 for unlimited (NOT recommended — your MB key has a daily limit).

### Step 3 — Smoke-test then merge to canonical

```powershell
python hash_database\smoke_test_merge.py

# Dry-run
python hash_database\merge_staging_to_canonical.py --source-label threatfox-$DATE

# If reasonable, --commit
python hash_database\merge_staging_to_canonical.py --source-label threatfox-$DATE --commit
```

ThreatFox typically adds **a few hundred to a few thousand** new rows per
weekly run (most IOCs are already in your DB from URLhaus/MB cycles).

### Step 4 — Report + decide on consolidate

- Pre/post/delta canonical count
- Family attribution coverage of new rows (ThreatFox has its own family tags;
  the ingest path maps them to Freally taxonomy via threatfox.rs)

If this run added meaningful new rows AND you haven't done a blacklist release
recently, consider following up with `PUBLISH-BLACKLIST-PROMPT.md` to ship a
new version. Otherwise, the rows sit in canonical until the next consolidate.

### Step 5 — Cleanup

```powershell
# Keep threatfox_full.csv.zip around (it's a meaningful CSV cache;
# --refresh-csv on next run overwrites it cleanly)
# No samples extracted (no bytes — IOC-only).
```

---

## Cadence

ThreatFox publishes their full CSV every few hours, but you don't need to
ingest that often. Reasonable cadence:

| Frequency | Why |
|---|---|
| **Daily** (as part of daily catchup) | Catches new community-attested malware families fastest. Recommended. |
| Weekly | Most ThreatFox IOCs converge with URLhaus/MB within a week; weekly is OK for lighter workflow. |
| Monthly | Too infrequent — you'll miss the family-attribution signal that ThreatFox is good for. |

Default: include in daily catchup (`DAILY-CATCHUP-PROMPT.md` step 9).

## Recovery

| Failure | Recovery |
|---|---|
| Wrong CSV downloaded | `--refresh-csv` next run pulls fresh |
| Merge committed wrong rows | `DELETE FROM samples WHERE source = 'threatfox-$DATE'` (after exporting hashes to JSON first per the no-destructive-without-ack rule) |
| MB API quota burned by `--fetch-unknown` | wait 24h for quota reset; future runs use lower `--fetch-limit` |
