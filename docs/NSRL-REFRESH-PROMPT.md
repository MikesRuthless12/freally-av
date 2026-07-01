# NSRL Refresh Prompt (Quarterly Whitelist Update)

Run **once per quarter** (when NIST publishes a new NSRL RDS release) to refresh
the optional `myth-whitelist.sqlite` artifact end users can download for
faster scans.

NIST publishes NSRL RDS releases approximately **March, June, September, December**.
Current `nsrl.sqlite` is from `RDS_2026.03.1_modern_minimal.db` per saved state.

This is a **multi-hour single-machine job** — the ingest alone took ~5h43m on the
last run (343 min, 169 GB source DB → 31 GB output, see prior `current_consolidation_state.md`).
Plan for a wall clock day of monitoring.

**Read constraints section of `docs/DAILY-CATCHUP-PROMPT.md` first** —
clean-room, dedup, smoke-test, no-destructive-without-ack, etc.

---

## You are Claude Code

Today's job: download the latest NIST NSRL RDSv3 modern-minimal release, run
`feed-builder.exe nsrl` to re-ingest into `nsrl.sqlite`, re-run consolidate
to refresh `myth-whitelist.sqlite`, publish a new whitelist GitHub release.

## Prereqs

- 250 GB free disk space (169 GB extracted source + 31 GB output + headroom)
- Source DB lives on the fastest available disk (E: T7 SSD per memory; the
  prior run on D: HDD stalled — see `current_consolidation_state.md`)
- `feed-builder.exe` release binary built
- `nsrl.rs` pragmas already bumped (cache_size = -4_000_000, mmap_size = 16 GB)
- `D:\feed-builder\` has space for the auto-launcher logs

## Pipeline

### Step 1 — Find + download the latest NSRL release

NIST NSRL home: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download

Look for the most recent **RDSv3 / Modern-Minimal** SQLite release. As of 2026
the naming convention is `RDS_YYYY.MM.N_modern_minimal.zip`.

```powershell
# Download to a working dir on the fast SSD
$NSRL_VERSION = "2026.06.1"  # update to the actual current release
$DL_URL = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_YYYY.MM.N/RDS_$($NSRL_VERSION)_modern_minimal.zip"
Invoke-WebRequest -Uri $DL_URL -OutFile "E:\feed-builder\nsrl\RDS_$($NSRL_VERSION).zip"
```

**Verify download integrity** — NIST publishes a SHA256 on their download page.
Compare:
```powershell
Get-FileHash "E:\feed-builder\nsrl\RDS_$($NSRL_VERSION).zip" -Algorithm SHA256
```

### Step 2 — Extract

```powershell
Expand-Archive `
  -Path "E:\feed-builder\nsrl\RDS_$($NSRL_VERSION).zip" `
  -DestinationPath "E:\feed-builder\nsrl\extracted_$NSRL_VERSION\"
```

Expect a single `.db` SQLite file inside, e.g. `RDS_$($NSRL_VERSION)_modern_minimal.db`,
~169 GB extracted.

### Step 3 — Back up existing nsrl.sqlite (REVERSIBLE)

```powershell
$PREV_NSRL_VERSION = "2026.03.1"  # whatever the prior was
Move-Item `
  "C:\Users\miken\Desktop\Havoc Software\FreallyAV\hash_database\nsrl.sqlite" `
  "C:\Users\miken\Desktop\Havoc Software\FreallyAV\hash_database\nsrl-$PREV_NSRL_VERSION.sqlite.bak"
```

Reversible — old version stays as `.bak` until you confirm new run is good.

### Step 4 — Run the NSRL ingest

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\FreallyAV\tools\feed-builder"
.\target\release\feed-builder.exe `
  --db D:\feed-builder\feed-builder.sqlite `
  nsrl `
  --rds "E:\feed-builder\nsrl\extracted_$NSRL_VERSION\RDS_$($NSRL_VERSION)_modern_minimal.db" `
  --out "C:\Users\miken\Desktop\Havoc Software\FreallyAV\hash_database\nsrl.sqlite" `
  --chunk-size 200000 `
  > D:\feed-builder\nsrl_$($NSRL_VERSION).log 2>&1
```

**Run as background task.** ETA: ~5-6 hours wall clock. Monitor with hourly
pings checking process state + WAL growth + main DB size.

The pattern from the prior run: first ~50 min the WAL is buffered, then it
streams to disk at ~1.5 GB / 10 min, eventually checkpointing the final
~31 GB main DB.

### Step 5 — Verify the new nsrl.sqlite

```powershell
python "C:\Users\miken\Desktop\Havoc Software\FreallyAV\hash_database\verify_nsrl.py"
```

Expected output:
- 70M+ distinct sha256 rows (was 72,015,285 at 2026.03 release; quarter-over-quarter growth typically a few %)
- Schema unchanged from prior version
- Top OS distribution: windows ~42%, linux ~27%, NULL ~10%, macos ~4%, multi-OS combos rest
- Provenance meta: "NIST NSRL RDSv3, public domain per 17 USC 105"

STOP if anything looks structurally wrong.

### Step 6 — Re-run consolidate to refresh myth-whitelist.sqlite

```powershell
$WL_VERSION = "v$NSRL_VERSION"  # e.g. v2026.06.1

cd "C:\Users\miken\Desktop\Havoc Software\FreallyAV\tools\feed-builder"
.\target\release\feed-builder.exe consolidate `
  --src-db ..\..\hash_database\MythAV-HashDB.sqlite `
  --src-nsrl ..\..\hash_database\nsrl.sqlite `
  --out-blacklist ..\..\hash_database\myth-blacklist.sqlite `
  --out-whitelist ..\..\hash_database\myth-whitelist.sqlite `
  --version $WL_VERSION
```

This produces:
- A fresh `myth-whitelist.sqlite` from the new NSRL (rebuilt from scratch)
- A refresh of `myth-blacklist.sqlite` (incidental — no harm, but a separate
  blacklist release isn't required from this run unless canonical has changed
  since the last blacklist publish)

ETA: 15-25 min.

### Step 7 — Verify whitelist artifact

```python
import sqlite3
db = r'C:\Users\miken\Desktop\Havoc Software\FreallyAV\hash_database\myth-whitelist.sqlite'
c = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
n = c.execute('SELECT COUNT(*) FROM nsrl_samples').fetchone()[0]
meta = dict(c.execute('SELECT key, value FROM freally_meta').fetchall())
print(f'whitelist rows={n:,} version={meta["artifact_version"]}')
assert n >= 70_000_000
```

STOP if low.

### Step 8 — Publish whitelist GitHub release (MAINTAINER ACK)

```powershell
cd "C:\Users\miken\Desktop\Havoc Software\FreallyAV"
$STG = "release-staging-whitelist-$WL_VERSION"
New-Item -ItemType Directory -Path $STG -Force | Out-Null

Copy-Item hash_database\myth-whitelist.sqlite "$STG\myth-whitelist-$WL_VERSION.sqlite"
zstd -19 "$STG\myth-whitelist-$WL_VERSION.sqlite" -o "$STG\myth-whitelist-$WL_VERSION.sqlite.zst"
Get-FileHash "$STG\myth-whitelist-$WL_VERSION.sqlite.zst" -Algorithm SHA256 `
  | Format-List > "$STG\SHA256SUMS.txt"

git tag -a "whitelist-$WL_VERSION" -m "NSRL whitelist refresh $WL_VERSION"
git push origin "whitelist-$WL_VERSION"

gh release create "whitelist-$WL_VERSION" `
  --title "FreallyAV Whitelist $WL_VERSION (NSRL $NSRL_VERSION)" `
  --notes "Refreshed NIST NSRL whitelist. Row count: $n. Source: NSRL RDSv3 $NSRL_VERSION. Optional download for end users wanting faster scans (skips known-good files)." `
  "$STG\myth-whitelist-$WL_VERSION.sqlite.zst" `
  "$STG\SHA256SUMS.txt"
```

### Step 9 — Cleanup

After confirming new release works:

```powershell
# Delete the extracted NSRL source (169 GB!)
Remove-Item -Recurse -Force "E:\feed-builder\nsrl\extracted_$NSRL_VERSION\"

# Delete the downloaded zip (~7 GB)
Remove-Item -Force "E:\feed-builder\nsrl\RDS_$($NSRL_VERSION).zip"

# Delete the .bak of prior nsrl.sqlite (after a few days of stability)
# Don't auto-delete this — ask user. The .bak is the only rollback path.
# Remove-Item -Force "C:\Users\miken\...\hash_database\nsrl-$PREV_NSRL_VERSION.sqlite.bak"

# Release staging dir
Remove-Item -Recurse -Force "release-staging-whitelist-$WL_VERSION"
```

### Step 10 — Update memory + report

- New whitelist version + row count
- GitHub release URL
- Disk reclaimed
- Add to memory: next NSRL release expected ~3 months from publication of this one
- Update [[current_consolidation_state]] memory to reflect new nsrl.sqlite version

---

## Decision points

1. **Step 1**: if NSRL hasn't actually released a new version since `$PREV_NSRL_VERSION`, STOP. No work to do.
2. **Step 4**: if process appears stuck (low CPU, no WAL growth, no main DB growth for > 30 min after the initial buffer-fill phase), investigate before killing. Prior Run 1 got into a PageIn limbo state that took 7h to detect.
3. **Step 5**: if new row count is DRAMATICALLY lower (e.g. -50% vs prior NSRL), STOP — likely a malformed source DB or schema change.
4. **Step 8**: ALWAYS ack before publishing.
5. **Step 9**: ask before deleting the `.bak` — it's the rollback.

## Cadence

| Quarter | Expected NSRL release | Action |
|---|---|---|
| Q1 (Mar) | Yes | Run this prompt |
| Q2 (Jun) | Yes | Run this prompt |
| Q3 (Sep) | Yes | Run this prompt |
| Q4 (Dec) | Yes | Run this prompt |

Set a calendar reminder for the 15th of each release month to check the NSRL site.

## Recovery

| Failure | Recovery |
|---|---|
| Download interrupted | `Invoke-WebRequest -Resume` or restart |
| Ingest stalls (PageIn limbo) | See `current_consolidation_state.md` — kill PID, restart with source on faster disk, ensure pragmas in nsrl.rs are still at -4_000_000 cache + 16 GB mmap |
| New nsrl.sqlite is corrupt | `Move-Item nsrl-$PREV.sqlite.bak nsrl.sqlite` restores prior; re-run ingest from scratch |
| Whitelist release published broken | `gh release delete whitelist-$WL_VERSION --yes`; re-run from Step 6 |
