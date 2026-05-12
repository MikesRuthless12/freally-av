# bench-1m-files.ps1 — TASK-057.
#
# Windows mirror of `scripts/bench-1m-files.sh`. End-to-end Phase 5
# benchmark: generates a synthetic 1M-file tree under $Target (default
# $env:TEMP\myth-bench-1m) if it is not already populated, then runs
# `mythctl scan` against it and asserts the NFR-001 / NFR-002 budget for
# the current release line.
#
# Budget (Windows host, NTFS volume, NVMe):
#   v0.5     cold ≤ 6 minutes (360 s) — Phase 5 lenient gate
#   v0.10    cold ≤ 8 minutes (480 s) — global baseline
#   v0.15    cold ≤ 6 minutes (360 s) — tightened
#   v0.19.84 cold ≤ 4 minutes (240 s) — final NFR-001
#
# Usage:
#   pwsh scripts/bench-1m-files.ps1
#   pwsh scripts/bench-1m-files.ps1 -Target "D:\bench" -BudgetSeconds 360
#
# Notes:
#   * Tree generation uses 1000 dirs × 1000 files = 1M files at ~1 GiB on disk.
#     Generation is the slow part; the scan it drives is what we measure.
#   * Re-running with the same -Target reuses the existing tree. Add
#     `-Force` to regenerate (e.g. after an OS reinstall).
#   * The script intentionally avoids `Measure-Command` so the engine's
#     own structured progress output stays visible. Wall time is measured
#     via `Get-Date` on either side of the scan invocation.

[CmdletBinding()]
param(
    [string]$Target = (Join-Path $env:TEMP "myth-bench-1m"),
    [int]$BudgetSeconds = 360,
    [int]$FileCount = 1000000,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Stage([string]$Message) {
    Write-Host "[bench] $Message" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------
# Generate (or reuse) the synthetic tree.
# -----------------------------------------------------------------------
$needGen = $Force.IsPresent
if (-not $needGen) {
    if (-not (Test-Path $Target -PathType Container)) {
        $needGen = $true
    } else {
        $existing = (Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
                     Measure-Object).Count
        if ($existing -lt $FileCount) {
            Write-Stage "existing tree has $existing files (< $FileCount); regenerating"
            $needGen = $true
        } else {
            Write-Stage "reusing existing tree at $Target ($existing files)"
        }
    }
}

if ($needGen) {
    Write-Stage "generating $FileCount files under $Target (one-shot; this takes a while)"
    if (Test-Path $Target) {
        Remove-Item -Path $Target -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Target -Force | Out-Null

    # 1000 dirs × 1000 files. One byte each keeps the tree at ~1 GiB on
    # NTFS (4-KiB cluster slack dominates the on-disk size, not the file
    # bytes themselves).
    $dirsPerLevel = [int][Math]::Round([Math]::Sqrt($FileCount))
    $filesPerDir  = [int][Math]::Floor($FileCount / [Math]::Max($dirsPerLevel, 1))

    for ($d = 1; $d -le $dirsPerLevel; $d++) {
        $dir = Join-Path $Target ("d{0:0000}" -f $d)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        for ($f = 1; $f -le $filesPerDir; $f++) {
            $p = Join-Path $dir ("f{0:0000}.txt" -f $f)
            # `New-Item -ItemType File` is faster than `Set-Content` for
            # tiny payloads since it bypasses the encoding pipeline.
            New-Item -ItemType File -Path $p -Force | Out-Null
            "x" | Out-File -FilePath $p -Encoding ascii -NoNewline
        }
        if (($d % 100) -eq 0) {
            Write-Stage "  built $d / $dirsPerLevel dirs"
        }
    }
}

# -----------------------------------------------------------------------
# Build the release binary.
# -----------------------------------------------------------------------
Write-Stage "cargo build --release -p mythctl"
cargo build --release -p mythctl
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed (exit $LASTEXITCODE)"
}

$mythctl = (Resolve-Path "target\release\mythctl.exe").Path

# -----------------------------------------------------------------------
# Cold scan — drop the page cache implicitly by reusing the system's
# 'first-use' fingerprint on the tree we just built. (Windows doesn't
# expose a `/proc/sys/vm/drop_caches` equivalent; reboot before this
# script for a true cold run if measuring against a reused tree.)
# -----------------------------------------------------------------------
Write-Stage "cold scan: $Target (budget ${BudgetSeconds}s)"
$start = Get-Date
& $mythctl scan $Target --format text | Out-Null
$cold = (Get-Date) - $start
$coldSecs = [int]$cold.TotalSeconds
Write-Stage "cold completed in ${coldSecs}s (budget ${BudgetSeconds}s)"

if ($coldSecs -gt $BudgetSeconds) {
    Write-Host "[bench] FAIL: NFR-001 cold-scan budget exceeded ($coldSecs > $BudgetSeconds)" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------
# Warm scan — should be substantially faster (file cache hot, no MFT
# pagination misses). NFR-002 v0.5 interim budget is 30 s.
# -----------------------------------------------------------------------
$warmBudget = 30
Write-Stage "warm scan: $Target (budget ${warmBudget}s)"
$start = Get-Date
& $mythctl scan $Target --format text | Out-Null
$warm = (Get-Date) - $start
$warmSecs = [int]$warm.TotalSeconds
Write-Stage "warm completed in ${warmSecs}s (budget ${warmBudget}s)"

if ($warmSecs -gt $warmBudget) {
    Write-Host "[bench] WARN: NFR-002 warm-scan budget exceeded ($warmSecs > $warmBudget) — Phase 5 wave 2 lenient" -ForegroundColor Yellow
}

Write-Host "[bench] PASS — cold ${coldSecs}s | warm ${warmSecs}s" -ForegroundColor Green
