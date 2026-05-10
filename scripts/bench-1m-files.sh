#!/usr/bin/env bash
# bench-1m-files.sh — TASK-018.
#
# End-to-end Phase-1 benchmark. Generates a synthetic 1M-file tree under
# $TARGET (default /tmp/myth-bench-1m) if it is not already populated, then
# runs `mythctl scan` against it and asserts the NFR-001 budget for the
# current release line.
#
# Budget:
#   v0.10  ≤ 8 minutes (480 s)
#   v0.15  ≤ 6 minutes (360 s)
#   v0.19.84 ≤ 4 minutes (240 s)
#
# Usage:
#   scripts/bench-1m-files.sh [--target DIR] [--budget-seconds N]

set -euo pipefail

TARGET="/tmp/myth-bench-1m"
BUDGET_SECONDS=480 # v0.10 baseline
FILE_COUNT=1000000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2;;
        --budget-seconds) BUDGET_SECONDS="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

if [[ ! -d "$TARGET" ]] || [[ "$(find "$TARGET" -type f | wc -l)" -lt "$FILE_COUNT" ]]; then
    echo "[bench] generating $FILE_COUNT files under $TARGET (this takes a while)…"
    rm -rf "$TARGET"
    mkdir -p "$TARGET"
    # 1000 dirs × 1000 files = 1M files. A single byte each keeps disk usage modest (~1 GB
    # with FS overhead).
    for d in $(seq -w 0001 1000); do
        mkdir -p "$TARGET/d${d}"
        for f in $(seq -w 0001 1000); do
            echo -n "x" > "$TARGET/d${d}/f${f}.txt"
        done
    done
fi

echo "[bench] cargo build --release -p mythctl"
cargo build --release -p mythctl

echo "[bench] scanning $TARGET (budget: ${BUDGET_SECONDS}s)"
START=$(date +%s)
target/release/mythctl scan "$TARGET" --format text > /dev/null
END=$(date +%s)
ELAPSED=$((END - START))

echo "[bench] completed in ${ELAPSED}s (budget ${BUDGET_SECONDS}s)"
if [[ "$ELAPSED" -gt "$BUDGET_SECONDS" ]]; then
    echo "[bench] FAIL: NFR-001 budget exceeded" >&2
    exit 1
fi
echo "[bench] PASS"
