#!/usr/bin/env bash
# Parse an LTP serial log and decide pass/fail for one matrix cell.
#
# Pass accounting matches the contest runner's output:
#   "RUN LTP CASE <name>"            — a case was launched
#   "FAIL LTP CASE <name> : <rc>"    — rc==0 means the case passed (the
#                                       "FAIL" literal is just the marker the
#                                       runner always prints; rc is the truth)
#   "...TPASS..."                    — LTP sub-assertion passed
#
# Gate (fail the job) on, in order:
#   1. a kernel panic / unrecoverable exception   (hard regression)
#   2. init (pid 1) being killed                  (hard regression)
#   3. a started-but-never-ended ltp group        (the run wedged)
#   4. rc==0 case count below the committed baseline (ci/baseline/<cell>.txt)
#
# Usage: parse-ltp.sh <cell-name> <log>
set -uo pipefail

CELL="$1"
LOG="$2"
BASE_DIR="$(dirname "$0")/baseline"
BASE_FILE="$BASE_DIR/$CELL.txt"

c() { grep -acE "$1" "$LOG" 2>/dev/null || true; }

panics=$(c 'kernel exception|Kernel panic|rust_begin_unwind|\[kernel fault storm\]')
init_kill=$(c 'pid=1 .* killing task')
started=$(c '#### OS COMP TEST GROUP START ltp')
ended=$(c '#### OS COMP TEST GROUP END ltp')
run=$(c 'RUN LTP CASE ')
pass=$(grep -acE 'FAIL LTP CASE .* : 0$' "$LOG" 2>/dev/null || true)
tpass=$(c 'TPASS')

echo "::group::LTP summary ($CELL)"
echo "cases launched     : $run"
echo "cases rc==0 (pass) : $pass"
echo "TPASS assertions   : $tpass"
echo "group start/end    : $started / $ended"
echo "kernel panics      : $panics"
echo "init (pid 1) kills : $init_kill"
echo "::endgroup::"

fail=0
note() { echo "::error title=$CELL::$1"; fail=1; }

[ "$panics"    -gt 0 ] && note "kernel panic/exception in the run ($panics)"
[ "$init_kill" -gt 0 ] && note "init (pid 1) was killed — run ended early"
if [ "$started" -gt 0 ] && [ "$ended" -eq 0 ]; then
  note "ltp group started but never ended — the run wedged"
fi

if [ -f "$BASE_FILE" ]; then
  baseline=$(tr -dc '0-9' < "$BASE_FILE")
  baseline=${baseline:-0}
  # Allow a little console-noise jitter; a real regression drops far more.
  floor=$(( baseline - (baseline / 20) - 3 ))   # baseline - 5% - 3
  [ "$floor" -lt 0 ] && floor=0
  echo "baseline=$baseline  floor=$floor  observed=$pass"
  if [ "$pass" -lt "$floor" ]; then
    note "pass count $pass < floor $floor (baseline $baseline) — regression"
  fi
  # Surface an improvement so the baseline can be bumped deliberately.
  if [ "$pass" -gt "$baseline" ]; then
    echo "::notice title=$CELL::pass count $pass > baseline $baseline — consider bumping ci/baseline/$CELL.txt"
  fi
else
  echo "::warning title=$CELL::no baseline ($BASE_FILE); recording $pass as informational only"
  mkdir -p "$BASE_DIR"
  echo "$pass" > "$BASE_FILE.observed"
fi

exit "$fail"
