#!/usr/bin/env bash
# Parse an LTP serial log and decide pass/fail for one matrix cell.
#
# Gate metric is TPASS sub-assertions — the same thing the contest grader sums,
# and robust to the run being time-capped (under QEMU/TCG the guest is slow, so
# the host wall often fires before the guest's ~2000s ltp budget emits its END
# marker; that is normal, not a regression).
#
# Hard-fail (real regressions) on:
#   1. a kernel panic / unrecoverable exception
#   2. init (pid 1) being killed
#   3. TPASS count below the committed baseline (ci/baseline/<cell>.txt)
# A time-capped group (start without end) is a NOTICE, not a failure.
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
rc0=$(grep -acE 'FAIL LTP CASE .* : 0$' "$LOG" 2>/dev/null || true)
tpass=$(c 'TPASS')

echo "::group::LTP summary ($CELL)"
echo "cases launched     : $run"
echo "TPASS assertions   : $tpass   <- gate metric"
echo "cases rc==0 (info) : $rc0"
echo "group start/end    : $started / $ended"
echo "kernel panics      : $panics"
echo "init (pid 1) kills : $init_kill"
echo "::endgroup::"

fail=0
note() { echo "::error title=$CELL::$1"; fail=1; }

[ "$panics"    -gt 0 ] && note "kernel panic/exception in the run ($panics)"
[ "$init_kill" -gt 0 ] && note "init (pid 1) was killed — run ended early"

# A started-but-unended group is the QEMU host wall cutting a slow TCG run; the
# grader's in-guest budget would have ended it. Informational only.
if [ "$started" -gt 0 ] && [ "$ended" -eq 0 ]; then
  echo "::notice title=$CELL::ltp group time-capped (no END marker) — normal under QEMU/TCG; gating on TPASS"
fi

# Sanity: the run must have actually produced LTP output.
if [ "$started" -eq 0 ] || [ "$tpass" -eq 0 ]; then
  note "no LTP output (started=$started tpass=$tpass) — image/boot problem"
fi

if [ -f "$BASE_FILE" ]; then
  baseline=$(tr -dc '0-9' < "$BASE_FILE"); baseline=${baseline:-0}
  floor=$(( baseline - (baseline / 20) - 25 ))   # baseline - 5% - small jitter
  [ "$floor" -lt 0 ] && floor=0
  echo "baseline(TPASS)=$baseline  floor=$floor  observed=$tpass"
  if [ "$tpass" -lt "$floor" ]; then
    note "TPASS $tpass < floor $floor (baseline $baseline) — regression"
  fi
  if [ "$tpass" -gt "$baseline" ]; then
    echo "::notice title=$CELL::TPASS $tpass > baseline $baseline — consider bumping ci/baseline/$CELL.txt"
  fi
else
  echo "::warning title=$CELL::no baseline yet ($BASE_FILE); observed TPASS=$tpass (recording, not gating)"
fi

exit "$fail"
