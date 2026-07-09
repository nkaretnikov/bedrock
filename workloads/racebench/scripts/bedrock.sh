#!/usr/bin/env bash
# Bedrock coverage for the RaceBench corpus: how many of the 60 injected bugs the
# concurrency-fuzz scheduler reaches UNDER bedrock (single vCPU, emulated TSC,
# thread-fuzz SCHED_EXT). This is the counterpart to baseline.sh: run the two and
# compare TOTALs. Bugs bedrock reaches that the native baseline never does are the
# scheduler's payoff.
#
# Under bedrock each boot is one DETERMINISTIC schedule: the getrandom stream
# (which drives the fuzzing scheduler) is a pure function of the rdrand seed. So
# coverage comes from sweeping the seed across boots, not from re-running one
# seed. Because it is deterministic, this sweep needs no reps: re-running the same
# seed range reproduces byte-identical coverage (that is the whole point). The
# repro of a triggered bug is (target, input, seed).
#
# Each boot runs the full corpus (all three targets) once via fuzz/run.sh and
# prints one line per target to serial:
#   "<name>: BUG TRIGGERED (rc=134) bug_ids: 3 7"   or   "<name>: no trigger ..."
# We union bug_ids per target across boots and plateau per target, exactly like
# baseline.sh -- same PLATEAU/MAX semantics so the numbers are comparable.
#
# Prerequisites (run this ON THE HOST where bedrock is loaded, e.g. galactus):
#   - bedrock module loaded (lsmod | grep bedrock) and /dev/bedrock present
#   - workload image built: cd .. && ./build.sh
#   - the seed knob: this drives the flake app test-racebench-workload, which
#     passes RDRAND_SEED to bedrock-cli -s (see flake.nix).
#
# Usage (capture to a dated, host-tagged file like the baseline does):
#   ./bedrock.sh 2>&1 | tee "bedrock-$(hostname -s)-$(date +%F).txt"
#
# WARNING: a boot is FAR heavier than a native run (boots a podman guest, then
# runs all three targets), so PLATEAU=500 is many hours. Start small to sanity
# check, e.g. PLATEAU=20 MAX=100 ./bedrock.sh, then raise for the real number.
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT=$(cd ../../.. && pwd)     # scripts -> racebench -> workloads -> repo root
SEED_BASE="${SEED_BASE:-1}"         # first seed; boot i uses seed SEED_BASE + (i-1)
PLATEAU="${PLATEAU:-500}"           # stop a target after this many boots add no new bug
MAX="${MAX:-20000}"                 # hard cap on boots
TARGETS=(blackscholes streamcluster fluidanimate)

if ! lsmod 2>/dev/null | grep -q bedrock; then
  echo "ERROR: bedrock module not loaded (lsmod | grep bedrock). Run this on the host where bedrock is loaded." >&2
  exit 1
fi
if [ ! -f "$REPO_ROOT/workloads/racebench/images.tar" ]; then
  echo "ERROR: images.tar not found. Build it first: cd .. && ./build.sh" >&2
  exit 1
fi

declare -A reached                  # target -> space-separated union of bug ids
declare -A noNew                    # target -> consecutive boots with no new bug
for t in "${TARGETS[@]}"; do reached[$t]=""; noNew[$t]=0; done

echo "--- bedrock coverage: seed_base=$SEED_BASE plateau=$PLATEAU max=$MAX ---"

boots=0
while [ "$boots" -lt "$MAX" ]; do
  # Stop once every target has plateaued.
  done_all=1
  for t in "${TARGETS[@]}"; do
    [ "${noNew[$t]}" -lt "$PLATEAU" ] && done_all=0
  done
  [ "$done_all" -eq 1 ] && break

  seed=$((SEED_BASE + boots))
  boots=$((boots + 1))

  # One deterministic boot of the whole corpus. Capture serial; a triggered bug
  # aborts a target (rc=134) but the guest logs the line and boots to shutdown,
  # so `nix run` still exits 0. Guard with || true regardless.
  out=$(cd "$REPO_ROOT" && RDRAND_SEED="$seed" nix run .#test-racebench-workload 2>&1 || true)

  # Parse "<name>: BUG TRIGGERED (rc=...) bug_ids: 3 7" lines; update per-target
  # union and plateau counters. Targets with no trigger this boot just increment.
  for t in "${TARGETS[@]}"; do
    ids=$(printf '%s\n' "$out" | sed -n "s/^$t: BUG TRIGGERED[^:]*bug_ids:\(.*\)$/\1/p" | tr -s ' \n' ' ')
    new=0
    for id in $ids; do
      case " ${reached[$t]} " in
        *" $id "*) : ;;
        *) reached[$t]="${reached[$t]} $id"; new=1 ;;
      esac
    done
    if [ "$new" -eq 1 ]; then noNew[$t]=0; else noNew[$t]=$((noNew[$t] + 1)); fi
  done
done

total=0
for t in "${TARGETS[@]}"; do
  ids=$(echo "${reached[$t]}" | tr -s ' ' ' ' | sed 's/^ //; s/ $//')
  cnt=$(echo "$ids" | wc -w)
  total=$((total + cnt))
  echo "$t: reached $cnt/20 in $boots boots -> bug_ids: $ids"
done
echo "TOTAL bedrock coverage: $total/60"
