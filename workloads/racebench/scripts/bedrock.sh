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

# Capture lsmod and string-match it, rather than `lsmod | grep -q`: under
# `set -o pipefail`, grep -q exits at the first match and SIGPIPEs lsmod (whose
# freshly-insmod'd bedrock line is at the top), and pipefail then propagates that
# non-zero status - so the check spuriously fails even when the module IS loaded.
lsmod_out=$(lsmod 2>/dev/null || true)
case "$lsmod_out" in
  *bedrock*) : ;;
  *)
    echo "ERROR: bedrock module not loaded (lsmod | grep bedrock). Run this on the host where bedrock is loaded." >&2
    exit 1
    ;;
esac
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

  # Sanity: if a boot did not reach the OK marker it likely failed (module
  # unloaded, image missing). Warn so a broken sweep is not mistaken for 0/60.
  # Match with `case`, not `printf | grep -q`, to avoid the same pipefail/SIGPIPE
  # trap as the module check above.
  case "$out" in
    *"RaceBench workload: OK"*) : ;;
    *) echo "boot $boots seed $seed: WARNING boot did not complete cleanly (no OK marker)" >&2 ;;
  esac

  # Parse "<name>: BUG TRIGGERED (rc=...) bug_ids: 3 7" lines; update per-target
  # union and plateau counters. Targets with no trigger this boot just increment.
  # The guest lines reach us with a console prefix, e.g.
  #   "[vt   28.79] [fuzz] | streamcluster: BUG TRIGGERED (rc=134) bug_ids: 3 7"
  # so match the target name ANYWHERE on the line, not anchored at column 0.
  newmsg=""
  for t in "${TARGETS[@]}"; do
    ids=$(printf '%s\n' "$out" | sed -n "s/.*$t: BUG TRIGGERED[^:]*bug_ids:\(.*\)$/\1/p" | tr -s ' \n' ' ')
    newthis=""
    for id in $ids; do
      case " ${reached[$t]} " in
        *" $id "*) : ;;
        *) reached[$t]="${reached[$t]} $id"; newthis="$newthis $id" ;;
      esac
    done
    if [ -n "$newthis" ]; then
      noNew[$t]=0; newmsg="$newmsg ${t}+{${newthis# }}"
    else
      noNew[$t]=$((noNew[$t] + 1))
    fi
  done

  # Per-boot progress to stderr (kept off the stdout summary). `slowest-plateau`
  # is min(noNew) across targets: the sweep ends when it reaches PLATEAU, and it
  # resets to 0 whenever any target finds a new bug. `tail -f` the tee'd log.
  total_now=0; minplat="$PLATEAU"
  for t in "${TARGETS[@]}"; do
    c=$(echo "${reached[$t]}" | wc -w); total_now=$((total_now + c))
    [ "${noNew[$t]}" -lt "$minplat" ] && minplat="${noNew[$t]}"
  done
  [ -n "$newmsg" ] && newmsg=" NEW:$newmsg"
  echo "boot $boots seed $seed: coverage ${total_now}/60; slowest-plateau ${minplat}/${PLATEAU}${newmsg}" >&2
done

total=0
for t in "${TARGETS[@]}"; do
  ids=$(echo "${reached[$t]}" | tr -s ' ' ' ' | sed 's/^ //; s/ $//')
  cnt=$(echo "$ids" | wc -w)
  total=$((total + cnt))
  echo "$t: reached $cnt/20 in $boots boots -> bug_ids: $ids"
done
echo "TOTAL bedrock coverage: $total/60"
