#!/usr/bin/env bash
# Coverage-guided PCT sweep for the mptest concurrency-fuzz workload.
#
# Like fuzz.sh, this sweeps bedrock RDRAND seeds against mptest under the PCT
# sched_ext scheduler, hunting the libmultiprocess IPC races (#35491 hang, #34014
# crash). It adds an edge-coverage feedback loop on top: each run dumps the
# guest's coverage buffer via `bedrock-cli --coverage-out`, and the driver keeps
# a running union of edge coverage (AFL-style hitcount buckets). Seeds that light
# up *new* edges are recorded as a corpus; a plateau in new coverage is the
# signal that the reachable code (under these schedules) has saturated.
#
# REQUIRES an instrumented image: build it with
#   COVERAGE=1 ./workloads/mptest/build.sh
# Without instrumentation the coverage dumps are empty and this degrades to a
# plain seed sweep (new=0 every run) -- still a valid PCT sweep, just no guidance.
#
# SCOPE: this is coverage *accumulation + novelty selection + plateau* (the
# "Tier A" loop). It selects and ranks whole seeds; it does not yet mutate a seed
# locally, because the fuzzer input today is a single PRNG seed with no
# positional locality. Local, schedule-aware mutation needs the positional
# pool-input work (a host-supplied testcase feeding scx-init's pool) -- see the
# README. The corpus this records (interesting seeds + their coverage) is exactly
# what that mutation phase will breed from.
#
# Also note edge coverage is *code* coverage, not *interleaving* coverage: it
# rewards schedules that reach new code (e.g. a race-opened error path), but two
# schedules that run the same lines in a different racy order look identical. A
# concurrency-specific metric (communication pairs / cross-context-switch PC
# pairs / PCT-native change-point buckets) is the stronger follow-on.
#
# Run from the repo root with the module loaded, /dev/bedrock present, and the
# instrumented image built.
#
# Usage:
#   COVERAGE=1 ./workloads/mptest/build.sh          # once: instrumented image
#   ./workloads/mptest/fuzz-cov.sh                  # up to 24h, stop on 1st repro
#   DURATION=3600 ./workloads/mptest/fuzz-cov.sh    # 1h budget
#   STOP_ON_REPRO=0 ./workloads/mptest/fuzz-cov.sh  # keep hunting after a find
#
# Env knobs (shared with fuzz.sh): DURATION, RUN_TIMEOUT, STOP_ON_REPRO, OUT.
set -u

DURATION=${DURATION:-$((24 * 3600))}
RUN_TIMEOUT=${RUN_TIMEOUT:-3600}
STOP_ON_REPRO=${STOP_ON_REPRO:-1}
OUT=${OUT:-fuzz-cov-runs}

if [ ! -f workloads/mptest/images.tar ]; then
  echo "ERROR: workloads/mptest/images.tar not found (run from the repo root)." >&2
  echo "Build an instrumented image first: COVERAGE=1 ./workloads/mptest/build.sh" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 needed for coverage accounting." >&2
  exit 1
fi

end=$(( $(date +%s) + DURATION ))
mkdir -p "$OUT/corpus" "$OUT/cov"
: > "$OUT/summary.txt"
COV_MAP="$OUT/coverage.map"     # accumulated per-edge max bucket (binary)
rm -f "$COV_MAP"

# Build stamp: pin what this sweep ran against (same rationale as fuzz.sh).
commit=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit+dirty"
img_sha=$(sha256sum workloads/mptest/images.tar 2>/dev/null | cut -c1-16)
{
  echo "# build: commit=$commit images.tar=sha256:$img_sha"
  echo "# started: $(date -Is)"
  echo "# columns: <seed> <result> new=<edges> total=<edges> plateau=<runs>"
} >> "$OUT/summary.txt"

echo "Coverage-guided fuzzing for ${DURATION}s; stop-on-repro=$STOP_ON_REPRO"
echo "Build: commit=$commit images.tar=sha256:$img_sha"

# Merge one run's coverage dump into the accumulated map. Prints "<new> <total>":
# <new> = edges whose AFL hitcount bucket increased this run (0 = nothing novel),
# <total> = edges ever covered. Buckets {1,2,3,4-7,8-15,16-31,32-127,128+} match
# AFL, so "ran a loop once" and "ran it 100 times" count as distinct coverage.
cov_merge() {
  python3 - "$COV_MAP" "$1" <<'PY'
import sys, os
mappath, covpath = sys.argv[1], sys.argv[2]
def bucket(c):
    if c == 0: return 0
    if c <= 3: return c
    if c <= 7: return 4
    if c <= 15: return 5
    if c <= 31: return 6
    if c <= 127: return 7
    return 8
cov = open(covpath, "rb").read() if os.path.exists(covpath) else b""
acc = bytearray(open(mappath, "rb").read()) if os.path.exists(mappath) else bytearray()
if len(cov) > len(acc):
    acc.extend(b"\x00" * (len(cov) - len(acc)))
new = 0
for i, c in enumerate(cov):
    b = bucket(c)
    if b > acc[i]:
        acc[i] = b
        new += 1
open(mappath, "wb").write(acc)
total = sum(1 for x in acc if x)
print(new, total)
PY
}

plateau=0
runs=0
while [ "$(date +%s)" -lt "$end" ]; do
  s=0x$(head -c8 /dev/urandom | od -An -tx8 | tr -d ' ')
  log="$OUT/run-$s.log"
  cov="$OUT/cov/$s.bin"
  echo "=== $(date -Is) seed $s ==="

  BEDROCK_RDRAND_SEED=$s BEDROCK_COVERAGE_OUT=$cov \
    timeout -k 30 "$RUN_TIMEOUT" nix run .#test-mptest-workload > "$log" 2>&1
  rc=$?

  line=$(grep -E 'mptest (FAILED|survived)' "$log" | head -1)
  [ -z "$line" ] && line="(no result line; rc=$rc)"

  # Coverage accounting. A missing/empty dump (uninstrumented image or a wedged
  # run) yields new=0, total unchanged -- the sweep still runs, just unguided.
  read -r new total < <(cov_merge "$cov")
  runs=$((runs + 1))
  if [ "${new:-0}" -gt 0 ]; then
    plateau=0
    # Keep the interesting input's coverage as the corpus to breed from later.
    mv "$cov" "$OUT/corpus/$s.bin"
    echo "$s new=$new total=$total" >> "$OUT/corpus.txt"
  else
    plateau=$((plateau + 1))
    rm -f "$cov"
  fi

  printf '%s  build=%s  %s  new=%s total=%s plateau=%s\n' \
    "$s" "$commit" "$line" "${new:-0}" "${total:-0}" "$plateau" | tee -a "$OUT/summary.txt"

  case "$line" in
    *FAILED*)
      echo ">>> REPRO on seed $s -> $log (coverage: $OUT/corpus/$s.bin)"
      echo ">>> REPRO seed=$s build=$commit" >> "$OUT/summary.txt"
      [ "$STOP_ON_REPRO" = 1 ] && break
      ;;
    *)
      rm -f "$log"  # keep only interesting logs
      ;;
  esac
done

echo "Done at $(date -Is): $runs runs, $(cat "$OUT/corpus.txt" 2>/dev/null | wc -l) corpus seeds."
echo "Final coverage: $(python3 -c "import os;print(sum(1 for x in open('$COV_MAP','rb').read() if x) if os.path.exists('$COV_MAP') else 0)") edges."
grep FAILED "$OUT/summary.txt" 2>/dev/null || echo "No repros."
