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
# SHARED_COV_DIR (set by fuzz-parallel.sh) points the map/corpus/plateau at one
# shared, flock-serialized accumulation dir so parallel workers pool coverage
# into a single global union instead of each keeping a private one.
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

# Coverage accumulation state. Standalone it lives under this driver's own OUT.
# In parallel, fuzz-parallel.sh exports SHARED_COV_DIR: one directory shared by
# every worker, so the union map, corpus, and plateau counter are fleet-wide and
# each read-modify-write merge is serialized with flock. Workers never reset a
# shared map: the launcher does that once before spawning them.
if [ -n "${SHARED_COV_DIR:-}" ]; then
  COV_DIR=$SHARED_COV_DIR
  COV_LOCK=$COV_DIR/.lock
else
  COV_DIR=$OUT
  COV_LOCK=
fi
COV_MAP=$COV_DIR/coverage.map     # accumulated per-edge max bucket (binary)
CORPUS_DIR=$COV_DIR/corpus
CORPUS_TXT=$COV_DIR/corpus.txt
COV_STATE=$COV_DIR/plateau.state  # consecutive-no-new-edge run counter

mkdir -p "$CORPUS_DIR" "$OUT/cov"
: > "$OUT/summary.txt"
if [ -z "$COV_LOCK" ]; then
  rm -f "$COV_MAP" "$COV_STATE"   # standalone owns its accumulation; start clean
fi

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

# Merge one run's coverage dump into the accumulated map and update the plateau
# counter. Prints "<new> <total> <plateau>":
#   <new>     edges whose AFL hitcount bucket increased this run (0 = nothing novel)
#   <total>   edges ever covered
#   <plateau> consecutive runs with no new edge (fleet-wide when shared)
# Buckets {1,2,3,4-7,8-15,16-31,32-127,128+} match AFL, so "ran a loop once" and
# "ran it 100 times" count as distinct coverage. When COV_LOCK is set (parallel),
# the whole read-modify-write of the map + plateau state is serialized with flock
# so concurrent workers merge into one global map without racing.
cov_merge() {
  {
    [ -n "$COV_LOCK" ] && flock 9
    python3 - "$COV_MAP" "$1" "$COV_STATE" <<'PY'
import sys, os
mappath, covpath, statepath = sys.argv[1], sys.argv[2], sys.argv[3]
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
try:
    plateau = int(open(statepath).read().strip())
except (OSError, ValueError):
    plateau = 0
plateau = 0 if new > 0 else plateau + 1
open(statepath, "w").write(str(plateau))
print(new, total, plateau)
PY
  } 9>>"${COV_LOCK:-/dev/null}"
}

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
  # <plateau> is fleet-wide when SHARED_COV_DIR is set (updated under flock).
  read -r new total plateau < <(cov_merge "$cov")
  runs=$((runs + 1))
  if [ "${new:-0}" -gt 0 ]; then
    # Keep the interesting input's coverage as the corpus to breed from later.
    mv "$cov" "$CORPUS_DIR/$s.bin"
    echo "$s new=$new total=$total" >> "$CORPUS_TXT"
  else
    rm -f "$cov"
  fi

  printf '%s  build=%s  %s  new=%s total=%s plateau=%s\n' \
    "$s" "$commit" "$line" "${new:-0}" "${total:-0}" "${plateau:-0}" | tee -a "$OUT/summary.txt"

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

echo "Done at $(date -Is): $runs runs, $(cat "$CORPUS_TXT" 2>/dev/null | wc -l) corpus seeds."
echo "Final coverage: $(python3 -c "import os;print(sum(1 for x in open('$COV_MAP','rb').read() if x) if os.path.exists('$COV_MAP') else 0)") edges."
grep FAILED "$OUT/summary.txt" 2>/dev/null || echo "No repros."
