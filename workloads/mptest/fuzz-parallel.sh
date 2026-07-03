#!/usr/bin/env bash
# Launch N mptest fuzzers in parallel, each in its own output dir (<root>/wI).
# Each worker draws its own random seeds from /dev/urandom, so they explore
# disjoint schedules with no coordination needed.
#
# Two modes:
#   default        N fuzz.sh workers (plain PCT seed sweep).
#   COVERAGE=1     N fuzz-cov.sh workers sharing ONE global edge-coverage map,
#                  corpus, and plateau counter (all under <root>/coverage/,
#                  serialized with flock). Novelty and saturation are then
#                  measured fleet-wide: a seed is "new" only if it beats what
#                  every worker has covered so far, and plateau climbs only when
#                  no worker finds a new edge. Needs an instrumented image:
#                    COVERAGE=1 ./workloads/mptest/build.sh
#
# CPU is not the limit (each bedrock VM is a single vCPU); host RAM is. Each VM
# uses the flake's -m (5120 MB by default), so budget ~5 GB per worker: on a 30 GB
# box that is ~4 workers at the default guest memory.
#
# Run from the repo root, with the module loaded, /dev/bedrock present, and the
# image built (./workloads/mptest/build.sh). Warm the nix build FIRST with a
# single `nix run .#test-mptest-workload` so N workers do not all block on one
# initrd rebuild.
#
# Usage:
#   ./workloads/mptest/fuzz-parallel.sh [N]                 # N plain workers (default 4)
#   COVERAGE=1 ./workloads/mptest/fuzz-parallel.sh 4        # N coverage-guided workers
#   N=5 DURATION=3600 ./workloads/mptest/fuzz-parallel.sh
#
# Env (passed through to each worker): DURATION, RUN_TIMEOUT, STOP_ON_REPRO.
# COVERAGE=1 selects the coverage driver + shared map. OUT overrides the root dir.
#
# Watch:    tail -f <root>/w*/summary.txt
# Corpus:   tail -f <root>/coverage/corpus.txt      (COVERAGE=1: shared corpus)
# Repros:   grep -H FAILED <root>/w*/summary.txt
# Stop all: Ctrl-C here, then: pkill -f fuzz.sh; pkill -f test-mptest-workload
set -u

N=${1:-${N:-4}}
COVERAGE=${COVERAGE:-0}

if [ "$COVERAGE" = 1 ]; then
  DRIVER=./workloads/mptest/fuzz-cov.sh
  ROOT=${OUT:-fuzz-cov-runs}
else
  DRIVER=./workloads/mptest/fuzz.sh
  ROOT=${OUT:-fuzz-runs}
fi
mkdir -p "$ROOT"

# Coverage mode: set up ONE accumulation dir shared by every worker and reset it
# once here (workers never reset a shared map), so this launch starts from a
# clean global union. fuzz-cov.sh reads SHARED_COV_DIR from the environment.
if [ "$COVERAGE" = 1 ]; then
  if [ ! -f workloads/mptest/images.tar ]; then
    echo "ERROR: workloads/mptest/images.tar not found (run from the repo root)." >&2
    echo "Build an instrumented image first: COVERAGE=1 ./workloads/mptest/build.sh" >&2
    exit 1
  fi
  export SHARED_COV_DIR="$ROOT/coverage"
  mkdir -p "$SHARED_COV_DIR/corpus"
  rm -f "$SHARED_COV_DIR/coverage.map" "$SHARED_COV_DIR/plateau.state"
  : > "$SHARED_COV_DIR/.lock"
  echo "Coverage-guided: shared map $SHARED_COV_DIR/coverage.map (flock-serialized)."
fi

pids=""
cleanup() {
  echo "stopping $N workers..."
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null
  # Kill the current VM of each worker too (the nix-run children outlive the driver).
  pkill -f test-mptest-workload 2>/dev/null
}
trap cleanup INT TERM

echo "Launching $N parallel fuzzers (~5 GB RAM each): $DRIVER"
for i in $(seq 1 "$N"); do
  OUT="$ROOT/w$i" "$DRIVER" > "$ROOT/w$i.out" 2>&1 &
  pids="$pids $!"
  echo "  worker $i: pid $! -> $ROOT/w$i/ (driver log: $ROOT/w$i.out)"
done

echo "Watch:  tail -f $ROOT/w*/summary.txt"
[ "$COVERAGE" = 1 ] && echo "Corpus: tail -f $SHARED_COV_DIR/corpus.txt"
echo "Repros: grep -H FAILED $ROOT/w*/summary.txt"
wait
echo "All $N workers exited."
grep -H FAILED "$ROOT"/w*/summary.txt 2>/dev/null && echo "^ repros above" || echo "No repros."
