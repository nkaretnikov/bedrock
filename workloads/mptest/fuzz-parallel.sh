#!/usr/bin/env bash
# Launch N mptest fuzzers in parallel, each in its own output dir (fuzz-runs/wI).
# Each worker draws its own random seeds from /dev/urandom, so they explore
# disjoint schedules with no coordination needed.
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
#   ./workloads/mptest/fuzz-parallel.sh [N]            # N workers (default 4)
#   N=5 DURATION=3600 ./workloads/mptest/fuzz-parallel.sh
#
# Env (passed through to each fuzz.sh): DURATION, RUN_TIMEOUT, STOP_ON_REPRO.
#
# Watch:    tail -f fuzz-runs/w*/summary.txt
# Repros:   grep -H FAILED fuzz-runs/w*/summary.txt
# Stop all: Ctrl-C here, then: pkill -f fuzz.sh; pkill -f test-mptest-workload
set -u

N=${1:-${N:-4}}
mkdir -p fuzz-runs

pids=""
cleanup() {
  echo "stopping $N workers..."
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null
  # Kill the current VM of each worker too (fuzz.sh's nix-run children outlive it).
  pkill -f test-mptest-workload 2>/dev/null
}
trap cleanup INT TERM

echo "Launching $N parallel fuzzers (~5 GB RAM each)."
for i in $(seq 1 "$N"); do
  OUT="fuzz-runs/w$i" ./workloads/mptest/fuzz.sh > "fuzz-runs/w$i.out" 2>&1 &
  pids="$pids $!"
  echo "  worker $i: pid $! -> fuzz-runs/w$i/ (driver log: fuzz-runs/w$i.out)"
done

echo "Watch:  tail -f fuzz-runs/w*/summary.txt"
echo "Repros: grep -H FAILED fuzz-runs/w*/summary.txt"
wait
echo "All $N workers exited."
grep -H FAILED fuzz-runs/w*/summary.txt 2>/dev/null && echo "^ repros above" || echo "No repros."
