#!/usr/bin/env bash
# Launch N fork-based mptest fuzzers in parallel, each a continuous campaign.
#
# Unlike fuzz-parallel.sh (which runs N fuzz.sh workers that RE-BOOT a fresh VM
# per seed), this runs N mptest_fuzz workers that each boot once per regime and
# fork many re-seeded branches off that one boot via copy-on-write -- so seeds
# cost a fork, not a Linux boot. Each worker keeps booting fresh regimes and
# forking batches until DURATION elapses. At any instant there are N live VMs
# (one per worker), so this is the "multiple VMs at once, for 24h" setup.
#
# A repro is the pair (boot_seed, child_seed): recorded in each worker's
# summary.txt and re-runnable with `mptest_fuzz --boot-seed BS --replay-child CS`.
#
# REQUIRES the guest-side pool re-roll (rebuild BOTH artifacts first):
#   ./workloads/mptest/build.sh                 # images.tar (baked run.sh)
#   git add -A                                   # so nix sees the initrd changes
# CPU is not the limit (each bedrock VM is single-vCPU); host RAM is: each worker
# holds ~5-6 GB (one live VM). Budget ~floor(free_GB / 6) workers.
#
# Usage:
#   ./workloads/mptest/fork-parallel.sh [N]                 # N workers (default 4)
#   DURATION=3600 N=3 ./workloads/mptest/fork-parallel.sh   # 1h, 3 workers
#
# Env: DURATION (total seconds, default 86400=24h), COUNT (branches per boot,
#      default 64), OUT (root dir, default fuzz-fork-runs).
#
# Watch:    tail -f fuzz-fork-runs/w*/summary.txt
# Repros:   grep -H FAILED fuzz-fork-runs/w*/summary.txt
# Stop all: Ctrl-C here (kills workers + their VMs).
set -u

N=${1:-${N:-4}}
DURATION=${DURATION:-$((24 * 3600))}
COUNT=${COUNT:-64}
OUT=${OUT:-fuzz-fork-runs}

# Disjoint seed ranges per worker so regimes (boot_seed = base + epoch) and child
# seeds never collide across workers over a long run. Strides are far above any
# realistic 24h epoch/branch count.
BOOT_STRIDE=$((1 << 40))
SEED_STRIDE=$((1 << 48))

if [ ! -f workloads/mptest/images.tar ]; then
  echo "ERROR: workloads/mptest/images.tar not found (run from the repo root)." >&2
  echo "Rebuild it with the new run.sh: ./workloads/mptest/build.sh" >&2
  exit 1
fi

mkdir -p "$OUT"

echo "Resolving guest kernel + initrd (rebuilds the initrd if sources changed)..."
K="$(nix build --no-link --print-out-paths .#guestKernel)/vmlinux"
I="$(nix build --no-link --print-out-paths .#podmanInitrd)"
echo "  vmlinux: $K"
echo "  initrd:  $I"

echo "Building mptest_fuzz (release)..."
nix develop -c cargo build --release -p bedrock-lab --example mptest_fuzz || exit 1
BIN=target/release/examples/mptest_fuzz

pids=""
cleanup() {
  echo "stopping $N workers..."
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null
  # Belt and suspenders: killing the worker frees its /dev/bedrock VM, but reap
  # any stragglers by name too.
  pkill -f 'examples/mptest_fuzz' 2>/dev/null
}
trap cleanup INT TERM

echo "Launching $N workers (~5-6 GB RAM each) for ${DURATION}s, COUNT=$COUNT/boot."
for i in $(seq 1 "$N"); do
  bs=$((i * BOOT_STRIDE))
  sb=$((i * SEED_STRIDE))
  mkdir -p "$OUT/w$i"
  nix develop -c "$BIN" "$K" "$I" \
    workloads/mptest/compose.yaml workloads/mptest/images.tar \
    --boot-seed "$bs" --seed-base "$sb" \
    --count "$COUNT" --duration-secs "$DURATION" \
    --quiet --out "$OUT/w$i" > "$OUT/w$i.log" 2>&1 &
  pids="$pids $!"
  echo "  worker $i: pid $! boot_seed_base=$bs -> $OUT/w$i/ (driver log: $OUT/w$i.log)"
done

echo "Watch:  tail -f $OUT/w*/summary.txt"
echo "Repros: grep -H FAILED $OUT/w*/summary.txt"
wait
echo "All $N workers exited."
grep -H FAILED "$OUT"/w*/summary.txt 2>/dev/null && echo "^ repros above" || echo "No repros."
