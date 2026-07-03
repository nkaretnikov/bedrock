#!/usr/bin/env bash
# Fuzz bedrock RDRAND seeds against the mptest concurrency-fuzz workload, hunting
# for a schedule that reproduces the libmultiprocess IPC races (bitcoin/bitcoin
# #35491 hang, #34014 "Promise already satisfied" / segfault).
#
# Each boot runs mptest under the thread-fuzz sched_ext scheduler; the schedule
# is a pure function of the seed (see the test-mptest-workload app in flake.nix),
# so a seed that fails is a permanent, replayable repro. This driver keeps trying
# fresh random seeds until one fails or a wall-clock budget is exhausted.
#
# Run from the bedrock repo root (the flake app uses cwd-relative paths), with
# the bedrock module loaded, /dev/bedrock present, and the image already built:
#   ./workloads/mptest/build.sh
#
# Usage:
#   ./workloads/mptest/fuzz.sh                 # up to 24h, stop on first repro
#   DURATION=3600 ./workloads/mptest/fuzz.sh   # 1h budget
#   STOP_ON_REPRO=0 ./workloads/mptest/fuzz.sh # collect every repro, don't stop
#
# Run it detached so a disconnect does not kill it, e.g.:
#   tmux new -s mptest-fuzz    # then run this script
#   # or: nohup ./workloads/mptest/fuzz.sh >fuzz.log 2>&1 &
#   tail -f fuzz-runs/summary.txt
#
# Outputs (created under ./fuzz-runs/):
#   summary.txt     "# build:" header (commit + images.tar hash) then one line per
#                   seed: "<seed> build=<commit> <result> [pool[0] | profile-exact]".
#                   Each line is a self-contained repro recipe (seed + build +
#                   byte-exact rodata ns). FAILED seeds also get a ">>> repro build:"
#                   line with the exact guest nix store hashes.
#   run-<seed>.log  full guest console, KEPT only for seeds that FAILED
#
# Env knobs:
#   DURATION       total wall-clock budget in seconds (default 86400 = 24h)
#   RUN_TIMEOUT    per-run host-side wedge guard in seconds (default 3600). A
#                  normal run should finish well under this; hitting it means the
#                  guest wedged (not just a hung mptest, which run.sh catches).
#   STOP_ON_REPRO  1 (default) stop at the first FAILED seed; 0 keep fuzzing.
set -u

DURATION=${DURATION:-$((24 * 3600))}
RUN_TIMEOUT=${RUN_TIMEOUT:-3600}
STOP_ON_REPRO=${STOP_ON_REPRO:-1}
OUT=fuzz-runs

if [ ! -f workloads/mptest/images.tar ]; then
  echo "ERROR: workloads/mptest/images.tar not found (run from the repo root)." >&2
  echo "Build it first: ./workloads/mptest/build.sh" >&2
  exit 1
fi

end=$(( $(date +%s) + DURATION ))
mkdir -p "$OUT"
: > "$OUT/summary.txt"

# Build stamp: pin what this sweep ran against so any repro seed can be replayed
# against the exact same scheduler + image. `commit` fixes the source tree;
# `+dirty` warns of uncommitted changes (then trust the per-repro nix store hashes
# below, which are content-exact regardless of git state). The images.tar hash
# pins the mptest/libmultiprocess build (it is a local file, not a nix store path,
# so its content is not otherwise recorded).
commit=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
[ -n "$(git status --porcelain 2>/dev/null)" ] && commit="$commit+dirty"
img_sha=$(sha256sum workloads/mptest/images.tar 2>/dev/null | cut -c1-16)
{
  echo "# build: commit=$commit images.tar=sha256:$img_sha"
  echo "# started: $(date -Is)"
} >> "$OUT/summary.txt"

echo "Fuzzing for ${DURATION}s (until $(date -d "@$end" -Is 2>/dev/null || echo "+${DURATION}s")); stop-on-repro=$STOP_ON_REPRO"
echo "Build: commit=$commit images.tar=sha256:$img_sha"

while [ "$(date +%s)" -lt "$end" ]; do
  # Fresh random 64-bit seed as 0x-hex (bedrock-cli -s accepts hex or decimal).
  s=0x$(head -c8 /dev/urandom | od -An -tx8 | tr -d ' ')
  log="$OUT/run-$s.log"
  echo "=== $(date -Is) seed $s ==="

  # Host-side timeout guards against a wedged guest (a whole-VM hang the in-guest
  # watchdog would not catch): SIGTERM at RUN_TIMEOUT, SIGKILL 30s later.
  BEDROCK_RDRAND_SEED=$s timeout -k 30 "$RUN_TIMEOUT" \
    nix run .#test-mptest-workload > "$log" 2>&1
  rc=$?

  # The result line is guest console output, so it is not ^-anchored; match on
  # FAILED|survived to skip the workload's banner (which also contains "mptest ").
  line=$(grep -E 'mptest (FAILED|survived)' "$log" | head -1)
  if [ -z "$line" ]; then
    if [ "$rc" = 124 ]; then
      line="(no result line; rc=124 HOST-TIMEOUT/WEDGED)"
    else
      line="(no result line; rc=$rc)"
    fi
  fi
  # Record the schedule fingerprint for EVERY run (survivors included): the
  # per-boot chaos profile and pool[0], both printed by scx-init. This is the
  # audit trail that seeds actually produce distinct schedules -- if these ever
  # stop varying run-to-run, the seed is not reaching bedrock and the sweep is
  # testing one schedule. Survivor full logs are still deleted below to save disk;
  # this one summary line preserves the evidence.
  # Record the byte-exact profile (raw ns) + pool[0] + the build commit, so each
  # line is a self-contained, losslessly-reproducible recipe: <seed> + <build> +
  # exact rodata values.
  prof=$(grep -oE 'scx-fuzz profile-exact:.*' "$log" | head -1)
  fp=$(grep -oE 'pool\[0\] 0x[0-9a-f]+' "$log" | head -1)
  printf '%s  build=%s  %s  [%s | %s]\n' "$s" "$commit" "$line" "$fp" "$prof" | tee -a "$OUT/summary.txt"

  case "$line" in
    *FAILED*)
      # Stamp the exact guest build hashes from the kept log so this repro is
      # anchored even if the tree was dirty: the initrd store path pins the
      # scx-init/thread-fuzz/BPF build, vmlinux pins the guest kernel.
      guest=$(grep -oE '/nix/store/[a-z0-9]{32}-[^ ]*(bedrock-podman-rootfs|vmlinux)' "$log" | sort -u | tr '\n' ' ')
      echo ">>> REPRO on seed $s -> $log"
      echo ">>> repro build: $guest" | tee -a "$OUT/summary.txt"
      [ "$STOP_ON_REPRO" = 1 ] && break
      ;;
    *)
      rm -f "$log"  # keep only interesting logs
      ;;
  esac
done

echo "Fuzzing done at $(date -Is). Results in $OUT/summary.txt"
grep -c FAILED "$OUT/summary.txt" >/dev/null 2>&1 && \
  echo "Repro seeds:" && grep FAILED "$OUT/summary.txt" || true
