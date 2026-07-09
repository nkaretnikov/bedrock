#!/usr/bin/env bash
# Run bedrock.sh REPS times, saving each rep to its own file so the spread of the
# bedrock coverage number can be seen. Files are named:
#
#   bedrock-<host>-<date>-run<NN>.txt
#
# The counterpart to baseline_reps.sh, but the reason for reps is DIFFERENT.
# baseline_reps.sh reruns the *same* config to average out the host scheduler's
# nondeterminism. Under bedrock there is no nondeterminism: rerunning the same
# seed range reproduces byte-identical coverage, so plain reps would just write N
# identical files. What actually varies is WHICH seeds you sweep. So each rep here
# gets a DISJOINT seed window: rep i sweeps [1 + (i-1)*MAX, ...), non-overlapping
# because a single bedrock.sh run boots at most MAX times. The reps then answer:
# is the coverage number stable across independent seed windows, or does it depend
# on which seeds you happened to pick?
#
# Usage:
#   ./bedrock_reps.sh               # 10 reps, disjoint seed windows (default)
#   REPS=5 ./bedrock_reps.sh        # 5 reps
#   PLATEAU=100 ./bedrock_reps.sh   # shorter runs (passed through to bedrock.sh)
#   MAX=5000 ./bedrock_reps.sh      # smaller windows AND smaller per-rep seed stride
#
# This is a LONG, unattended job (each rep is a full bedrock.sh plateau sweep, and
# every boot is much heavier than a native run). Run it detached:
#   tmux new -s bedrock-reps   # paste this; detach with Ctrl-b d
#
# Each rep is independent: a failed rep is logged to its file (stderr captured)
# and the batch continues, so one transient boot error does not abort the run.
set -u
cd "$(dirname "$0")"

REPS="${REPS:-10}"
MAX="${MAX:-20000}"          # hard cap on boots per rep AND the per-rep seed stride
host=$(hostname -s)
date=$(date +%F)

export MAX                   # pass through to bedrock.sh (and reuse as the stride)

for i in $(seq -w 1 "$REPS"); do
  # 10#$i strips any leading zero so arithmetic is base-10, not octal.
  n=$((10#$i))
  base=$(( (n - 1) * MAX + 1 ))   # disjoint window per rep, since a rep boots <= MAX times
  echo "=== rep $i/$REPS: seed window [$base, $((base + MAX - 1))] ==="
  SEED_BASE="$base" ./bedrock.sh 2>&1 | tee "bedrock-$host-$date-run$i.txt"
done

echo "=== done: $REPS reps -> $(ls bedrock-$host-$date-run*.txt 2>/dev/null | wc -l) files ==="
