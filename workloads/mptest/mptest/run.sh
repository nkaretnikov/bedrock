#!/bin/sh
# Entrypoint for the mptest concurrency-fuzz workload.
#
#   1. Signal the VM ready (takes the boot checkpoint).
#   2. Run Bitcoin Core's libmultiprocess IPC test (mptest) under thread-fuzz in
#      a bounded loop until it crashes or hangs (the outcome we are hunting), or
#      until MAX_ITERS is reached.
#   3. Emit exactly one deterministic result line, then shut the VM down.
#
# Why loop: mptest normally passes in well under a second, so a single run rarely
# exposes the rare IPC race behind bitcoin/bitcoin#35491 (the "Make simultaneous
# IPC calls on single remote thread" hang) or #34014 ("Promise already satisfied"
# / segfault). The in-kernel sched_ext fuzzing scheduler (loaded at boot by
# scx-init) widens those windows by starving threads; running mptest repeatedly
# under it is the historical way these races surface.
#
# We opt mptest into the fuzzing scheduler by wrapping it in thread-fuzz, which
# switches itself to SCHED_EXT and then execs mptest. SCHED_EXT is inherited
# across fork+exec, so mptest AND the IPC server subprocess it spawns (plus all
# their threads) are governed by the fuzzing scheduler, while everything else
# stays on the stock scheduler. thread-fuzz is bind-mounted into the container by
# the guest (see nix/podman-initrd.nix).
#
# Determinism: under bedrock's single vCPU + emulated TSC the entire schedule is
# a pure function of the getrandom stream bedrock serves (fixed by bedrock-cli
# -s/--rdrand-seed). So the first failing iteration K and its mode are a pure
# function of the seed: the result line below is identical across boots for a
# given seed. Vary the seed to search for a schedule that reproduces the bug;
# once found, that seed replays the same failure at the same K forever.
set -eu

# Bound the loop so a seed that does not reproduce still halts the VM cleanly
# instead of running forever. Override without an image rebuild via compose env.
MAX_ITERS="${MPTEST_MAX_ITERS:-500}"
# Watchdog for the #35491 deadlock/hang: a healthy mptest finishes in << 1s, so
# anything past HANG_SECS is the hang we are looking for. timeout's SIGALRM is
# driven by the emulated TSC, so it fires at a deterministic guest-time point.
HANG_SECS="${MPTEST_HANG_SECS:-30}"
# Detection self-test (default 0 = off). When set to N>0, force a synthetic
# "FAILED ... crash" result at iteration N instead of running mptest, so the
# detect -> result-line -> fuzz.sh grep/classify -> keep-log pipeline can be
# validated end-to-end without a known-bad binary. A clean fuzzer must produce a
# repro when this is on; if it does not, detection is broken, not the search.
SELFTEST="${MPTEST_SELFTEST:-0}"
BIN=/usr/local/bin/mptest

bedrock-vmcall --ready

# Fork-based fuzzing (bedrock-lab's mptest_fuzz): the lab checkpoints and forks
# the VM at the ready hypercall above, then re-seeds each fork. Ask the in-kernel
# scheduler (scx-init) to redraw its PCT pool from getrandom now: in a forked,
# re-seeded branch that draws the branch's own randomness, so each fork explores
# a distinct schedule. Wait for it to finish so mptest never starts on the
# pre-fork pool. On the plain (non-fork) CLI path this just re-rolls the pool once
# from the same seed stream -- same determinism, one extra step. The handshake
# dir is shared with the initrd scx-init service via a bind mount (/bedrock/scx),
# and the whole tmpfs is copy-on-write per fork, so each branch has its own flags.
mkdir -p /bedrock/scx
rm -f /bedrock/scx/refill-done
: > /bedrock/scx/refill
# Bounded spin: scx-init polls ~every 100ms. Cap it (~10s) so a missing/failed
# scheduler cannot wedge the run; sleep is emulated-TSC driven, so both the wait
# count and the pool it waits for are deterministic.
w=0
while [ ! -e /bedrock/scx/refill-done ] && [ "$w" -lt 200 ]; do
	sleep 0.05
	w=$((w + 1))
done
[ -e /bedrock/scx/refill-done ] || echo "WARN: scx pool re-roll timed out; running on boot pool" >&2

result=""
i=0
while [ "$i" -lt "$MAX_ITERS" ]; do
	i=$((i + 1))

	# Self-test: synthesize a failure so the detection pipeline can be exercised
	# without a real repro. Off unless MPTEST_SELFTEST > 0.
	if [ "$SELFTEST" -gt 0 ] && [ "$i" -ge "$SELFTEST" ]; then
		result="mptest FAILED at iteration $i: crash rc=134 | SELFTEST synthetic failure (MPTEST_SELFTEST=$SELFTEST)"
		break
	fi

	rc=0
	# Capture stderr (KJ prints failures / uncaught exceptions there) so we can
	# quote the reason, e.g. "Promise already satisfied". `timeout -s KILL` turns
	# a hang into rc=137 (128+SIGKILL); plain timeout would be 124. Keep stdout
	# off the console (1>/dev/null) so only our result line is parsed downstream.
	#
	# LD_PRELOAD=libtag.so names each mptest thread by its spawn call-site
	# (see guest/scx-fuzz/libtag.c) so the in-kernel scheduler can key its
	# interleaving-coverage edges on a stable per-thread identity via comm.
	# thread-fuzz is static and ignores the preload; it only reaches mptest and
	# the IPC server it spawns (env is inherited across the SCHED_EXT exec).
	err="$(LD_PRELOAD=/usr/local/lib/libtag.so \
		timeout -s KILL "$HANG_SECS" thread-fuzz "$BIN" 2>&1 1>/dev/null)" || rc=$?

	if [ "$rc" -eq 0 ]; then
		continue
	fi

	# One-line excerpt of mptest's stderr for the result line.
	excerpt="$(printf '%s' "$err" | tr '\n\t' '  ' | tail -c 200)"
	if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
		result="mptest FAILED at iteration $i: hang rc=$rc | $excerpt"
	else
		# 134=SIGABRT, 139=SIGSEGV, or a non-zero KJ assertion failure.
		result="mptest FAILED at iteration $i: crash rc=$rc | $excerpt"
	fi
	break
done

[ -n "$result" ] || result="mptest survived $MAX_ITERS iterations (no repro on this seed)"
echo "$result"

# The result line travels an async pipeline (stderr -> conmon -> journald ->
# journalctl -> hvc0). The shutdown VMCALL halts the VM the instant it is issued,
# so without a pause the last line can be dropped before it reaches the console.
# Yield the single vCPU briefly so the journal drains first; nanosleep is driven
# by the emulated TSC, so the drain window is deterministic.
sleep 0.5

bedrock-vmcall
