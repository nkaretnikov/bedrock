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
BIN=/usr/local/bin/mptest

bedrock-vmcall --ready

result=""
i=0
while [ "$i" -lt "$MAX_ITERS" ]; do
	i=$((i + 1))
	rc=0
	# Capture stderr (KJ prints failures / uncaught exceptions there) so we can
	# quote the reason, e.g. "Promise already satisfied". `timeout -s KILL` turns
	# a hang into rc=137 (128+SIGKILL); plain timeout would be 124. Keep stdout
	# off the console (1>/dev/null) so only our result line is parsed downstream.
	err="$(timeout -s KILL "$HANG_SECS" thread-fuzz "$BIN" 2>&1 1>/dev/null)" || rc=$?

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
