#!/usr/bin/env bash
# Bedrock coverage for the RaceBench corpus, via FORK-BASED fuzzing: how many of
# the 60 injected bugs the concurrency-fuzz scheduler reaches UNDER bedrock
# (single vCPU, emulated TSC, thread-fuzz SCHED_EXT). Counterpart to baseline.sh:
# run the two and compare TOTALs.
#
# WHY FORK (not cold boot per seed). The strict late-inject abort (a late
# APIC-timer delivery aborts the run) fires during EARLY BOOT, so cold-booting a
# fresh guest per seed is no longer viable. Instead we boot ONE parent guest to
# the post-boot ready checkpoint and hold it there, then fork a re-seeded child
# per seed off it (copy-on-write):
#   - the expensive boot (kernel + podman + image load) is paid ONCE and shared;
#   - the early-boot late injects happen only in the throwaway parent, which
#     tolerates them (BEDROCK_IGNORE_LATE_INJECT=1, set by the parent app);
#   - each scored child runs STRICT, so a late inject inside a real schedule
#     aborts and is caught (logged here as a LATE-INJECT ABORT) rather than
#     silently diverging.
#
# A child's schedule is a pure function of its child seed (the getrandom stream
# the in-kernel fuzzing scheduler draws), exactly as a cold boot's was, so
# coverage still comes from sweeping the CHILD seed across forks, not from
# re-running one seed. Because it is deterministic, this sweep needs no reps:
# re-running the same (boot_seed, child-seed range) reproduces byte-identical
# coverage. The repro of a triggered bug is (target, input, boot_seed, child_seed).
#
# Each fork runs the full corpus (all three targets) once and prints one line per
# target to serial:
#   "<name>: BUG TRIGGERED (rc=134) bug_ids: 3 7"   or   "<name>: no trigger ..."
# We union bug_ids per target across forks and plateau per target, exactly like
# baseline.sh -- same PLATEAU/MAX semantics so the numbers are comparable.
#
# Prerequisites (run this ON THE HOST where bedrock is loaded, e.g. galactus):
#   - bedrock module loaded (lsmod | grep bedrock) and /dev/bedrock present
#   - workload image built: cd .. && ./build.sh
#   - the seed knobs drive bedrock-cli -s: BOOT_SEED for the parent boot,
#     RDRAND_SEED for each child fork (see the fork apps in flake.nix).
#
# Usage (capture to a dated, host-tagged file like the baseline does):
#   ./bedrock.sh 2>&1 | tee "bedrock-$(hostname -s)-$(date +%F).txt"
#
# WARNING: PLATEAU=500 is still many forks; a fork is far cheaper than a cold
# boot (no Linux boot) but not free. Start small to sanity check, e.g.
# PLATEAU=20 MAX=100 ./bedrock.sh, then raise for the real number.
#
# Env knobs:
#   SEED_BASE   first CHILD seed; fork i uses SEED_BASE + (i-1)      (default 1)
#   BOOT_SEED   parent boot seed; fixes the one-time throwaway boot  (default 0)
#   PLATEAU     stop a target after this many forks add no new bug   (default 500)
#   MAX         hard cap on forks                                    (default 20000)
#   PARENT_READY_TIMEOUT  seconds to wait for the parent to reach
#               the ready checkpoint before giving up               (default 300)
#   BEDROCK_PREEMPT_PERIOD  forced-preempt period per child, retired
#               instructions                                        (default 0=off)
#   BEDROCK_WATCHPOINT_PCT  EPT write-watchpoint directed-preempt
#               chance % per shared write                           (default 0=off)
#   BEDROCK_WATCHPOINT_REARM  sampling re-arm interval, emulated-TSC
#               ticks; 0 uses the CLI default (100k)                (default 0)
#   BEDROCK_WATCHPOINT_CULL_EPOCHS  cull a watched page after N
#               epochs without spanning a switch                    (default 2)
#   BEDROCK_WATCHPOINT_CULL_CAP  fault-count backstop cull          (default 256)
# The preempt/watchpoint knobs are recorded in the run header so a triggered
# bug's repro -- (guest build, boot_seed, child_seed, these knobs) -- is complete.
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT=$(cd ../../.. && pwd)     # scripts -> racebench -> workloads -> repo root
SEED_BASE="${SEED_BASE:-1}"         # first CHILD seed; fork i uses SEED_BASE + (i-1)
BOOT_SEED="${BOOT_SEED:-0}"         # parent boot seed (one-time throwaway boot)
PLATEAU="${PLATEAU:-500}"           # stop a target after this many forks add no new bug
MAX="${MAX:-20000}"                 # hard cap on forks
PARENT_READY_TIMEOUT="${PARENT_READY_TIMEOUT:-300}"
PREEMPT_PERIOD="${BEDROCK_PREEMPT_PERIOD:-0}"   # forced-preempt period per child (retired instrs); 0=off
WATCHPOINT_PCT="${BEDROCK_WATCHPOINT_PCT:-0}"   # EPT write-watchpoint directed-preempt chance % per shared write; 0=off (much slower per fork: use a small MAX)
# Watchpoint tuning knobs. Defaults mirror bedrock-cli's own defaults, so an
# unset knob forwards the same value the CLI would have picked and behavior is
# unchanged: the point of forwarding them explicitly is that they land in the
# run header below, so a triggered bug's repro is complete. Inert when
# WATCHPOINT_PCT=0 (the CLI reads them only when watchpoints are on). The
# watchpoint decision seed is deliberately NOT forwarded: it defaults to the
# child's RDRAND seed, so the watchpoint schedule sweeps with the child seed.
WATCHPOINT_REARM="${BEDROCK_WATCHPOINT_REARM:-0}"        # sampling re-arm interval (emulated-TSC ticks); 0=CLI default (100k)
WATCHPOINT_CULL_EPOCHS="${BEDROCK_WATCHPOINT_CULL_EPOCHS:-2}"   # cull a page after N epochs without spanning a switch
WATCHPOINT_CULL_CAP="${BEDROCK_WATCHPOINT_CULL_CAP:-256}"       # fault-count backstop cull
# Hardware data-breakpoint race detector (DataCollider-style). Layered on the EPT
# watchpoint sampler (needs WATCHPOINT_PCT>0 for candidates): confirmed-shared
# writes arm a DR on the exact address, and a #DB from a different thread is a
# realized race (surfaced as wp_dr_conflicts). Fires ONLY on an actual conflict,
# and arming costs no INVEPT. WATCHPOINT_DR=0 = EPT-only behavior.
WATCHPOINT_DR="${BEDROCK_WATCHPOINT_DR:-0}"                     # enable DR race detector; 0=off
WATCHPOINT_DR_LEN="${BEDROCK_WATCHPOINT_DR_LEN:-4}"            # DR watch width in bytes (1/2/4/8)
WATCHPOINT_DR_ONESHOT="${BEDROCK_WATCHPOINT_DR_ONESHOT:-1}"   # disarm a slot on first conflict; 0=keep armed
# DR candidate RIP-window filter. Only arm a DR when the racy access faults from
# [RIP_LO, RIP_HI): keeps library-internal shared writes (malloc/futex/stdio,
# whose RIPs live in the 0x7f... shared-object mapping) from monopolizing the 4
# slots, so cold in-target race sites (the rb_state bug words, faulted from the
# PIE target text) actually get watched. Default HI=0x7f0000000000 excludes the
# whole shared-library region while keeping target (0x55...) and the low static
# helper. To watch ONLY the PIE target region (also excluding the 0x42b617 static
# helper), tighten to LO=0x550000000000 HI=0x570000000000. RIP_HI=0 = filter off.
WATCHPOINT_DR_RIP_LO="${BEDROCK_WATCHPOINT_DR_RIP_LO:-0}"          # arm-window low bound (inclusive)
WATCHPOINT_DR_RIP_HI="${BEDROCK_WATCHPOINT_DR_RIP_HI:-0x7f0000000000}"  # arm-window high bound (exclusive); 0=off
# Per-fork wall-clock timeout (seconds). A child that livelocks (no forward
# progress -- e.g. under heavy forced preemption) would otherwise hang the whole
# sweep, since a fork has no internal watchdog visible here. On timeout the child
# is killed and counted as a no-trigger fork (its schedule is deterministic, so a
# timed-out seed reproduces). 0 disables the timeout (old behavior).
FORK_TIMEOUT="${FORK_TIMEOUT:-120}"
# Circuit breaker. A per-fork leak on the held parent (child VM slots filling the
# kernel's fixed MAX_TRACKED_VMS=1024 table -> ENOSPC, or the parent process being
# OOM-killed under an accumulating COW/Arc leak -> parent-not-found) makes EVERY
# subsequent fork fail the same way. Without a breaker the sweep grinds all the
# way to MAX firing thousands of doomed forks (a 6000-fork run wasted ~4900 that
# way and hid the cause). Abort after this many CONSECUTIVE non-clean forks: an
# occasional timeout/late-inject resets the counter when the next fork completes,
# but a systemic break trips it fast and prints the captured child error. 0=off.
FAIL_ABORT="${FAIL_ABORT:-25}"
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

# --- Build fingerprint ------------------------------------------------------
# A repro is (guest build, boot_seed, child_seed), not just the seeds. The guest
# kernel + initrd are byte-reproducible (nix), but a change under crates/
# legitimately produces a different guest, so record what this sweep ran against:
# the resolved store paths (content-exact even on a dirty tree), the workload
# image hash, and the bedrock commit. A later repro asserts these match; a
# mismatch means "different guest," not "flaky." `nix eval` resolves the paths
# without building (they were already built to run). Printed to stdout so it
# lands in the tee'd result file as a self-contained header.
commit=$(cd "$REPO_ROOT" && git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
[ -n "$(cd "$REPO_ROOT" && git status --porcelain 2>/dev/null)" ] && commit="$commit+dirty"
guest_kernel=$(cd "$REPO_ROOT" && nix eval --raw .#guestKernel.outPath 2>/dev/null || echo unknown)
guest_initrd=$(cd "$REPO_ROOT" && nix eval --raw .#podmanInitrd.outPath 2>/dev/null || echo unknown)
img_sha=$(sha256sum "$REPO_ROOT/workloads/racebench/images.tar" 2>/dev/null | cut -c1-16)
echo "--- guest-build: commit=$commit images.tar=sha256:$img_sha ---"
echo "--- guest-build: kernel=$guest_kernel ---"
echo "--- guest-build: initrd=$guest_initrd ---"

# --- Boot the fork parent once and capture its vm_id ------------------------
# The parent app boots to the ready checkpoint and HOLDS there (bedrock-cli
# --wait) tolerating early-boot late injects; children fork off its frozen,
# copy-on-write state. We run it in the background, tail its log for the
# "vm_id=N" line the CLI prints at the ready checkpoint, then fork children off N.
parent_log=$(mktemp)
parent_pid=""
cleanup() {
  # Release the held parent so its VM is freed (bedrock-cli's Ctrl-C handler on
  # SIGINT, or plain process exit -> fd close -> the kernel drops the VM).
  # SIGINT-ing the background subshell may not reach the bedrock-cli grandchild
  # under `nix run`, so also target the held parent directly: the `--wait` flag
  # uniquely marks it (child forks never use --wait). No child fork is running
  # during EXIT cleanup, so this cannot hit a scored fork.
  [ -n "$parent_pid" ] && kill -INT "$parent_pid" 2>/dev/null || true
  pkill -INT -f 'bedrock-cli.*--wait' 2>/dev/null || true
  [ -n "$parent_pid" ] && wait "$parent_pid" 2>/dev/null || true
  rm -f "$parent_log"
}
trap cleanup EXIT INT TERM

echo "--- booting fork parent (boot_seed=$BOOT_SEED); tolerating early-boot late injects ---" >&2
( cd "$REPO_ROOT" && BOOT_SEED="$BOOT_SEED" nix run .#test-racebench-fork-parent >"$parent_log" 2>&1 ) &
parent_pid=$!

PARENT_ID=""
deadline=$(( $(date +%s) + PARENT_READY_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$parent_pid" 2>/dev/null; then
    echo "ERROR: fork parent exited before reaching the ready checkpoint. Parent log:" >&2
    cat "$parent_log" >&2
    exit 1
  fi
  # The CLI logs "... vm_id=N" at the ready checkpoint. Take the first match.
  PARENT_ID=$(sed -n 's/.*vm_id=\([0-9][0-9]*\).*/\1/p' "$parent_log" | head -1)
  [ -n "$PARENT_ID" ] && break
  sleep 1
done
if [ -z "$PARENT_ID" ]; then
  echo "ERROR: fork parent did not reach the ready checkpoint within ${PARENT_READY_TIMEOUT}s. Parent log:" >&2
  cat "$parent_log" >&2
  exit 1
fi
echo "--- fork parent ready: vm_id=$PARENT_ID (boot_seed=$BOOT_SEED) ---" >&2

declare -A reached                  # target -> space-separated union of bug ids
declare -A noNew                    # target -> consecutive forks with no new bug
for t in "${TARGETS[@]}"; do reached[$t]=""; noNew[$t]=0; done

echo "--- bedrock coverage (fork): boot_seed=$BOOT_SEED seed_base=$SEED_BASE plateau=$PLATEAU max=$MAX preempt_period=$PREEMPT_PERIOD watchpoint_pct=$WATCHPOINT_PCT watchpoint_rearm=$WATCHPOINT_REARM watchpoint_cull_epochs=$WATCHPOINT_CULL_EPOCHS watchpoint_cull_cap=$WATCHPOINT_CULL_CAP watchpoint_dr=$WATCHPOINT_DR watchpoint_dr_len=$WATCHPOINT_DR_LEN watchpoint_dr_oneshot=$WATCHPOINT_DR_ONESHOT watchpoint_dr_rip_lo=$WATCHPOINT_DR_RIP_LO watchpoint_dr_rip_hi=$WATCHPOINT_DR_RIP_HI ---"

forks=0
aborts=0
consec_fail=0                       # consecutive non-clean forks; feeds the circuit breaker
while [ "$forks" -lt "$MAX" ]; do
  # Stop once every target has plateaued.
  done_all=1
  for t in "${TARGETS[@]}"; do
    [ "${noNew[$t]}" -lt "$PLATEAU" ] && done_all=0
  done
  [ "$done_all" -eq 1 ] && break

  # Parent-liveness recheck. The held fork parent was verified once at boot, but a
  # long sweep can outlive it: an accumulating per-fork leak can get the 5GB parent
  # OOM-killed, after which every child forks off a dead parent_id and fails. Catch
  # that here with a clear cause instead of grinding out doomed forks to MAX.
  if [ -n "$parent_pid" ] && ! kill -0 "$parent_pid" 2>/dev/null; then
    echo "ERROR: fork parent (pid $parent_pid, vm_id=$PARENT_ID) died at fork $forks -- every subsequent fork would fail off a dead parent. Stopping. Parent log tail:" >&2
    tail -20 "$parent_log" >&2 2>/dev/null || true
    break
  fi

  seed=$((SEED_BASE + forks))
  forks=$((forks + 1))

  # One deterministic fork of the whole corpus off the held parent. A triggered
  # bug aborts a target (rc=134) but the guest logs the line and runs to
  # shutdown, so the child exits 0. A late-inject abort makes the child exit
  # non-zero; capture rc without tripping `set -e`.
  child_rc=0
  # `timeout` (coreutils) bounds a livelocking fork; FORK_TIMEOUT=0 disables it.
  # SIGKILL after a short grace so a wedged child cannot ignore the signal.
  timeout_cmd=()
  [ "$FORK_TIMEOUT" != "0" ] && timeout_cmd=(timeout --kill-after=10 "$FORK_TIMEOUT")
  out=$(cd "$REPO_ROOT" && "${timeout_cmd[@]}" env BEDROCK_PARENT_ID="$PARENT_ID" RDRAND_SEED="$seed" \
        BEDROCK_PREEMPT_PERIOD="$PREEMPT_PERIOD" \
        BEDROCK_WATCHPOINT_PCT="$WATCHPOINT_PCT" \
        BEDROCK_WATCHPOINT_REARM="$WATCHPOINT_REARM" \
        BEDROCK_WATCHPOINT_CULL_EPOCHS="$WATCHPOINT_CULL_EPOCHS" \
        BEDROCK_WATCHPOINT_CULL_CAP="$WATCHPOINT_CULL_CAP" \
        BEDROCK_WATCHPOINT_DR="$WATCHPOINT_DR" \
        BEDROCK_WATCHPOINT_DR_LEN="$WATCHPOINT_DR_LEN" \
        BEDROCK_WATCHPOINT_DR_ONESHOT="$WATCHPOINT_DR_ONESHOT" \
        BEDROCK_WATCHPOINT_DR_RIP_LO="$WATCHPOINT_DR_RIP_LO" \
        BEDROCK_WATCHPOINT_DR_RIP_HI="$WATCHPOINT_DR_RIP_HI" \
        nix run .#test-racebench-fork-child 2>&1) || child_rc=$?

  # Classify the fork. A timed-out fork (timeout exits 124, or 137 if it needed
  # SIGKILL) is checked first: it is a livelock/too-slow schedule that was killed,
  # contributes no coverage, but still counts toward the plateau (falls through to
  # the bug-id parse below, which finds no triggers). `case` (not `printf |
  # grep -q`) avoids the pipefail/SIGPIPE trap noted above.
  fork_ok=0                          # set only when the child prints the OK marker; resets the breaker
  if [ "$child_rc" = 124 ] || [ "$child_rc" = 137 ]; then
    aborts=$((aborts + 1))
    echo "fork $forks seed $seed: TIMEOUT after ${FORK_TIMEOUT}s (livelock/too slow; killed, rc=$child_rc)" >&2
  else
  case "$out" in
    *"RaceBench workload: OK"*) fork_ok=1 ;;
    *"Late-inject abort"*|*"injected late"*)
      # A late inject INSIDE a scored schedule: the child could not be delivered
      # deterministically. This is the signal the strict abort exists to surface
      # -- the schedule is not reproducible, so it contributes no coverage. If
      # these are frequent, the host PEBS margin is too small for the fork regime.
      aborts=$((aborts + 1))
      echo "fork $forks seed $seed: LATE-INJECT ABORT (non-reproducible schedule; rc=$child_rc)" >&2
      ;;
    *)
      echo "fork $forks seed $seed: WARNING fork did not complete cleanly (no OK marker, rc=$child_rc)" >&2
      # Dump the child's tail so the FAILURE REASON is captured, not discarded. A
      # fork that cannot start (dead parent, VM cap, OOM) prints no exit-stats
      # block, so without this the log records only "rc=1" and the cause is lost --
      # exactly what made the ~1100-fork cliff undiagnosable. Tail only (the block
      # is short on failure) and indent so it is greppable as fork-child-err.
      printf '%s\n' "$out" | tail -20 | sed "s/^/fork $forks seed $seed: fork-child-err| /" >&2
      ;;
  esac
  fi

  # Circuit breaker. A clean fork resets the streak; any non-clean fork extends it.
  # A systemic break (ENOSPC once the parent's VM table fills, or a dead parent)
  # fails every fork the same way, so the streak reaches FAIL_ABORT quickly. Abort
  # then, rather than firing thousands more doomed forks -- the fork-child-err dump
  # just above names the cause (e.g. "Failed to create VM: ENOSPC" = 1024-slot VM
  # table full = per-fork slot leak; "parent ... not found" = parent process gone).
  if [ "$fork_ok" = 1 ]; then
    consec_fail=0
  else
    consec_fail=$((consec_fail + 1))
    if [ "$FAIL_ABORT" != 0 ] && [ "$consec_fail" -ge "$FAIL_ABORT" ]; then
      echo "ERROR: $consec_fail consecutive forks failed to complete cleanly (through fork $forks, seed $seed) -- systemic break, not a coverage result. Stopping the sweep. See the fork-child-err lines above for the cause (ENOSPC = kernel VM-table full; parent-not-found = parent died). Set FAIL_ABORT=0 to disable this breaker." >&2
      break
    fi
  fi

  # Parse "<name>: BUG TRIGGERED (rc=...) bug_ids: 3 7" lines; update per-target
  # union and plateau counters. Targets with no trigger this fork just increment.
  # The guest lines reach us with a console prefix, e.g.
  #   "[vt   28.79] [fuzz] | streamcluster: BUG TRIGGERED (rc=134) bug_ids: 3 7"
  # so match the target name ANYWHERE on the line, not anchored at column 0. An
  # aborted fork simply has no trigger lines and counts as "no new".
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

  # Per-fork progress to stderr (kept off the stdout summary). `slowest-plateau`
  # is min(noNew) across targets: the sweep ends when it reaches PLATEAU, and it
  # resets to 0 whenever any target finds a new bug. `tail -f` the tee'd log.
  total_now=0; minplat="$PLATEAU"
  for t in "${TARGETS[@]}"; do
    c=$(echo "${reached[$t]}" | wc -w); total_now=$((total_now + c))
    [ "${noNew[$t]}" -lt "$minplat" ] && minplat="${noNew[$t]}"
  done
  [ -n "$newmsg" ] && newmsg=" NEW:$newmsg"
  echo "fork $forks seed $seed: coverage ${total_now}/60; slowest-plateau ${minplat}/${PLATEAU}${newmsg}" >&2

  # DR race-detector harvest. The child prints ONE exit-stats block per fork (the
  # whole corpus runs in one child), so its `dr_conflicts=` count and the
  # `dr_conflict[i]: gva=.. rip=..` samples live in $out. The classification above
  # never dumps $out, so without this the per-seed DR data is lost. Emit one
  # compact line per fork (count always, so the sweep is a per-seed dataset;
  # gva=rip sites only when nonzero) into the tee'd log. Inert when DR is off.
  if [ "$WATCHPOINT_DR" != 0 ]; then
    drc=$(printf '%s\n' "$out" | sed -n 's/.*dr_conflicts=\([0-9][0-9]*\).*/\1/p' | tail -1)
    [ -z "$drc" ] && drc=0
    # sed (not grep -oE): grep exits 1 on no-match, and under `set -o pipefail`
    # that fails the whole command substitution and `set -e` would abort the
    # sweep. A timed-out fork prints no exit-stats block, so no-match is normal.
    drsites=$(printf '%s\n' "$out" \
      | sed -n 's/.*dr_conflict\[[0-9]*\]: \(gva=0x[0-9a-f]* rip=0x[0-9a-f]*\).*/\1/p' \
      | tr '\n' ';')
    if [ "$drc" != 0 ]; then
      echo "fork $forks seed $seed: DR dr_conflicts=$drc sites: ${drsites%;}" >&2
    else
      echo "fork $forks seed $seed: DR dr_conflicts=0" >&2
    fi
  fi
done

total=0
for t in "${TARGETS[@]}"; do
  ids=$(echo "${reached[$t]}" | tr -s ' ' ' ' | sed 's/^ //; s/ $//')
  cnt=$(echo "$ids" | wc -w)
  total=$((total + cnt))
  echo "$t: reached $cnt/20 in $forks forks -> bug_ids: $ids"
done
echo "TOTAL bedrock coverage: $total/60 (boot_seed=$BOOT_SEED, $forks forks, $aborts late-inject aborts)"
