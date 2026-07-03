# mptest concurrency-fuzz workload

Hunts the libmultiprocess IPC races behind bitcoin/bitcoin#35491 (the "make
simultaneous IPC calls on a single remote thread" hang) and #34014 ("Promise
already satisfied" / segfault) by running Bitcoin Core's `mptest` in a loop under
an in-kernel `sched_ext` chaos scheduler, inside a deterministic bedrock VM.

## How it works

- Each boot runs `mptest` repeatedly (`run.sh`) until it crashes or hangs, or
  `MPTEST_MAX_ITERS` is reached, then emits one result line and halts the VM.
- `run.sh` opts `mptest` into the fuzzing scheduler by wrapping it in
  `thread-fuzz`, which switches the process (and its forked IPC server) into
  `SCHED_EXT`. The in-guest chaos scheduler (`guest/scx-fuzz`, loaded at boot by
  `scx-init`) then starves threads in bursts to widen the race window.
- Under bedrock's single vCPU + emulated TSC, the entire schedule is a pure
  function of the getrandom stream, which is fixed by the RDRAND seed. So a seed
  that reproduces a failure is a permanent, replayable repro.
- The chaos profile (starvation timescale, gap, victim density, timeslice) is
  drawn fresh per boot from that same seed-driven stream, so different seeds
  explore genuinely different scheduling regimes rather than one fixed profile.

## Prerequisites

- The bedrock kernel module loaded and `/dev/bedrock` present.
- For `build.sh` only: a `docker` daemon and a Bitcoin Core checkout with the
  vendored libmultiprocess at `$BITCOIN_SRC/src/ipc/libmultiprocess`
  (`BITCOIN_SRC` defaults to `$HOME/dev/bitcoin`).

## Build

There are two artifacts. You usually only rebuild the initrd.

1. Container image (`images.tar`): bakes `mptest` + `run.sh`. Rebuild only when
   `run.sh`, the Dockerfile, or the mptest source changes:

   ```bash
   ./workloads/mptest/build.sh
   # BITCOIN_SRC=/path/to/bitcoin ./workloads/mptest/build.sh   # other revision
   ```

   This also writes `images.tar.meta`, recording the Bitcoin / libmultiprocess
   revision the image was built from (surfaced in the fuzz log for reproducibility).

2. Guest initrd (the `sched_ext` scheduler + `scx-init`): built by nix from
   `guest/scx-fuzz`. It rebuilds automatically on the next `nix run`. Stage your
   changes first so the flake sees them:

   ```bash
   git add -A
   nix run .#test-mptest-workload    # compiles the scheduler, boots one seed
   ```

   Neither the bedrock kernel module nor the guest kernel needs rebuilding for
   scheduler changes.

## Run a single seed

```bash
BEDROCK_RDRAND_SEED=0x<seed> nix run .#test-mptest-workload
```

Without `BEDROCK_RDRAND_SEED` the run uses the fixed default seed (a single
deterministic run). Each boot prints its chaos profile:

```
scx-fuzz profile:       starve=..us gap=..us reroll=..us slice=..us low=1/N cap=N%
scx-fuzz profile-exact: starve_min_ns=.. starve_max_ns=.. ... starve_cap_pct=..
```

## Fuzz

### One driver

```bash
./workloads/mptest/fuzz.sh                  # up to 24h, stop on first repro
DURATION=3600 ./workloads/mptest/fuzz.sh    # 1h budget
STOP_ON_REPRO=0 ./workloads/mptest/fuzz.sh  # collect every repro, keep going
```

### In parallel (recommended)

Each bedrock VM is single-vCPU, so CPU is not the limit: host RAM is (each VM
uses ~5 GB). The launcher runs N drivers, each in its own output dir, each
drawing independent random seeds.

```bash
# Warm the build once so N workers do not all rebuild the initrd at once:
nix run .#test-mptest-workload

# Launch 4 workers (~5 GB each = ~20 GB):
./workloads/mptest/fuzz-parallel.sh 4
```

Watch and collect across all workers:

```bash
tail -f fuzz-runs/w*/summary.txt
grep -H FAILED fuzz-runs/w*/summary.txt
```

Stop everything:

```bash
# Ctrl-C the launcher, then clean up any in-flight VM:
pkill -f fuzz.sh; pkill -f test-mptest-workload
```

Pick N by RAM, not cores: at ~5 GB/VM, budget roughly `floor(free_GB / 5)` and
leave headroom for the host. Prefix with `STOP_ON_REPRO=0` to keep all workers
hunting after a find.

## Reproduce a repro

A found seed replays the same crash at the same iteration, given the same build.
`fuzz.sh` keeps the full console log only for FAILED seeds and records a complete
recipe in `summary.txt`:

- `# build:` header: bedrock commit + `images.tar` sha256
- `# mptest:` header: Bitcoin / libmultiprocess revision
- per-seed line: `<seed> build=<commit> <result> [pool[0] | profile-exact]`
- FAILED seeds also get a `>>> repro build:` line with the exact guest nix store
  hashes (initrd = scheduler build, `vmlinux` = guest kernel)

To replay, pin the same build (commit / store hashes) and run the seed:

```bash
BEDROCK_RDRAND_SEED=0x<seed> nix run .#test-mptest-workload
```

Confirm determinism by running a repro seed 2-3 times: the result line and the
`profile-exact` line must be identical each time.

Note: editing `draw_profile` in `scx-init.c` re-maps every seed (it shifts the
getrandom stream), so freeze the scheduler source once a hunt is underway, or use
the logged `profile-exact` values to reconstruct the exact regime.

## Validate detection

Before trusting a long sweep, confirm the crash-detection pipeline actually
fires. Set `MPTEST_SELFTEST` (via `compose.yaml`) to force a synthetic FAILED at
a chosen iteration, run once, and confirm `fuzz.sh` reports and keeps it.

## Environment knobs

Fuzz drivers (`fuzz.sh`, `fuzz-parallel.sh`):

| Var | Default | Meaning |
| --- | --- | --- |
| `DURATION` | `86400` | Total wall-clock budget, seconds. |
| `RUN_TIMEOUT` | `3600` | Per-run host-side wedge guard, seconds. |
| `STOP_ON_REPRO` | `1` | 1: stop at first FAILED; 0: keep fuzzing. |
| `OUT` | `fuzz-runs` | Output dir (per-worker under the launcher). |

Workload (set in `compose.yaml`, no image rebuild needed except as noted):

| Var | Default | Meaning |
| --- | --- | --- |
| `MPTEST_MAX_ITERS` | `500` | Loop bound before giving up on a seed. |
| `MPTEST_HANG_SECS` | `30` | Per-iteration hang watchdog, seconds. |
| `MPTEST_SELFTEST` | `0` | >0: force a synthetic FAILED at iteration N. |
| `BEDROCK_RDRAND_SEED` | fixed default | Seed for the schedule (set by the fuzzers). |

## Files

| Path | Role |
| --- | --- |
| `run.sh` | Container entrypoint: the mptest loop + result classification. |
| `build.sh` | Builds `images.tar` (+ provenance sidecar). |
| `fuzz.sh` | Single-driver seed sweep. |
| `fuzz-parallel.sh` | Runs N `fuzz.sh` workers in parallel. |
| `compose.yaml` | Compose service + runtime env knobs. |
| `mptest/` | Dockerfile + sources for the image. |

The scheduler itself lives in `guest/scx-fuzz` (BPF `main.bpf.c` + `scx-init.c`),
and `thread-fuzz` (the SCHED_EXT opt-in) is bind-mounted into the container by the
guest.
