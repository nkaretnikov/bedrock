# mptest concurrency-fuzz workload

Hunts the libmultiprocess IPC races behind bitcoin/bitcoin#35491 (the "make
simultaneous IPC calls on a single remote thread" hang) and #34014 ("Promise
already satisfied" / segfault) by running Bitcoin Core's `mptest` in a loop under
an in-kernel `sched_ext` PCT scheduler — Probabilistic Concurrency Testing,
Burckhardt et al. ASPLOS'10 — inside a deterministic bedrock VM.

## How it works

- Each boot runs `mptest` repeatedly (`run.sh`) until it crashes or hangs, or
  `MPTEST_MAX_ITERS` is reached, then emits one result line and halts the VM.
- `run.sh` opts `mptest` into the fuzzing scheduler by wrapping it in
  `thread-fuzz`, which switches the process (and its forked IPC server) into
  `SCHED_EXT`. The in-guest PCT scheduler (`guest/scx-fuzz`, loaded at boot by
  `scx-init`) then runs the highest-priority runnable thread and inserts a few
  randomly-placed "change points" that demote the running thread, forcing the
  rare preemptions that expose depth-d bugs. Unlike uniform chaos, PCT gives a
  probabilistic lower bound on hitting a depth-d bug, concentrating the search on
  the shallow (2-3 constraint) races these issues actually need.
- Each `mptest` iteration is a fresh process, so the scheduler draws a fresh PCT
  schedule (base priorities + change points) per execution — one boot is ~500
  independent PCT samples, not one. Change points are placed on the emulated-TSC
  clock (the deterministic proxy for PCT's step index) and demotions expire after
  a bounded window, so scheduler starvation cannot masquerade as the #35491 hang.
- Under bedrock's single vCPU + emulated TSC, the entire schedule is a pure
  function of the getrandom stream, which is fixed by the RDRAND seed. So a seed
  that reproduces a failure is a permanent, replayable repro.
- The per-boot PCT bounds (horizon range, timeslice, demotion cap, depth ceiling,
  priority spread) are drawn fresh per boot from that same seed-driven stream, so
  different seeds explore genuinely different regimes rather than one fixed one.

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
deterministic run). Each boot prints its PCT profile:

```
scx-fuzz profile:       horizon=..us slice=..us demote<=..us depth<=N spread=N
scx-fuzz profile-exact: horizon_min_ns=.. horizon_max_ns=.. ... prio_spread=..
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

## Coverage-guided fuzzing (optional)

`fuzz-cov.sh` adds an edge-coverage feedback loop on top of the PCT sweep: each
run dumps the guest's coverage buffer and the driver keeps a running union of
edge coverage (AFL hitcount buckets), recording seeds that reach new edges as a
corpus and reporting when new coverage plateaus.

It needs an **instrumented image** (the default image carries no coverage):

```bash
COVERAGE=1 ./workloads/mptest/build.sh   # clang + trace-pc-guard + libfeedback
./workloads/mptest/fuzz-cov.sh           # coverage-guided PCT sweep
tail -f fuzz-cov-runs/summary.txt        # columns include new=/total=/plateau=
```

### In parallel (shared coverage)

`COVERAGE=1 ./workloads/mptest/fuzz-parallel.sh N` runs N `fuzz-cov.sh` workers
that share **one** global edge-coverage map, corpus, and plateau counter under
`fuzz-cov-runs/coverage/`. Each worker still keeps its own per-seed
`summary.txt`, but every coverage merge is serialized with `flock` against the
shared map, so a seed counts as `new` only if it beats what *all* workers have
covered so far, and `plateau` climbs only when *no* worker finds a new edge.
That makes novelty and saturation fleet-wide instead of per-worker (independent
workers would each re-discover the same edges and plateau on their own clocks).

```bash
COVERAGE=1 ./workloads/mptest/build.sh              # once: instrumented image
nix run .#test-mptest-workload                      # warm the build
COVERAGE=1 ./workloads/mptest/fuzz-parallel.sh 4    # 4 workers, shared map
tail -f fuzz-cov-runs/coverage/corpus.txt           # shared corpus (new-edge seeds)
grep -H FAILED fuzz-cov-runs/w*/summary.txt         # repros across all workers
```

Under the hood: `COVERAGE=1` links `guest/libpcguard.c` + `libfeedback.c` into
`mptest`, which registers a `cov-<build>` feedback buffer; `bedrock-cli
--coverage-out <file>` (wired through the `BEDROCK_COVERAGE_OUT` env of the nix
app) dumps it after the run. Without instrumentation the dumps are empty and
`fuzz-cov.sh` degrades to a plain PCT seed sweep (`new=0` every run).

Scope and caveats — read before relying on the numbers:

- **This is coverage *accumulation + novelty + plateau* (Tier A), not local
  mutation.** It selects and ranks whole seeds; it cannot yet breed a seed,
  because the fuzzer input is a single PRNG seed with no positional locality
  (flip one bit and the whole schedule re-rolls). Genuine AFL-style mutation
  needs a **host-supplied positional pool input** feeding `scx-init`'s randomness
  pool (so byte range k ↔ execution k, mutable in isolation). That is designed
  but not yet wired — the two candidate paths (a file-backed GET_RANDOM source in
  the random device, or a host-side file-xfer change so `scx-init` can pull the
  pool at early boot) both touch determinism-critical code and need on-hardware
  validation. The corpus `fuzz-cov.sh` records is exactly what that phase breeds.
- **Edge coverage is *code* coverage, not *interleaving* coverage.** It rewards
  schedules that reach new code (e.g. a race-opened error path) but cannot tell
  two schedules apart when they run the same lines in a different racy order. A
  concurrency-specific metric (communication pairs, cross-context-switch PC
  pairs, or PCT-native change-point buckets — the scheduler can emit the last
  almost for free) is the stronger follow-on.

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

Note: editing `draw_profile` in `scx-init.c` (or the per-epoch draws in
`main.bpf.c`) re-maps every seed — it shifts the getrandom stream — so freeze the
scheduler source once a hunt is underway, or use the logged `profile-exact`
values to reconstruct the exact regime.

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
| `build.sh` | Builds `images.tar` (+ provenance sidecar). `COVERAGE=1` instruments mptest. |
| `fuzz.sh` | Single-driver seed sweep. |
| `fuzz-parallel.sh` | Runs N workers in parallel: `fuzz.sh`, or (with `COVERAGE=1`) `fuzz-cov.sh` sharing one global coverage map/corpus/plateau. |
| `fuzz-cov.sh` | Coverage-guided seed sweep (needs `COVERAGE=1` image). |
| `compose.yaml` | Compose service + runtime env knobs. |
| `mptest/` | Dockerfile + sources for the image. |

The scheduler itself lives in `guest/scx-fuzz` (BPF `main.bpf.c` + `scx-init.c`),
and `thread-fuzz` (the SCHED_EXT opt-in) is bind-mounted into the container by the
guest.
