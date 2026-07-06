# RaceBench workload

A benchmark corpus for the concurrency-fuzz scheduler: real concurrent programs
with **pre-injected, self-observing concurrency bugs**. When a bug's specific
thread interleaving fires, the injected harness prints
`RaceBench crashes deliberately.` and `abort()`s (SIGABRT), recording the bug id
in a stat file. The crash is self-observable with **no external race detector**
(no TSan) - unlike the LLVM TSan test suite, whose races are silent without the
detector. This makes it a direct measure of whether the scheduler manufactures
the rare interleavings that trigger bugs.

Under bedrock (single vCPU + emulated TSC) the schedule is a pure function of the
getrandom stream, so a trigger reproduces from a fixed seed. Repro of a triggered
bug = `(target, input file, scheduler seed)`. Vary the seed across boots to
explore interleavings - the same fuzzing loop the concurrency-fuzz workload uses
for `queue.c`, but against real programs with ground-truth bugs.

## How it runs

Same contract as the concurrency-fuzz workload. The sched_ext fuzzing scheduler
is guest infrastructure loaded at boot (scx-init); `thread-fuzz` is bind-mounted
into the container by the guest (see `nix/podman-initrd.nix`). `run.sh` wraps
each target in `thread-fuzz`, which switches it into SCHED_EXT so the fuzzing
scheduler governs it. Nothing scheduler-specific is baked into this image.

```bash
./build.sh                          # build image -> images.tar (needs docker)
nix run .#test-racebench-workload   # boot it on the host
```

A single boot runs the corpus once under one schedule. Most seeds will NOT
trigger (a bug needs its specific interleaving); a clean `rc=0` is the expected
"no bug this seed" outcome. `rc=134` (SIGABRT) means a bug fired; the
`RACEBENCH_STAT` file records which of the target's 20 injected bugs.

## Corpus

Three PARSEC compute kernels, RaceBench variant `.1` (20 injected bugs each):
`blackscholes`, `streamcluster`, `fluidanimate`. These were chosen because they
build from source with only a base toolchain (`gcc`/`g++`/`make`/libc) - no
third-party libraries - and run cleanly (canneal, and the SPLASH-2 targets which
need K&R compiler flags, were excluded on purpose). Each target's binary is
compiled **from source** by `fuzz/Dockerfile`; the prebuilt binaries shipped by
RaceBench are never used.

To add more later: vendor another target's `code/` (instrumented source +
`racebench*.{c,h}` + its Makefile) and a few `input/` files under
`fuzz/targets/<name>/`, add its name to the loops in `fuzz/Dockerfile` and
`fuzz/run.sh`, and confirm it builds and runs clean.

## Provenance and licensing

Sources are vendored (not fetched at build time) from RaceBench, pinned to:

- Data:    https://github.com/rb130/RaceBenchData  commit `cb79cc5` (2023-04-03)
- Tooling: https://github.com/rb130/RaceBench      commit `8c4b3e8`

Only the files necessary to build and run each target are vendored (the
instrumented program source, the RaceBench harness `racebench*.{c,h}`, the
target's own Makefile/`rb-build`, and three input files). Prebuilt binaries,
`.o` files, Windows project files, sample data, and unused build variants were
dropped.

Licenses:

- The RaceBench harness (`racebench.c`, `racebench.h`, `racebench_bugs.c`,
  `racebench_bugs.h` under each `code/`) is licensed under **Mulan PSL v2** - see
  `LICENSE.racebench` (full text: http://license.coscl.org.cn/MulanPSL2).
- Each target's underlying program is from the **PARSEC** benchmark suite; the
  original copyright notice is retained at `fuzz/targets/<name>/code/src/COPYRIGHT`
  (blackscholes, fluidanimate: Intel Corp.; streamcluster: Princeton University).
