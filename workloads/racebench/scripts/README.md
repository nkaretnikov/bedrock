# RaceBench scripts

Helper scripts for the RaceBench workload.

## `baseline.sh` - native (no-bedrock) baseline

Records how many of the 60 injected bugs the host's **stock scheduler** reaches
**without bedrock** (no `thread-fuzz`, no deterministic TSC/getrandom). This is
the control to compare bedrock's concurrency-fuzz coverage against: bugs bedrock
reaches that this baseline never does are the scheduler's payoff.

It runs the *identical* from-source binaries from the workload image, inside a
container on the bare host, looping each target until coverage plateaus, and
prints the union of triggered bug ids per target plus a `TOTAL /60`.

### 1. Build and load the image

The script runs the binaries from the `bedrock/racebench:latest` image, so build
it and load it into the local container runtime first. From the workload dir
(one level up from here):

```bash
cd ..
./build.sh                       # builds targets FROM SOURCE -> images.tar
docker load -i images.tar        # load the archive into docker
```

`build.sh` defaults to `docker` (`DOCKER=docker`); it fetches Debian packages
(gcc/g++/make) during the image build, so it needs network access.

> **podman note:** `podman` is not installed on this host, so use `docker`
> (the daemon is reachable here). Everything below assumes docker. If you ever
> run somewhere with podman instead, pass `RUNTIME=podman` to `baseline.sh` and
> use `podman load -i images.tar` above.

### 2. Run the baseline

Capture each run to its own file with `tee` (so you see it live and keep the
log). Record **both** CPU configs - they answer different questions:

```bash
cd scripts

# single-core: apples-to-apples with bedrock's single vCPU (isolates the
# scheduler-fuzzing contribution from the host's parallelism)
CPUSET=0 ./baseline.sh 2>&1 | tee "baseline-$(hostname -s)-$(date +%F)-cpuset0.txt"

# all cores: the realistic "what a normal test run catches" host baseline
./baseline.sh 2>&1 | tee "baseline-$(hostname -s)-$(date +%F)-allcores.txt"
```

This produces e.g. `baseline-galactus-2026-07-07-cpuset0.txt` and
`...-allcores.txt`. The filename encodes the CPU config (the dimension being
contrasted), the host (baselines are host-specific: core count, scheduler, CPU),
and the date (so re-runs accumulate instead of clobbering).

`2>&1` matters: the header line goes to stdout and runtime errors (e.g.
image-not-found) go to stderr - you want both in the log.

### Knobs (environment variables)

| Var       | Default                  | Meaning                                              |
| --------- | ------------------------ | ---------------------------------------------------- |
| `CPUSET`  | *(empty = all cores)*    | `CPUSET=0` pins to one core (`--cpuset-cpus 0`).      |
| `PLATEAU` | `500`                    | Stop a target after this many runs add no new bug.   |
| `MAX`     | `20000`                  | Hard cap on attempts per target.                     |
| `RUNTIME` | `docker`                 | Container runtime (`podman` if available).            |
| `IMAGE`   | `bedrock/racebench:latest` | Image to run the binaries from.                    |

### Reading the output

```
blackscholes: reached 3/20 in 812 runs -> bug_ids: 2 7 14
streamcluster: reached 1/20 in 611 runs -> bug_ids: 9
fluidanimate: reached 0/20 in 500 runs -> bug_ids:
TOTAL native baseline: 4/60
```

`reached N/20` is that target's bug-id union across all attempts; `TOTAL /60` is
the baseline number. Expect it to be **low** - many RaceBench bugs need a narrow
interleaving the stock scheduler almost never hits even over thousands of tries,
which is exactly what makes bedrock's coverage number meaningful.
