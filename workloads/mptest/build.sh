#!/usr/bin/env bash
# Build the mptest concurrency-fuzz workload's container image and pack it into a
# docker-archive tarball at workloads/mptest/images.tar. That file and
# compose.yaml are served to the guest at runtime over the file-transmission
# hypercall (the guest's generic initrd downloads them at boot), e.g. via
# `bedrock-cli --file compose.yaml=... --file images.tar=...`, or `nix run
# .#test-mptest-workload`. See nix/podman-initrd.nix.
#
# The image bakes Bitcoin Core's libmultiprocess IPC test (mptest) and the VMCALL
# helper. mptest is built from the *vendored* libmultiprocess copy in a local
# Bitcoin Core checkout (src/ipc/libmultiprocess), so the binary matches the
# exact code referenced by the upstream issues (#35491, #34014). Point at a
# different checkout/commit with BITCOIN_SRC to target another mptest revision
# (e.g. one that still carries #34014's "thread busy" TestCase).
#
# The fuzzing scheduler itself is guest infrastructure (sched_ext BPF + scx-init
# in nix/podman-initrd.nix), and thread-fuzz (which opts mptest in) is
# bind-mounted into the container by the guest, so neither is part of this image.
# The guest kernel must be built with sched_ext + BTF (see nix/guest-kernel.nix).
#
# Usage:  ./build.sh
#         BITCOIN_SRC=/path/to/bitcoin ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim), a local
# Bitcoin Core checkout, and network access (the image build fetches Debian
# packages).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"
BITCOIN_SRC="${BITCOIN_SRC:-$HOME/dev/bitcoin}"
LMP_SRC="$BITCOIN_SRC/src/ipc/libmultiprocess"

if [ ! -f "$LMP_SRC/CMakeLists.txt" ]; then
  echo "ERROR: vendored libmultiprocess not found at $LMP_SRC" >&2
  echo "Set BITCOIN_SRC to your Bitcoin Core checkout, e.g." >&2
  echo "  BITCOIN_SRC=/path/to/bitcoin ./build.sh" >&2
  exit 1
fi

# Stage inputs that live outside the Docker build context into it: Docker's COPY
# cannot reach files outside the context, so we copy them in here and remove them
# on exit, keeping one source of truth instead of committed dups.
#   - guest/libvmcall.h                       : shared header-only hypercall lib.
#   - guest/libfeedback.{c,h}, libpcguard.c   : coverage-feedback runtime, linked
#                                               into mptest only when COVERAGE=1.
#   - libmultiprocess/                        : vendored mptest source.
trap 'rm -rf mptest/libvmcall.h mptest/libfeedback.c mptest/libfeedback.h mptest/libpcguard.c mptest/libmultiprocess' EXIT
cp ../../guest/libvmcall.h mptest/libvmcall.h
cp ../../guest/libfeedback.c mptest/libfeedback.c
cp ../../guest/libfeedback.h mptest/libfeedback.h
cp ../../guest/libpcguard.c mptest/libpcguard.c
rm -rf mptest/libmultiprocess
# Copy the tree without its build artifacts / VCS metadata so the context stays
# small and the build is not polluted by a prior host-side cmake build dir.
cp -r "$LMP_SRC" mptest/libmultiprocess
rm -rf mptest/libmultiprocess/build mptest/libmultiprocess/.git

# Coverage build (opt-in): COVERAGE=1 compiles mptest with SanitizerCoverage
# trace-pc-guard and links the libfeedback runtime, so a run registers an edge
# coverage buffer the host reads back with `bedrock-cli --coverage-out`. Default
# (COVERAGE=0) leaves the image byte-for-byte as before.
COVERAGE="${COVERAGE:-0}"

echo "Building mptest from $LMP_SRC (COVERAGE=$COVERAGE)"
$DOCKER build --build-arg "COVERAGE=$COVERAGE" -t bedrock/mptest:latest mptest/

# Pack into one docker-archive. `podman load` inside the initrd reads the
# embedded manifest to recover the image's name+tag, so the tarball's filename
# is opaque to consumers.
$DOCKER save bedrock/mptest:latest -o images.tar

# Provenance sidecar: record which mptest source this image was built from, so a
# fuzz repro can name the exact Bitcoin Core / libmultiprocess revision. fuzz.sh
# reads this into summary.txt. The images.tar sha256 pins the content byte-exactly;
# the commits make it human-meaningful. Written next to images.tar as key=value.
btc_commit=$(git -C "$BITCOIN_SRC" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ -n "$(git -C "$BITCOIN_SRC" status --porcelain 2>/dev/null)" ]; then
  btc_commit="$btc_commit+dirty"
fi
# Last commit that touched the vendored mptest source (most relevant to behavior).
lmp_commit=$(git -C "$BITCOIN_SRC" log -1 --format=%h -- src/ipc/libmultiprocess 2>/dev/null || echo unknown)
{
  echo "built=$(date -Is)"
  echo "bitcoin_src=$BITCOIN_SRC"
  echo "bitcoin_commit=$btc_commit"
  echo "libmultiprocess_commit=$lmp_commit"
  echo "images_sha256=$(sha256sum images.tar | cut -d' ' -f1)"
} > images.tar.meta

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"
echo "Provenance: bitcoin=$btc_commit libmultiprocess=$lmp_commit -> images.tar.meta"
