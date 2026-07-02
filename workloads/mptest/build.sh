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
#   - guest/libvmcall.h : the shared header-only guest hypercall library.
#   - libmultiprocess/  : the vendored mptest source from the Bitcoin checkout.
trap 'rm -rf mptest/libvmcall.h mptest/libmultiprocess' EXIT
cp ../../guest/libvmcall.h mptest/libvmcall.h
rm -rf mptest/libmultiprocess
# Copy the tree without its build artifacts / VCS metadata so the context stays
# small and the build is not polluted by a prior host-side cmake build dir.
cp -r "$LMP_SRC" mptest/libmultiprocess
rm -rf mptest/libmultiprocess/build mptest/libmultiprocess/.git

echo "Building mptest from $LMP_SRC"
$DOCKER build -t bedrock/mptest:latest mptest/

# Pack into one docker-archive. `podman load` inside the initrd reads the
# embedded manifest to recover the image's name+tag, so the tarball's filename
# is opaque to consumers.
$DOCKER save bedrock/mptest:latest -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"
