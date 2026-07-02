# syntax=docker/dockerfile:1
#
# mptest concurrency-fuzz workload image: Bitcoin Core's libmultiprocess IPC
# test binary (mptest) plus the VMCALL ready/shutdown helper.
#
# The mptest source is the *vendored* copy from a local Bitcoin Core checkout
# (src/ipc/libmultiprocess), staged into this build context by build.sh. That
# tree is a self-contained CMake project, so we build only the `mptest` target
# (Cap'n Proto + cmake) rather than all of Bitcoin Core, while keeping the exact
# vendored code so file/line numbers match the upstream issues (#35491, #34014).
#
# The fuzzing scheduler is NOT in this image. It is a generic guest capability:
# the sched_ext BPF scheduler and its init service (scx-init) live in the initrd
# (see nix/podman-initrd.nix) and load once at boot. The thread-fuzz helper,
# which opts a process into the scheduler, is bind-mounted into the container by
# the guest (not baked here); run.sh wraps mptest in it.
#
# Multi-stage: the build stage carries the full C++ toolchain, but the runtime
# image ships only the mptest binary, the Cap'n Proto / KJ shared objects it
# actually links, and libstdc++. This matters because the guest unpacks the
# image into RAM-backed podman storage; a fat single-stage image (toolchain +
# build tree) overflows it ("no space left on device"). `timeout` (run.sh's hang
# watchdog) comes from coreutils, already in the slim base.
#
# Build context is this directory (mptest/); build.sh stages guest/libvmcall.h
# and the vendored libmultiprocess/ tree in.

FROM debian:trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake libcapnp-dev capnproto pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Vendored libmultiprocess subtree (staged by build.sh). Build just the mptest
# target; BUILD_TESTING is forced on so the test executable is configured even
# if the standalone default differs.
COPY libmultiprocess ./libmultiprocess
RUN cmake -B build -S libmultiprocess -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --target mptest -j"$(nproc)"
# The mptest binary lands under build/ (typically build/test/mptest); locate it
# robustly rather than hard-coding the path.
RUN install -D "$(find build -type f -name mptest -perm -u+x | head -n1)" /out/mptest

# VMCALL helper: no third-party deps, so link it static.
COPY vmcall.c libvmcall.h ./
RUN gcc -O2 -static -o /out/bedrock-vmcall vmcall.c

# Stage exactly the Cap'n Proto / KJ shared objects mptest links (libcapnp,
# libcapnp-rpc, libkj, libkj-async, libkj-test), resolved via ldd so this stays
# correct across capnp version bumps. glibc/libstdc++ come from the runtime base.
RUN mkdir -p /out/lib \
 && ldd /out/mptest | awk '/=> \//{print $3}' | grep -E '/lib.*(capnp|kj)' \
      | xargs -I{} cp -v {} /out/lib/

FROM debian:trixie-slim
# libstdc++6 (pulls libgcc-s1) for mptest's C++ runtime.
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/lib/ /usr/lib/x86_64-linux-gnu/
RUN ldconfig
COPY --from=build /out/mptest          /usr/local/bin/mptest
COPY --from=build /out/bedrock-vmcall  /usr/local/bin/bedrock-vmcall
COPY run.sh /usr/local/bin/run.sh
# Fail the build now (not at guest runtime) if any runtime lib is missing.
RUN chmod +x /usr/local/bin/run.sh && ldd /usr/local/bin/mptest
ENTRYPOINT ["/usr/local/bin/run.sh"]
