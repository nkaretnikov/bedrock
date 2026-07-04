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

# Coverage build (opt-in, default off). When 1, mptest is compiled with
# SanitizerCoverage trace-pc-guard and linked against the libfeedback runtime, so
# a run registers an edge-coverage buffer the host reads back via
# `bedrock-cli --coverage-out`. The trace-pc-guard guard-init ABI
# (__sanitizer_cov_trace_pc_guard*) is clang-specific, so the instrumented build
# uses clang; the default (COVERAGE=0) build is the unchanged gcc build.
ARG COVERAGE=0

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake libcapnp-dev capnproto pkg-config \
      $( [ "$COVERAGE" = 1 ] && echo clang ) \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Coverage-feedback runtime (staged by build.sh): the LLVM trace-pc-guard
# frontend (libpcguard.c) over the generic hitcount backend (libfeedback.c),
# which registers the buffer with the host over the hypercall (libvmcall.h).
# Compiled WITHOUT -fsanitize-coverage (or the hooks would instrument themselves)
# and archived; only linked into mptest when COVERAGE=1.
COPY libvmcall.h libfeedback.h libfeedback.c libpcguard.c ./
RUN mkdir -p /cov \
 && if [ "$COVERAGE" = 1 ]; then \
      clang -O2 -fPIC -c libfeedback.c -o /cov/libfeedback.o && \
      clang -O2 -fPIC -c libpcguard.c  -o /cov/libpcguard.o  && \
      ar rcs /cov/libcov.a /cov/libfeedback.o /cov/libpcguard.o && \
      : "compile-only instrumentation wrappers: add -fsanitize-coverage on a" \
        "compile (-c present) but NOT on a link, so clang's driver never pulls" \
        "the compiler-rt sanitizer runtime -- which Debian's clang omits and" \
        "which we do not need, since libpcguard provides the trace-pc-guard" \
        "callbacks. This is what makes the ABI check and final link succeed" \
        "without libclang_rt; mptest's edge calls resolve from libcov.a." && \
      printf '%s\n' '#!/bin/sh' \
        'for a in "$@"; do [ "$a" = -c ] && exec clang   -fsanitize-coverage=trace-pc-guard "$@"; done' \
        'exec clang   "$@"' > /usr/local/bin/covcc && \
      printf '%s\n' '#!/bin/sh' \
        'for a in "$@"; do [ "$a" = -c ] && exec clang++ -fsanitize-coverage=trace-pc-guard "$@"; done' \
        'exec clang++ "$@"' > /usr/local/bin/covcxx && \
      chmod +x /usr/local/bin/covcc /usr/local/bin/covcxx; \
    fi

# Vendored libmultiprocess subtree (staged by build.sh). Build just the mptest
# target; BUILD_TESTING is forced on so the test executable is configured even
# if the standalone default differs. Under COVERAGE=1 every TU compiles through
# the covcc/covcxx wrappers (trace-pc-guard at compile only) and links libcov.a
# (+ --build-id, which libfeedback keys the buffer id on; + -ldl for
# dl_iterate_phdr in libfeedback). The sancov flag is deliberately NOT in
# CMAKE_*_FLAGS -- those reach the link line, which is exactly what dragged in
# the missing compiler-rt runtime.
COPY libmultiprocess ./libmultiprocess
RUN set -e; \
    if [ "$COVERAGE" = 1 ]; then \
      CC=/usr/local/bin/covcc; CXX=/usr/local/bin/covcxx; \
      # --whole-archive forces every libcov member in regardless of link order,
      # so the guard symbols are defined even in cmake's compiler-ABI check,
      # whose minimal link applies EXE_LINKER_FLAGS but not STANDARD_LIBRARIES
      # and places libs before the object (defeating normal archive resolution).
      COV_LD="-Wl,--build-id -Wl,--whole-archive /cov/libcov.a -Wl,--no-whole-archive -ldl"; \
    else \
      CC=cc; CXX=c++; COV_LD=""; \
    fi; \
    cmake -B build -S libmultiprocess -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_EXE_LINKER_FLAGS="$COV_LD" \
 && cmake --build build --target mptest -j"$(nproc)"
# The mptest binary lands under build/ (typically build/test/mptest); locate it
# robustly rather than hard-coding the path.
RUN install -D "$(find build -type f -name mptest -perm -u+x | head -n1)" /out/mptest

# VMCALL helper: no third-party deps, so link it static.
COPY vmcall.c libvmcall.h ./
RUN gcc -O2 -static -o /out/bedrock-vmcall vmcall.c

# Thread-naming LD_PRELOAD shim (libtag.so). Built here, in the image, so it
# links against the SAME Debian glibc as mptest -- a nix-built .so bind-mounted
# into this container could hit a glibc symbol-version mismatch. Dynamic (a
# preload cannot be static); -ldl for dlsym(RTLD_NEXT)/dladdr, and backtrace()
# comes from libc. run.sh LD_PRELOADs it onto the mptest invocation so each
# thread names itself by spawn call-site for the fuzzing scheduler's coverage.
COPY libtag.c ./
RUN gcc -O2 -fPIC -shared -o /out/libtag.so libtag.c -ldl

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
COPY --from=build /out/libtag.so       /usr/local/lib/libtag.so
COPY run.sh /usr/local/bin/run.sh
# Fail the build now (not at guest runtime) if any runtime lib is missing.
RUN chmod +x /usr/local/bin/run.sh && ldd /usr/local/bin/mptest
ENTRYPOINT ["/usr/local/bin/run.sh"]
