# syntax=docker/dockerfile:1
#
# Concurrency-fuzz workload image: the in-kernel sched_ext fuzzing scheduler
# (BPF) + its C loader/supervisor, the producer/consumer sample target, and the
# VMCALL ready/shutdown helper.
#
# Base is debian:trixie for a recent toolchain: scx's BPF headers and
# .struct_ops.link skeletons need clang >= 17 and libbpf >= 1.3, which bookworm
# (clang 14 / libbpf 1.1) is too old for.
#
# Build context is this directory (fuzz/); build.sh stages guest/libvmcall.h in.

FROM debian:trixie AS build

# scx tag whose sched_ext kfunc ABI matches the bedrock guest kernel (6.18).
ARG SCX_REF=v1.0.18

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev pkg-config \
      make gcc git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# scx provides the sched_ext BPF headers (scx/common.bpf.h) plus a bundled
# vmlinux.h for CO-RE. CO-RE relocations are resolved at load time against the
# guest kernel's /sys/kernel/btf/vmlinux, so the bundled header need not match
# the guest exactly.
RUN git clone --depth 1 --branch "$SCX_REF" \
      https://github.com/sched-ext/scx.git /opt/scx

WORKDIR /src
COPY bpf/ bpf/
COPY loader.c queue.c vmcall.c libvmcall.h ./

# Compile the sched_ext BPF object (CO-RE; -g is required for BTF emission).
# Include flags mirror scx's own bpf_includes (meson.build): scx ships its
# bundled vmlinux.h under scheds/vmlinux (+ a per-arch copy), not under
# scheds/include.
RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
      -I/opt/scx/scheds/include \
      -I/opt/scx/scheds/include/bpf-compat \
      -I/opt/scx/scheds/include/lib \
      -I/opt/scx/scheds/vmlinux \
      -I/opt/scx/scheds/vmlinux/arch/x86 \
      -Ibpf \
      -c bpf/main.bpf.c -o main.bpf.o

# Generate the libbpf skeleton the loader includes.
RUN bpftool gen skeleton main.bpf.o name fuzz_bpf > fuzz_bpf.skel.h

# Loader links libbpf dynamically (static libbpf + libelf + zstd archives are
# fiddly on Debian); the runtime stage installs the matching runtime lib.
RUN gcc -O2 -Ibpf -I. -o fuzz-loader loader.c \
      $(pkg-config --cflags --libs libbpf)

# Target and VMCALL helper have no third-party deps, so link them static.
RUN gcc -O2 -static -pthread -o queue queue.c
RUN gcc -O2 -static -o bedrock-vmcall vmcall.c

FROM debian:trixie-slim
# libbpf1 pulls in the runtime libs the dynamically-linked loader needs
# (libelf, zlib, zstd) as dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends libbpf1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/fuzz-loader    /usr/local/bin/fuzz-loader
COPY --from=build /src/queue          /usr/local/bin/queue
COPY --from=build /src/bedrock-vmcall /usr/local/bin/bedrock-vmcall
COPY run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
ENTRYPOINT ["/usr/local/bin/run.sh"]
