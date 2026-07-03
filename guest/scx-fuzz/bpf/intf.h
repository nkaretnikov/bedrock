/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Structures shared between the in-kernel BPF scheduler (main.bpf.c) and the
 * user-space init service (scx-init.c). scx-init.c includes this header
 * directly, so it has to be valid both as BPF C (where the fixed width types
 * come from vmlinux.h) and as plain C for the service (where we define them
 * ourselves below).
 */
#ifndef __INTF_H
#define __INTF_H

/*
 * vmlinux.h (included by the BPF program via scx/common.bpf.h) already defines
 * these. When this header is parsed on its own, e.g. by the user-space service,
 * vmlinux.h is absent, so define them here.
 */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif /* __VMLINUX_H__ */

/* Task comm is TASK_COMM_LEN (16) in the kernel. */
#define FUZZ_COMM_LEN 16

/*
 * Size of the scheduler's randomness pool. scx-init fills it once at boot --
 * from a host-supplied testcase file if present, else from the getrandom vmcall
 * (see scx-init.c) -- and the BPF scheduler reads it as the schedule's input.
 *
 * The pool is the fuzzer's input surface. It is consumed POSITIONALLY, not
 * through a running counter: the scheduler runs one PCT "epoch" per governed
 * execution (see main.bpf.c) and epoch e reads a fixed SLOTS_PER_EPOCH-wide
 * window at offset (e mod EPOCHS_MAX) * SLOTS_PER_EPOCH. So pool byte range k
 * maps to a specific epoch's schedule and nothing else: mutating the window for
 * epoch e perturbs only that execution's interleaving, leaving every other epoch
 * bit-identical. That positional independence is what lets a host-side mutator
 * hill-climb (AFL-style) instead of re-rolling the whole schedule on every edit.
 *
 * Must be a power of two (the BPF side masks the index).
 */
#define RND_POOL_N 4096

/*
 * Pool slots consumed per PCT epoch, and how many distinct epoch windows the
 * pool holds before wrapping. One window is laid out as:
 *   slot 0        base_seed        (per-thread priority hash key)
 *   slot 1        depth selector   (bug depth d drawn from it)
 *   slot 2        horizon selector (execution-time window for change points)
 *   slots 3..7    change-point offset selectors (up to MAX_CP = 5)
 * SLOTS_PER_EPOCH must equal 3 + MAX_CP in main.bpf.c. With 4096/8 = 512 windows,
 * runs of up to 512 executions (>= the default MPTEST_MAX_ITERS of 500) get a
 * distinct window each; beyond that, windows reuse and schedules repeat. A fixed
 * number of slots per epoch (regardless of the drawn depth) keeps the mapping
 * stable so an early mutation never shifts later epochs' windows.
 */
#define SLOTS_PER_EPOCH 8
#define EPOCHS_MAX (RND_POOL_N / SLOTS_PER_EPOCH)

enum fuzz_event_type {
	/* A new per-execution PCT epoch began: pid = bug depth d for this epoch,
	 * duration_ns = the change-point horizon (ns) it was drawn over. */
	FUZZ_EVENT_EPOCH_BEGIN = 0,
	/* A change point fired: the running thread (pid) had its priority lowered
	 * to duration_ns, so a different thread now runs -- the deliberate
	 * preemption PCT inserts. */
	FUZZ_EVENT_DEMOTE = 1,
	/* Diagnostic (gated by the debug flag): a governed task seen on the
	 * enqueue path. duration_ns carries the pid. */
	FUZZ_EVENT_DEBUG = 2,
};

/*
 * One scheduler event, pushed to user space over a ring buffer so
 * scx-init can print the log lines. This is purely diagnostic: the scheduling
 * decision itself never leaves the kernel.
 */
struct fuzz_event {
	u64 time_ns;	  /* bpf_ktime_get_ns() at the transition */
	u64 duration_ns;  /* event-specific payload (see enum above) */
	u32 pid;
	u32 event_type;	  /* enum fuzz_event_type */
	char comm[FUZZ_COMM_LEN];
};

#endif /* __INTF_H */
