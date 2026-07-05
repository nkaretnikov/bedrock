// SPDX-License-Identifier: GPL-2.0
//
// Opt a command, and every process it spawns, into the in-kernel
// concurrency-fuzz scheduler by running it under SCHED_EXT.
//
// Usage: thread-fuzz <command> [args...]
//
// thread-fuzz sets its OWN scheduling policy to SCHED_EXT and then execs the
// given command. Scheduling policy is inherited across fork/exec, so every
// descendant of the command is governed by the fuzzing scheduler too, with no
// per-process opt-in. This is the manual-registration path used while we
// dogfood the scheduler: a workload opts in by wrapping the process it wants
// fuzzed, e.g. `thread-fuzz /usr/local/bin/queue`, and leaves everything else
// on the stock scheduler.
//
// It execs the target directly, so nothing in between resets the scheduling
// policy and plain inheritance suffices.
//
// The scheduler must already be attached (scx-init, at boot) with
// SCX_OPS_SWITCH_PARTIAL, so only the SCHED_EXT tasks thread-fuzz creates are
// governed while everything else stays on the stock scheduler. Setting
// SCHED_EXT needs CAP_SYS_NICE; the fuzzed workload's container runs privileged.
//
// Determinism is unchanged: the schedule is drawn from bedrock's getrandom
// stream (see scx-init.c), a pure function of the fuzzer input under the single
// vCPU + emulated TSC.

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

int main(int argc, char **argv)
{
	struct sched_param p = { .sched_priority = 0 };

	if (argc < 2) {
		fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
		return 2;
	}

	// Disable ASLR for the fuzzed process tree. The guest's address-space
	// randomization is NOT seeded from bedrock's deterministic getrandom stream,
	// so with it on the schedule replays identically but absolute addresses --
	// e.g. the futex/lock addresses the scheduler's lock-ordering coverage keys
	// on -- shift run to run, making coverage non-reproducible. Turning it off
	// makes those addresses deterministic. Personality is preserved across
	// execve and inherited by children (mptest + its IPC server), like the
	// SCHED_EXT policy below. Best-effort: warn but continue if it is refused.
	int persona = personality(0xffffffff); // query current without changing it
	if (persona == -1 ||
	    personality((unsigned int)persona | ADDR_NO_RANDOMIZE) == -1)
		fprintf(stderr, "thread-fuzz: personality(ADDR_NO_RANDOMIZE): %s\n",
			strerror(errno));

	// Force a single malloc arena. With ASLR off the address-space base is
	// fixed, but glibc still spreads allocations across per-thread arenas, and
	// arena assignment can place the same logical allocation at a different
	// address run to run -- residual non-determinism in the lock addresses the
	// coverage keys on. One arena serializes allocation into a fixed layout, so
	// addresses replay exactly. Inherited across execve and by children.
	setenv("MALLOC_ARENA_MAX", "1", 1);

	// Disable glibc's thread-stack cache. Freed thread stacks are otherwise
	// cached and reused, and the reuse can place a new thread's stack (and the
	// condvar/Waiter objects living on it, which signal C keys on) at a
	// different address run to run. With the cache off each stack is mmap'd
	// fresh into the fixed (ASLR-off) layout, so those addresses replay.
	setenv("GLIBC_TUNABLES", "glibc.pthread.stack_cache_size=0", 1);

	// Raw syscall, not the glibc wrapper: some libc versions reject an
	// unknown policy value (SCHED_EXT == 7) before the syscall.
	if (syscall(SYS_sched_setscheduler, 0, SCHED_EXT, &p) != 0) {
		fprintf(stderr, "thread-fuzz: sched_setscheduler(SCHED_EXT): %s\n",
			strerror(errno));
		return 1;
	}

	// Descendants inherit SCHED_EXT; only returns here if exec fails.
	execvp(argv[1], &argv[1]);

	fprintf(stderr, "thread-fuzz: exec %s: %s\n", argv[1], strerror(errno));
	return 127;
}
