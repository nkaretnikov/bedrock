// SPDX-License-Identifier: GPL-2.0
//
// libtag: an LD_PRELOAD shim that gives each guest thread a stable, semantic
// name the in-kernel fuzzing scheduler can read, WITHOUT touching the target's
// source. The concurrency-coverage scheduler (see bpf/main.bpf.c, signal A)
// keys its interleaving edges on a per-thread identity; the kernel `comm` is the
// only per-thread tag it can read cheaply. libmultiprocess never sets `comm`
// (its ThreadName string is userspace-only), so every mptest thread would
// otherwise share the process name "mptest" and be indistinguishable.
//
// Identity = the thread's SPAWN CALL-SITE. We interpose pthread_create and, at
// the moment of the call, unwind the stack to the first frame that lies in the
// main executable (mptest itself, not libstdc++/libc). That PC minus the
// executable's load base is a binary-relative offset: stable across schedules
// and across fork siblings, and distinct per logical role -- the event loop
// (spawned in TestSetup), the RPC worker pool (ProxyServer<Thread>::makeThread),
// and the async-cleanup thread each have their own spawn site. We then set the
// new thread's comm to "mp:<offset-hex>" from inside the thread.
//
// Why the stack unwind and not the start routine or a frame-pointer walk:
// std::thread hands libstdc++'s execute_native_thread_routine to pthread_create,
// so the start pointer is identical for every thread; and the Release build has
// no frame pointers, so __builtin_return_address(1) cannot cross the libstdc++
// frame. backtrace() uses the .eh_frame CFI that libstdc++/libc DO ship, so it
// works without frame pointers.
//
// The client is the process's INITIAL thread -- it is never created via
// pthread_create, so this shim never touches it and it keeps comm == "mptest",
// which is itself a fine distinct "client" tag.
//
// Determinism: backtrace/dladdr/prctl are pure functions of guest state and add
// no VM exits, so they neither move the emulated TSC nor perturb the schedule; a
// given input replays identical thread names and identical coverage. Injected by
// run.sh via LD_PRELOAD only for the mptest invocation (inherited by its IPC
// server child), so nothing else in the guest is affected. Static binaries
// (bedrock-vmcall) ignore LD_PRELOAD, which is harmless.

#define _GNU_SOURCE

#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

// Depth of stack to unwind at pthread_create. Frame 0 is this shim, frame 1 is
// libstdc++'s _M_start_thread / __gthread_create; the target's spawn site is
// typically frame 2-3, but scan a few extra to be safe.
#define BT_DEPTH 12

typedef int (*pthread_create_fn)(pthread_t *, const pthread_attr_t *,
				 void *(*)(void *), void *);

// Path of the main executable ("/usr/local/bin/mptest"), resolved once. Used to
// pick the first backtrace frame that belongs to the target rather than to a
// shared library.
static char g_exe_path[256];

static void resolve_exe_path(void)
{
	ssize_t n = readlink("/proc/self/exe", g_exe_path, sizeof(g_exe_path) - 1);
	if (n > 0)
		g_exe_path[n] = '\0';
	else
		g_exe_path[0] = '\0';
}

// The offset of the pthread_create call-site within the main executable, or 0 if
// it could not be attributed (e.g. a thread created entirely inside a shared
// library). Walk the backtrace to the first frame whose object is the main exe.
static uintptr_t spawn_site_offset(void)
{
	void *frames[BT_DEPTH];
	int n = backtrace(frames, BT_DEPTH);

	for (int i = 1; i < n; i++) {
		Dl_info info;

		if (dladdr(frames[i], &info) == 0 || info.dli_fname == NULL)
			continue;
		// dli_fname is the object the PC belongs to; match it against the
		// main executable so we skip libstdc++/libkj/libc frames.
		if (g_exe_path[0] && strcmp(info.dli_fname, g_exe_path) != 0)
			continue;
		if (info.dli_fbase == NULL)
			continue;
		// File offset = PC - load base. ASLR-invariant, so stable across runs.
		return (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
	}
	return 0;
}

// Passed to the trampoline so the new thread can name itself before running the
// real start routine. Heap-allocated by pthread_create, freed by the trampoline.
struct tag_ctx {
	void *(*start)(void *);
	void *arg;
	uintptr_t offset;
};

static void *tag_trampoline(void *p)
{
	struct tag_ctx *ctx = p;
	void *(*start)(void *) = ctx->start;
	void *arg = ctx->arg;
	char name[16];

	// comm is capped at 16 bytes incl NUL; "mp:" + 8 hex fits. Mask to 32 bits
	// (executable offsets are well under 4 GiB) to keep it short and stable.
	snprintf(name, sizeof(name), "mp:%08x", (unsigned)(ctx->offset & 0xffffffffu));
	prctl(PR_SET_NAME, name, 0, 0, 0);

	free(ctx);
	return start(arg);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
		   void *(*start)(void *), void *arg)
{
	static pthread_create_fn real;
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	// Resolve the real pthread_create and the exe path exactly once.
	if (!real) {
		real = (pthread_create_fn)dlsym(RTLD_NEXT, "pthread_create");
		pthread_once(&once, resolve_exe_path);
	}
	if (!real) // extremely unlikely; nothing sane to do but fail loudly
		return -1;

	struct tag_ctx *ctx = malloc(sizeof(*ctx));
	if (!ctx) // fall back to an untagged thread rather than failing the create
		return real(thread, attr, start, arg);

	ctx->start = start;
	ctx->arg = arg;
	ctx->offset = spawn_site_offset();

	int rc = real(thread, attr, tag_trampoline, ctx);
	if (rc != 0)
		free(ctx); // trampoline never ran, so reclaim its context here
	return rc;
}
