// SPDX-License-Identifier: GPL-2.0
//
// Guest-side init service for the in-kernel concurrency-fuzz scheduler.
//
// Loaded once at guest boot (before podman), this service:
//   - opens the BPF skeleton, writes the read-only chaos-mode parameters into
//     rodata, loads it, and attaches the sched_ext struct_ops with
//     SCX_OPS_SWITCH_PARTIAL. From here on the scheduler governs every
//     SCHED_EXT task and leaves all stock tasks on CFS;
//   - drains the ring buffer of scheduler events for the log and runs until
//     terminated by a signal (the guest shuts down via the VMCALL path).
//
// Which tasks are SCHED_EXT is decided by the workload itself: it wraps the
// process it wants fuzzed in thread-fuzz, which switches that process (and its
// descendants) into SCHED_EXT. So this service needs no notion of "which
// cgroup": every task it sees was opted in explicitly.
//
// Determinism: all timestamps printed come from the kernel (bpf_ktime_get_ns),
// which derives from bedrock's deterministic emulated TSC. The schedule is
// driven by getrandom(), which the guest kernel sources from the
// HYPERCALL_GET_RANDOM vmcall — bedrock's controlled, fuzzer-driven stream. No
// wall-clock or host randomness is read here.
//
// Usage: scx-init   (no arguments)

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "intf.h"
#include "libvmcall.h"
#include "fuzz_bpf.skel.h"

// Per-boot PCT bounds (depth ceiling, horizon range, timeslice, demotion cap,
// priority spread) are drawn fresh per boot from the deterministic getrandom
// stream (see draw_profile below), not fixed here: each boot samples a different
// regime. The actual per-execution schedule is drawn by the BPF scheduler from
// the randomness pool at runtime. Both draws are a pure function of the input, so
// a given input replays the same profile and schedule exactly.

static volatile sig_atomic_t stop;

static void on_term(int sig)
{
	(void)sig;
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct fuzz_event *e = data;
	(void)ctx;

	if (size < sizeof(*e))
		return 0;

	unsigned long long sec = e->time_ns / 1000000000ULL;
	unsigned long long ms = (e->time_ns % 1000000000ULL) / 1000000ULL;

	switch (e->event_type) {
	case FUZZ_EVENT_EPOCH_BEGIN:
		printf("[%6llu.%03llu] PCT epoch: depth=%u horizon=%lluus "
		       "(new execution schedule)\n",
		       sec, ms, e->pid, e->duration_ns / 1000ULL);
		break;
	case FUZZ_EVENT_DEMOTE:
		printf("[%6llu.%03llu] change point: demoted pid %u to prio %llu "
		       "(forced preemption)\n",
		       sec, ms, e->pid, (unsigned long long)e->duration_ns);
		break;
	case FUZZ_EVENT_DEBUG:
		printf("[%6llu.%03llu] debug: %s (pid %u) governed by scx-fuzz\n",
		       sec, ms, e->comm, e->pid);
		break;
	}
	fflush(stdout);
	return 0;
}

// Read len bytes from getrandom() (the guest kernel sources it from
// HYPERCALL_GET_RANDOM; see intf.h). Loops over short reads. Returns 0/-1.
static int get_random(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		long n = syscall(SYS_getrandom, p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

// Scratch buffer holding one half of the pool during a refill (see the poll loop).
#define RND_HALF (RND_POOL_N / 2)
static uint64_t refill_buf[RND_HALF];

// Refill one half of the pool — slots [half*RND_HALF, half*RND_HALF + RND_HALF) —
// with fresh getrandom values. Only ever called for the half the scheduler is NOT
// currently consuming, so the slots being written are never read concurrently.
// Returns 0 on success, -1 on failure.
static int refill_half(int fd, int half)
{
	uint32_t base = (uint32_t)half * RND_HALF;

	if (get_random(refill_buf, sizeof(refill_buf)) != 0)
		return -1;
	for (uint32_t j = 0; j < RND_HALF; j++) {
		uint32_t key = base + j;

		if (bpf_map_update_elem(fd, &key, &refill_buf[j], BPF_ANY) != 0)
			return -1;
	}
	return 0;
}

// Post-ready pool re-roll for fork-based fuzzing (the lab's mptest_fuzz).
//
// The pool is filled once at boot (below), before any fork point exists, so all
// forks of a booted VM would otherwise inherit the same pool and replay the same
// schedule. To let each fork explore, the workload's run.sh touches
// SCX_REFILL_REQ right after the ready hypercall (the point the lab checkpoints
// and forks at); we then redraw the whole pool from getrandom. In a forked,
// re-seeded branch that getrandom stream is the branch's own, so each fork gets
// a distinct pool -> a distinct PCT schedule. We create SCX_REFILL_DONE when the
// new pool is in place so run.sh starts mptest only after the re-roll, never on a
// half-updated pool. One-shot per boot (guarded by *refilled). The request path
// is a bind-mounted shared dir (/bedrock/scx) so the container's run.sh and this
// initrd service see the same files; the whole tmpfs is copy-on-write per fork.
//
// The per-boot PCT *profile* (rodata: horizon/slice/depth/spread) is NOT
// redrawn -- it is fixed at load time -- so a set of forks from one boot shares
// one regime and varies only the pool. Vary the boot seed for regime diversity.
#define SCX_REFILL_REQ "/bedrock/scx/refill"
#define SCX_REFILL_DONE "/bedrock/scx/refill-done"

static void maybe_refill_pool(int rnd_fd, int *refilled)
{
	if (*refilled || access(SCX_REFILL_REQ, F_OK) != 0)
		return;

	if (refill_half(rnd_fd, 0) != 0 || refill_half(rnd_fd, 1) != 0) {
		// Leave *refilled clear and DONE absent: run.sh's wait times out
		// rather than running mptest on a stale/partial pool.
		fprintf(stderr, "scx-fuzz: post-ready pool refill failed\n");
		return;
	}

	uint64_t first = 0;
	uint32_t zero = 0;
	bpf_map_lookup_elem(rnd_fd, &zero, &first);
	printf("scx-fuzz pool refilled post-ready; pool[0] %#llx\n",
	       (unsigned long long)first);
	fflush(stdout);

	*refilled = 1;
	int fd = open(SCX_REFILL_DONE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0)
		close(fd);
}

/*
 * Log-uniform draw: pick an exponent uniformly in [lo_bits, hi_bits), then a
 * uniform mantissa within that octave, giving a value in [2^lo_bits, 2^hi_bits).
 * Sampling per-octave weights every power-of-two band equally, so fine (us) and
 * coarse (s) timescales are explored evenly; a plain uniform draw would sit
 * almost entirely in the top octave.
 */
static uint64_t log_uniform(uint64_t r_oct, uint64_t r_mant,
			    unsigned lo_bits, unsigned hi_bits)
{
	unsigned k = lo_bits + (unsigned)(r_oct % (hi_bits - lo_bits));
	uint64_t base = 1ULL << k;

	return base + (r_mant % base);
}

/*
 * Per-boot PCT bounds. The BPF scheduler draws the actual per-epoch schedule
 * (depth, horizon, change-point placement, base priorities) from the pool at
 * runtime; these rodata values only set the ranges it draws within, and give
 * each boot a distinct regime that is logged (profile-exact) for reproducibility.
 */
struct pct_profile {
	uint64_t slice_ns;		/* base timeslice */
	uint64_t horizon_min_ns;	/* change-point horizon, low bound */
	uint64_t horizon_max_ns;	/* change-point horizon, high bound */
	uint64_t max_demote_ns;		/* demotion penalty magnitude + lifetime (starvation cap) */
	uint32_t max_depth;		/* max bug depth d (>= 2) */
	uint32_t prio_spread;		/* retained for ABI; unused by the vtime-fair base */
	uint32_t cp_prob_pct;		/* realism knob: % of epochs perturbed by change points */
};

/*
 * Draw a PCT profile from getrandom (the guest kernel sources it from bedrock's
 * deterministic, seed-driven stream). Consumes randomness BEFORE the pool is
 * filled, so the whole run stays a pure function of the input and replays
 * exactly. Returns 0/-1.
 *
 *   - Horizon (the emulated-TSC window the d-1 change points are scattered over)
 *     is bounded by a log-uniform ~8us..2.1s ceiling with a floor at ceiling/16.
 *     Sampling down to microseconds lets a change point land *inside* an IPC race
 *     window, not just around it.
 *   - The base timeslice is log-uniform ~8us..4ms, varying preemption
 *     granularity for the strict-priority policy.
 *   - max_demote_ns (how long a change-point demotion suppresses its victim) is
 *     log-uniform ~1ms..2.1s -- well under run.sh's 30s hang watchdog, so PCT
 *     starvation alone cannot masquerade as the #35491 hang.
 *   - max_depth (the bug-depth ceiling; per-epoch depth is drawn in [2, max_depth]
 *     inside the scheduler) is 3..6, and prio_spread is retained only for rodata
 *     ABI (the vtime-fair base does not use it).
 *   - cp_prob_pct (the realism knob) is the % of epochs the scheduler perturbs
 *     with change points; the rest run the pure vtime-fair base, staying close to
 *     stock Linux scheduling -- the regime the CI repros lived in. Drawn from a
 *     table weighted toward the low (near-default) end, with the occasional
 *     aggressive regime, so boot_seed sweeps the whole fidelity axis.
 */
static int draw_profile(struct pct_profile *pf)
{
	static const uint32_t spread_choices[] = { 32, 64, 128, 256 };
	/* Weighted toward near-default (two 0s: pure-fair boots); 100 = full PCT. */
	static const uint32_t cp_prob_choices[] = { 0, 0, 5, 10, 25, 50, 100 };
	uint64_t r[9];

	if (get_random(r, sizeof(r)) != 0)
		return -1;

	uint64_t H = log_uniform(r[0], r[1], 13, 31);	/* [8.2us, 2.1s) */

	pf->horizon_max_ns = H;
	pf->horizon_min_ns = H >> 4;			/* H/16 */
	if (pf->horizon_min_ns < 8192)
		pf->horizon_min_ns = 8192;		/* keep min < max, > 0 */
	if (pf->horizon_min_ns >= pf->horizon_max_ns)
		pf->horizon_max_ns = pf->horizon_min_ns + 1;
	pf->slice_ns = log_uniform(r[2], r[3], 13, 22);	/* [8.2us, 4.2ms) */
	pf->max_demote_ns = log_uniform(r[4], r[5], 20, 31);	/* [1ms, 2.1s) */
	pf->max_depth = 3 + (uint32_t)(r[6] % 4);	/* 3..6 (n_cp <= MAX_CP=5) */
	pf->prio_spread =
		spread_choices[r[7] % (sizeof(spread_choices) / sizeof(spread_choices[0]))];
	pf->cp_prob_pct =
		cp_prob_choices[r[8] % (sizeof(cp_prob_choices) / sizeof(cp_prob_choices[0]))];

	return 0;
}

// Interleaving/lock coverage (signals A+C) readback. The BPF program bumps a
// BPF_F_MMAPABLE array (cov_map); we mirror it to the host through a SEPARATE,
// inode-backed buffer rather than registering the BPF map's pages directly.
//
// Why the indirection: registering the BPF map's own mmap pages produced a
// non-reproducible readback -- the schedule (result, profile-exact, even the vt
// timestamps) is bit-identical across runs, so the guest-side bitmap is
// identical, yet the host read back different bytes. The host captures a
// buffer's guest-physical addresses once at registration and re-reads those
// GPAs; a BPF array map's pages were not a stable enough backing for that. So we
// use the same stable-page approach libfeedback uses for code coverage: a
// file/inode-backed mapping (here an anonymous memfd, since scx-init lives the
// whole boot and needs no on-disk path), mlock-pinned so the pages cannot move
// out from under the captured GPAs. scx-init snapshots the BPF map into it (see
// sync_coverage); the host reads this buffer.
//
// The id is SCHED_COV_ID ("schedcov"), which deliberately does NOT start with
// "cov", so the host keeps this stream separate from libfeedback's code-coverage
// buffers (whose dumper prefix-matches "cov").
static const uint8_t *g_bpf_cov;	// live view of the BPF cov_map (read side)
static uint8_t *g_host_cov;		// memfd-backed buffer registered with the host

static void register_sched_coverage(struct fuzz_bpf *skel)
{
	int fd = bpf_map__fd(skel->maps.cov_map);
	if (fd < 0) {
		fprintf(stderr, "scx-fuzz: no cov_map fd; sched coverage off\n");
		return;
	}

	// Read side: a live, read-only view of the BPF map's bytes.
	void *bpf = mmap(NULL, SCHED_COV_N, PROT_READ, MAP_SHARED, fd, 0);
	if (bpf == MAP_FAILED) {
		fprintf(stderr, "scx-fuzz: mmap cov_map: %s\n", strerror(errno));
		return;
	}

	// Host-read side: an anonymous memfd, mmap'd MAP_SHARED and mlock-pinned so
	// its pages (and thus the GPAs the host captures) stay put.
	int mfd = (int)syscall(SYS_memfd_create, "schedcov", 0);
	if (mfd < 0 || ftruncate(mfd, SCHED_COV_N) != 0) {
		fprintf(stderr, "scx-fuzz: memfd for coverage: %s\n",
			strerror(errno));
		munmap(bpf, SCHED_COV_N);
		if (mfd >= 0)
			close(mfd);
		return;
	}
	void *host = mmap(NULL, SCHED_COV_N, PROT_READ | PROT_WRITE, MAP_SHARED,
			  mfd, 0);
	close(mfd);	// the mapping keeps the memfd inode (and its pages) alive
	if (host == MAP_FAILED) {
		fprintf(stderr, "scx-fuzz: mmap coverage memfd: %s\n",
			strerror(errno));
		munmap(bpf, SCHED_COV_N);
		return;
	}
	memset(host, 0, SCHED_COV_N);	// fault every page in before registration
	mlock(host, SCHED_COV_N);	// best-effort pin; keeps GPAs stable

	g_bpf_cov = bpf;
	g_host_cov = host;

	vmcall_u64 slot = vmcall_register_feedback_buffer(
		host, SCHED_COV_N, SCHED_COV_ID, sizeof(SCHED_COV_ID) - 1);
	printf("scx-fuzz sched-coverage: id=%s bytes=%d slot=%llu\n",
	       SCHED_COV_ID, SCHED_COV_N, (unsigned long long)slot);
	fflush(stdout);
}

// Snapshot the BPF coverage map into the host-registered buffer. Called from the
// poll loop; the last snapshot before the VM halts is what the host reads. The
// governed workload is idle by then (the final mptest iteration is done and
// run.sh is sleeping before the shutdown vmcall), so no coverage is generated
// during that window: the snapshot is stable and the readback is reproducible.
static void sync_coverage(void)
{
	if (g_bpf_cov && g_host_cov)
		memcpy(g_host_cov, g_bpf_cov, SCHED_COV_N);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	int err;

	struct fuzz_bpf *skel = fuzz_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 2;
	}

	// Draw a fresh chaos profile from the deterministic getrandom stream, then
	// write it into rodata (must happen before load). Each boot samples a new
	// scheduling regime, so the fuzzer explores timescales and victim densities
	// rather than re-sampling one fixed profile; the choice is a pure function of
	// the seed, so it replays exactly.
	struct pct_profile pf;
	if (draw_profile(&pf) != 0) {
		fprintf(stderr, "failed to draw PCT profile\n");
		err = 2;
		goto cleanup_skel;
	}
	skel->rodata->slice_ns = pf.slice_ns;
	skel->rodata->horizon_min_ns = pf.horizon_min_ns;
	skel->rodata->horizon_max_ns = pf.horizon_max_ns;
	skel->rodata->max_demote_ns = pf.max_demote_ns;
	skel->rodata->max_depth = pf.max_depth;
	skel->rodata->prio_spread = pf.prio_spread;
	skel->rodata->cp_prob_pct = pf.cp_prob_pct;
	skel->rodata->logging = true;
	// Per-task diagnostics: prints each governed task once. Flip to false to
	// quiet the log once the pipeline is confirmed working.
	skel->rodata->debug = true;

	// Log the drawn profile so every run's regime is visible on the console
	// (fuzz.sh records both lines). The first line is human-readable (us,
	// rounded); the second is byte-exact -- raw ns/counts under the rodata field
	// names -- so a repro can be reconstructed exactly by hardcoding these values,
	// even across a scx-init change that would otherwise re-map the input.
	printf("scx-fuzz profile: horizon=%llu..%lluus slice=%lluus "
	       "demote<=%lluus depth<=%u spread=%u cp_prob=%u%%\n",
	       (unsigned long long)(pf.horizon_min_ns / 1000),
	       (unsigned long long)(pf.horizon_max_ns / 1000),
	       (unsigned long long)(pf.slice_ns / 1000),
	       (unsigned long long)(pf.max_demote_ns / 1000),
	       pf.max_depth, pf.prio_spread, pf.cp_prob_pct);
	printf("scx-fuzz profile-exact: horizon_min_ns=%llu horizon_max_ns=%llu "
	       "slice_ns=%llu max_demote_ns=%llu max_depth=%u prio_spread=%u "
	       "cp_prob_pct=%u\n",
	       (unsigned long long)pf.horizon_min_ns,
	       (unsigned long long)pf.horizon_max_ns,
	       (unsigned long long)pf.slice_ns,
	       (unsigned long long)pf.max_demote_ns,
	       pf.max_depth, pf.prio_spread, pf.cp_prob_pct);
	fflush(stdout);

	err = fuzz_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup_skel;
	}

	// Fill the whole randomness pool from getrandom before attaching, so it is
	// fully populated before the scheduler can consume any of it. The pool is now
	// read positionally, one fixed SLOTS_PER_EPOCH window per execution (see
	// intf.h); with EPOCHS_MAX (512) windows and mptest's default 500 iterations,
	// each execution gets a distinct window and no window is reused within a run,
	// so there is nothing to refresh mid-run (unlike the old running-counter pool).
	int rnd_fd = bpf_map__fd(skel->maps.rnd_pool);
	if (refill_half(rnd_fd, 0) != 0 || refill_half(rnd_fd, 1) != 0) {
		fprintf(stderr, "failed to fill randomness pool\n");
		err = 2;
		goto cleanup_skel;
	}

	// Register the interleaving-coverage bitmap with the host (signal A). Done
	// after load (the map now exists) and before attach, so any early switch is
	// already counted. Best-effort; never fatal.
	register_sched_coverage(skel);

	// Attaching the sched_ext struct_ops makes our policy the scheduler for
	// SCHED_EXT tasks. Hold the link; dropping it detaches.
	struct bpf_link *link =
		bpf_map__attach_struct_ops(skel->maps.chaos_ops);
	if (!link) {
		fprintf(stderr, "failed to attach sched_ext struct_ops: %d\n",
			-errno);
		err = 2;
		goto cleanup_skel;
	}

	// Attach the futex fentry probes for lock-ordering coverage (signal C).
	// Best-effort: if the kernel lacks the symbols/BTF, the scheduler still runs
	// without lock edges. Held for the whole boot; destroyed at cleanup.
	struct bpf_link *link_fw = bpf_program__attach(skel->progs.on_futex_wait);
	struct bpf_link *link_fk = bpf_program__attach(skel->progs.on_futex_wake);
	if (!link_fw || !link_fk)
		fprintf(stderr,
			"scx-fuzz: futex probes not attached; lock coverage off\n");
	else
		printf("scx-fuzz lock-ordering coverage attached (futex probes)\n");
	fflush(stdout);

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
				 NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		err = 2;
		goto cleanup_link;
	}

	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);

	// pool[0] is a stable fingerprint of the schedule (the first value drawn).
	uint64_t first = 0;
	uint32_t zero = 0;
	bpf_map_lookup_elem(rnd_fd, &zero, &first);
	printf("scx-fuzz attached (SWITCH_PARTIAL); rnd pool %d, pool[0] %#llx\n",
	       RND_POOL_N, (unsigned long long)first);
	fflush(stdout);

	// Drain with ring_buffer__consume(), not ring_buffer__poll() alone:
	// bpf_ringbuf_submit()'s adaptive wakeup does not reliably fire the epoll
	// notification under bedrock's single-vCPU execution, so poll() would leave
	// events unread. poll() here only paces the loop (~100ms); consume() then
	// force-drains everything pending. The pool is otherwise filled once up
	// front and read positionally; the only refresh is the one-shot post-ready
	// re-roll below (for fork-based fuzzing), never a mid-run one.
	int refilled = 0;
	while (!stop) {
		ring_buffer__poll(rb, 100 /* ms pacing */);
		ring_buffer__consume(rb);
		// Redraw the pool once run.sh signals it is past the ready/fork
		// point, so forked branches explore distinct schedules (see above).
		maybe_refill_pool(rnd_fd, &refilled);
		// Mirror the BPF coverage map into the host-registered buffer so the
		// host reads a stable, inode-backed snapshot (see sync_coverage).
		sync_coverage();
	}

	err = 0;
	ring_buffer__free(rb);
cleanup_link:
	// bpf_link__destroy is NULL/err-safe, so freeing the futex probes here is
	// fine whether or not they attached, and covers the !rb error path too.
	bpf_link__destroy(link_fw);
	bpf_link__destroy(link_fk);
	bpf_link__destroy(link);
cleanup_skel:
	fuzz_bpf__destroy(skel);
	return err;
}
