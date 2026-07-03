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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "intf.h"
#include "fuzz_bpf.skel.h"

// Chaos-mode parameters (after rr's chaos mode) are drawn fresh per boot from
// the deterministic getrandom stream (see draw_profile below), not fixed here:
// each run samples a different scheduling regime -- timescale, victim density,
// timeslice -- so the fuzzer explores schedules broadly instead of re-sampling a
// single fixed profile through the randomness pool alone. The draw is a pure
// function of the seed, so a given seed replays the same profile exactly.

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
	case FUZZ_EVENT_STARVE_BEGIN:
		printf("[%6llu.%03llu] starvation interval: %llums "
		       "(low-priority threads blocked)\n",
		       sec, ms, e->duration_ns / 1000000ULL);
		break;
	case FUZZ_EVENT_LOW_PRIO:
		printf("[%6llu.%03llu] froze %s (pid %u) for %llums "
		       "(starvation victim)\n",
		       sec, ms, e->comm, e->pid, e->duration_ns / 1000000ULL);
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

/* A chaos-mode configuration, drawn fresh per boot from the getrandom stream. */
struct chaos_profile {
	uint64_t starve_min_ns, starve_max_ns;
	uint64_t gap_min_ns, gap_max_ns;
	uint64_t prio_reroll_ns;
	uint64_t low_prob_inv;
	uint64_t starve_cap_pct;
	uint64_t slice_ns;
};

/*
 * Draw a chaos profile from getrandom (the guest kernel sources it from
 * bedrock's deterministic, seed-driven stream). Consumes randomness BEFORE the
 * pool is filled, so the whole run stays a pure function of BEDROCK_RDRAND_SEED
 * and replays exactly. Returns 0/-1.
 *
 * Why per-boot (vs the old fixed profile):
 *   - Timescale S is log-uniform ~8us..2.1s. The old profile pinned starvation
 *     at 50ms..1.5s, far coarser than an IPC race window, so a freeze only landed
 *     *around* a concurrent IPC call, never inside one. Sampling down to
 *     microseconds manufactures the fine interleavings too.
 *   - Victims are denser (1/2..1/6, not the old 1/8) and re-roll fast relative to
 *     the interval, so mptest's two-or-three critical threads are frequently the
 *     ones frozen, and a thread that is "high" this epoch becomes a victim a few
 *     epochs later instead of never being frozen.
 *   - The base timeslice is randomized (log-uniform ~8us..4ms), varying
 *     preemption granularity.
 * By construction the max single interval (~2.1s) stays well under run.sh's 30s
 * hang watchdog, so scheduler starvation alone cannot masquerade as the #35491
 * hang.
 */
static int draw_profile(struct chaos_profile *pf)
{
	static const uint64_t inv_choices[] = { 2, 2, 3, 3, 4, 6 };
	uint64_t r[9];

	if (get_random(r, sizeof(r)) != 0)
		return -1;

	uint64_t S = log_uniform(r[0], r[1], 13, 31);	/* [8.2us, 2.1s) */

	pf->starve_max_ns = S;
	pf->starve_min_ns = S >> (1 + (r[2] % 3));	/* S/2, S/4, or S/8 */
	pf->gap_max_ns = S >> (r[3] % 3);		/* S, S/2, or S/4 */
	pf->gap_min_ns = pf->gap_max_ns >> 2;
	pf->prio_reroll_ns = S >> (r[4] % 2);		/* S or S/2 */
	pf->slice_ns = log_uniform(r[5], r[6], 13, 22);	/* [8.2us, 4.2ms) */
	pf->low_prob_inv =
		inv_choices[r[7] % (sizeof(inv_choices) / sizeof(inv_choices[0]))];
	pf->starve_cap_pct = 30 + r[8] % 46;		/* 30..75% */

	return 0;
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
	struct chaos_profile pf;
	if (draw_profile(&pf) != 0) {
		fprintf(stderr, "failed to draw chaos profile\n");
		err = 2;
		goto cleanup_skel;
	}
	skel->rodata->starve_min_ns = pf.starve_min_ns;
	skel->rodata->starve_max_ns = pf.starve_max_ns;
	skel->rodata->gap_min_ns = pf.gap_min_ns;
	skel->rodata->gap_max_ns = pf.gap_max_ns;
	skel->rodata->prio_reroll_ns = pf.prio_reroll_ns;
	skel->rodata->low_prob_inv = pf.low_prob_inv;
	skel->rodata->starve_cap_pct = pf.starve_cap_pct;
	skel->rodata->slice_ns = pf.slice_ns;
	skel->rodata->logging = true;
	// Per-task diagnostics: prints each governed task once. Flip to false to
	// quiet the log once the pipeline is confirmed working.
	skel->rodata->debug = true;

	// Log the drawn profile so every run's regime is visible on the console
	// (fuzz.sh records both lines). The first line is human-readable (us,
	// rounded); the second is byte-exact -- raw ns under the rodata field names --
	// so a repro can be reconstructed exactly by hardcoding these values, even
	// across a scx-init change that would otherwise re-map the seed.
	printf("scx-fuzz profile: starve=%llu..%lluus gap=%llu..%lluus "
	       "reroll=%lluus slice=%lluus low=1/%llu cap=%llu%%\n",
	       (unsigned long long)(pf.starve_min_ns / 1000),
	       (unsigned long long)(pf.starve_max_ns / 1000),
	       (unsigned long long)(pf.gap_min_ns / 1000),
	       (unsigned long long)(pf.gap_max_ns / 1000),
	       (unsigned long long)(pf.prio_reroll_ns / 1000),
	       (unsigned long long)(pf.slice_ns / 1000),
	       (unsigned long long)pf.low_prob_inv,
	       (unsigned long long)pf.starve_cap_pct);
	printf("scx-fuzz profile-exact: starve_min_ns=%llu starve_max_ns=%llu "
	       "gap_min_ns=%llu gap_max_ns=%llu prio_reroll_ns=%llu slice_ns=%llu "
	       "low_prob_inv=%llu starve_cap_pct=%llu\n",
	       (unsigned long long)pf.starve_min_ns,
	       (unsigned long long)pf.starve_max_ns,
	       (unsigned long long)pf.gap_min_ns,
	       (unsigned long long)pf.gap_max_ns,
	       (unsigned long long)pf.prio_reroll_ns,
	       (unsigned long long)pf.slice_ns,
	       (unsigned long long)pf.low_prob_inv,
	       (unsigned long long)pf.starve_cap_pct);
	fflush(stdout);

	err = fuzz_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup_skel;
	}

	// Fill both halves of the randomness pool from getrandom before attaching,
	// so it is fully populated before the scheduler can consume any of it (no
	// race). The poll loop below refreshes a half at a time from then on.
	int rnd_fd = bpf_map__fd(skel->maps.rnd_pool);
	if (refill_half(rnd_fd, 0) != 0 || refill_half(rnd_fd, 1) != 0) {
		fprintf(stderr, "failed to fill randomness pool\n");
		err = 2;
		goto cleanup_skel;
	}

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
	// force-drains everything pending.
	//
	// Between drains, refresh the pool a half at a time (see intf.h for why).
	// rnd_idx sweeps half 0, then half 1, then wraps; when it crosses into a half
	// we refill the one it just left, so the slots being written are never the
	// ones the scheduler is reading. At ~10 refills/s against a few draws/s the
	// next half is always fresh before the scheduler reaches it.
	int last_half = 0;
	while (!stop) {
		ring_buffer__poll(rb, 100 /* ms pacing */);
		ring_buffer__consume(rb);

		int half = (skel->bss->rnd_idx & (RND_POOL_N - 1)) >= RND_HALF ? 1 : 0;
		if (half != last_half) {
			refill_half(rnd_fd, last_half);
			last_half = half;
		}
	}

	err = 0;
	ring_buffer__free(rb);
cleanup_link:
	bpf_link__destroy(link);
cleanup_skel:
	fuzz_bpf__destroy(skel);
	return err;
}
