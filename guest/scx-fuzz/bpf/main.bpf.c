/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Concurrency fuzzing scheduler, in-kernel BPF version -- PCT policy.
 *
 * A sched_ext scheduler that manufactures the rare interleavings that surface
 * concurrency bugs. The whole policy runs here in the kernel, so that under a
 * deterministic hypervisor (bedrock: single vCPU + emulated TSC) a run is fully
 * reproducible from the pool that drives it.
 *
 * Policy: PCT ("A Randomized Scheduler with Probabilistic Guarantees of Finding
 * Bugs", Burckhardt et al., ASPLOS'10), replacing the earlier rr-style chaos
 * starvation. PCT gives a provable lower bound on hitting any bug of "depth" d
 * (d ordering constraints among n threads over k steps): >= 1 / (n * k^(d-1)).
 * For the shallow libmultiprocess IPC races we hunt (bitcoin/bitcoin #35491,
 * #34014), which need only 2-3 ordering constraints, that concentrates the
 * search where the bugs are, rather than spending budget on deep, unlikely
 * schedules the way uniform chaos does.
 *
 * Mechanism, textbook PCT:
 *   - Each thread gets a random, fixed base priority. The scheduler always runs
 *     the highest-priority *enabled* (runnable) thread -- a strict priority
 *     policy. A thread only yields the CPU when it blocks (leaves the runnable
 *     set) or when a higher-priority thread wakes.
 *   - d-1 "change points" are placed in the execution. When a change point is
 *     reached, the *currently running* thread's priority is lowered below every
 *     base priority, so a different thread takes over. Those d-1 forced
 *     preemptions, placed randomly, are what expose depth-d bugs.
 *
 * Three adaptations to this platform, each noted at its site below:
 *   1. Per-execution epochs. mptest runs in a 500-iteration loop, each iteration
 *      a fresh `thread-fuzz mptest` process; textbook PCT assumes ONE bounded
 *      execution. So a fresh PCT schedule (base priorities + change points) is
 *      drawn each time a new governed process leader appears (see chaos_enable:
 *      a task with pid == tgid and a new tgid). One boot thus yields many
 *      independent PCT samples instead of one.
 *   2. Change points are placed on the emulated-TSC clock, not on a count of
 *      "steps" (visible memory operations, which we cannot see at the sched_ext
 *      layer and whose total is unknown a priori). Time is the deterministic
 *      proxy for PCT's step index; a per-epoch horizon is drawn and the d-1
 *      points scattered across it, fired by a one-shot bpf_timer.
 *   3. Bounded demotion lifetime as a starvation cap. Textbook PCT lowers a
 *      thread's priority permanently, which -- if a higher-priority thread
 *      busy-waits on a demoted one -- can livelock and masquerade as the #35491
 *      hang. Each demotion therefore expires after max_demote_ns (drawn well
 *      under run.sh's 30s hang watchdog), so a demotion cannot suppress its
 *      victim long enough to look like the hang. For the typical sub-second
 *      mptest iteration the demotion effectively lasts the whole execution
 *      anyway. NOTE this bounds only *demotion*-induced starvation; the base
 *      policy is strict priority, so PCT's standard assumption still holds --
 *      threads are expected to make progress by blocking (futex/KJ async), and a
 *      genuinely CPU-bound governed thread could still monopolize the vCPU and
 *      surface as a hang. Under this deterministic VM such a case is a
 *      reproducible, inspectable result rather than a silent flake.
 *
 * Input: the randomness pool (see intf.h). It is consumed positionally, one
 * fixed SLOTS_PER_EPOCH window per epoch, so a host mutator can perturb a single
 * execution's schedule in isolation. scx-init fills the pool from a testcase
 * file if present, else from bedrock's deterministic getrandom stream; either
 * way the whole run is a pure function of that input and replays exactly.
 *
 * Membership (who is governed):
 *   - Attached with SCX_OPS_SWITCH_PARTIAL, so it governs ONLY tasks whose
 *     policy is SCHED_EXT. Every ordinary host task stays on stock CFS/EEVDF.
 *   - A workload opts in by wrapping the process it wants fuzzed in thread-fuzz,
 *     which sets SCHED_EXT on itself and execs the target; the target's
 *     fork/exec descendants inherit it. So every task we see was opted in
 *     explicitly: there is nothing to exclude.
 *
 * Mechanism (sched_ext): one vtime-ordered DSQ whose key encodes priority
 * (KEY_BASE - priority), so dispatch() -- which always pulls the lowest key --
 * runs the highest-priority runnable task. A thread that blocks leaves the DSQ;
 * on wake it is re-inserted at its current priority. Demotions take effect the
 * next time the demoted (running) thread is re-enqueued, hurried along by a
 * preempt kick.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Single dispatch queue, ordered by the priority-derived key below. */
#define FAIR_DSQ_ID 0

/* Bound for the kick loop in the timer callback. */
#define MAX_CPUS 1024

/*
 * Maximum change points per epoch = max bug depth - 1. Must satisfy
 * SLOTS_PER_EPOCH == 3 + MAX_CP (see intf.h): slots 3..3+MAX_CP-1 hold the
 * change-point offset selectors.
 */
#define MAX_CP 5

/*
 * Priority-to-DSQ-key base. A task's key is KEY_BASE - priority, and dispatch
 * pulls the lowest key, so a higher priority runs first. KEY_BASE is far above
 * any priority (base priorities are max_depth + [0, prio_spread), demotions are
 * [1, max_depth)), so the subtraction never underflows.
 */
#define KEY_BASE (1ULL << 20)

/*
 * Read-only configuration, set by scx-init before the program is loaded.
 * "const volatile" is how sched_ext schedulers expose rodata to user space.
 * These are per-boot bounds; the actual per-epoch values (depth, horizon,
 * change-point placement, base priorities) are drawn from the pool at runtime.
 */
const volatile u64 slice_ns;		/* base timeslice for the priority policy */
const volatile u64 horizon_min_ns;	/* change-point horizon, low bound */
const volatile u64 horizon_max_ns;	/* change-point horizon, high bound */
const volatile u64 max_demote_ns;	/* how long a demotion lasts (starvation cap) */
const volatile u32 max_depth;		/* max bug depth d (>= 2); depth drawn in [2, max_depth] */
const volatile u32 prio_spread;		/* base-priority spread (>= 1) */
const volatile bool logging;
const volatile bool debug;		/* emit per-task membership diagnostics */

/*
 * Global PCT epoch state. All of it is rewritten by start_epoch() and only ever
 * touched from the ops callbacks, which are serialized on the single-vCPU
 * target. Times are bpf_ktime_get_ns(), i.e. the deterministic emulated TSC.
 */
static u64 epoch_no;		/* which execution this is; indexes the pool window */
static bool started;		/* has the first governed execution begun */
static u32 epoch_leader_tgid;	/* tgid of the current epoch's process leader */
static u64 base_seed;		/* per-epoch key for the base-priority hash */
static u32 depth;		/* bug depth d drawn this epoch */
static u32 n_cp;		/* change points this epoch = depth - 1 */
static u32 cur_pid;		/* pid of the task currently running (for demotion) */
static u32 cur_prio;		/* its priority (for wake-preemption) */

/* The change-point schedule for this epoch, and the demotions it has produced. */
static u64 cp_time[MAX_CP];	/* emulated-TSC time each change point fires */
static u32 cp_prio[MAX_CP];	/* priority the demoted thread drops to */
static bool cp_fired[MAX_CP];	/* whether it has fired yet */
static u32 dem_pid[MAX_CP];	/* pid demoted by change point i */
static u32 dem_prio[MAX_CP];	/* priority it was demoted to */
static u64 dem_expire[MAX_CP];	/* when the demotion lifts (starvation cap) */
static bool dem_active[MAX_CP];	/* whether this demotion is live */

/*
 * Membership-log throttle (gated by the "debug" rodata flag). enqueue() runs on
 * every wakeup, so the "governed" membership line is sampled only for the first
 * few tasks to confirm the scheduler is live without flooding.
 */
static u64 dbg_logged;

/* Wrapper so the timer can live in an array map (bpf_timer needs map storage). */
struct timer_wrap {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct timer_wrap);
} timer_map SEC(".maps");

/* Ring buffer carrying fuzz_event records up to scx-init. 256 KiB. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Randomness pool = the fuzzer input, filled by scx-init (see intf.h). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RND_POOL_N);
	__type(key, u32);
	__type(value, u64);
} rnd_pool SEC(".maps");

/* Read pool[idx], masked into range (RND_POOL_N is a power of two). */
static __always_inline u64 pool_at(u32 idx)
{
	u32 i = idx & (RND_POOL_N - 1);
	u64 *v = bpf_map_lookup_elem(&rnd_pool, &i);

	return v ? *v : 0;
}

/*
 * Finalizing hash of (a, b) -> u64. Used to derive stable per-thread base
 * priorities from (pid, base_seed) with no per-task storage: task-local storage
 * is unusable on the enqueue hot path here (bpf_task_storage_get() trylocks
 * under the rq lock and fails >99% of the time on a busy workload).
 */
static __always_inline u64 hash2(u64 a, u64 b)
{
	u64 h = a * 0x9E3779B97F4A7C15ULL;

	h ^= b * 0xD1B54A32D192ED03ULL;
	h ^= h >> 33;
	h *= 0xFF51AFD7ED558CCDULL;
	h ^= h >> 33;
	return h;
}

static __always_inline void log_event(u32 pid, const char *comm, u32 type,
				       u64 now, u64 payload)
{
	struct fuzz_event *e;

	if (!logging)
		return;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->time_ns = now;
	e->duration_ns = payload;
	e->pid = pid;
	e->event_type = type;
	if (comm)
		bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), comm);
	else
		e->comm[0] = '\0';
	bpf_ringbuf_submit(e, 0);
}

/* Arm the one-shot change-point timer to fire in `delay` ns (delay clamped >0). */
static __always_inline void arm_timer(u64 delay)
{
	struct timer_wrap *tw;
	u32 zero = 0;

	if ((s64)delay <= 0)
		delay = 1;
	tw = bpf_map_lookup_elem(&timer_map, &zero);
	if (tw)
		bpf_timer_start(&tw->timer, delay, 0);
}

/*
 * Start a fresh PCT epoch for a new governed execution. Draws the whole schedule
 * from this epoch's pool window (positional; see intf.h): a base-priority seed, a
 * bug depth d, a horizon, and d-1 change-point times scattered across it. The
 * change points are laid down as cumulative gaps so cp_time[] is monotonic by
 * construction -- no sort -- and each is assigned a distinct demotion priority
 * d-1, d-2, …, 1 (earlier point -> higher residual priority, as textbook PCT).
 */
static __always_inline void start_epoch(u64 now)
{
	u32 base = (u32)((epoch_no % EPOCHS_MAX) * SLOTS_PER_EPOCH);
	u64 horizon, span, t;
	u32 d;
	int i;

	base_seed = pool_at(base + 0);

	/* Depth d in [2, max_depth]; n_cp = d-1 change points, capped at MAX_CP. */
	d = 2 + (u32)(pool_at(base + 1) % (max_depth >= 2 ? max_depth - 1 : 1));
	if (d < 2)
		d = 2;
	if (d > max_depth)
		d = max_depth;
	depth = d;
	n_cp = d - 1;
	if (n_cp > MAX_CP)
		n_cp = MAX_CP;

	/* Horizon: the emulated-TSC window the change points are scattered over. */
	horizon = horizon_min_ns;
	if (horizon_max_ns > horizon_min_ns)
		horizon += pool_at(base + 2) % (horizon_max_ns - horizon_min_ns);
	span = n_cp ? horizon / n_cp : horizon;
	if (span == 0)
		span = 1;

	/* Scatter the change points as cumulative gaps in (0, 2*span] so they are
	 * monotonically increasing and average out to ~horizon total. */
	t = now;
	for (i = 0; i < MAX_CP; i++) {
		if (i < (int)n_cp) {
			u64 gap = 1 + pool_at(base + 3 + i) % (2 * span);

			t += gap;
			cp_time[i] = t;
			cp_prio[i] = d - 1 - (u32)i;	/* d-1, d-2, …, 1 */
			cp_fired[i] = false;
		} else {
			cp_time[i] = 0;
			cp_prio[i] = 0;
			cp_fired[i] = true;		/* inert */
		}
		dem_active[i] = false;
		dem_pid[i] = 0;
		dem_prio[i] = 0;
		dem_expire[i] = 0;
	}

	log_event(depth, NULL, FUZZ_EVENT_EPOCH_BEGIN, now, horizon);

	if (n_cp)
		arm_timer(cp_time[0] - now);

	epoch_no++;
}

/* Base priority of a thread: high (>= max_depth), stable within an epoch. */
static __always_inline u32 base_prio(u32 pid)
{
	return max_depth + (u32)(hash2(pid, base_seed) % prio_spread);
}

/*
 * Current priority of a thread: its base priority, unless a live (unexpired)
 * change-point demotion has lowered it. Multiple change points can demote the
 * same thread; the lowest (most recent) demotion wins.
 */
static __always_inline u32 task_prio(u32 pid, u64 now)
{
	u32 prio = base_prio(pid);
	int i;

	for (i = 0; i < MAX_CP; i++) {
		if (dem_active[i] && dem_pid[i] == pid && now < dem_expire[i] &&
		    dem_prio[i] < prio)
			prio = dem_prio[i];
	}
	return prio;
}

/*
 * Advance the change-point schedule: fire every change point now due, demoting
 * the currently-running thread, and re-arm the timer for the next one. Called
 * from the scheduling hooks and from the timer, all serialized on the single
 * vCPU. A preempt kick follows a firing so the just-demoted running thread is
 * re-enqueued (at its new low priority) promptly.
 */
static __always_inline void advance_schedule(u64 now)
{
	bool need_preempt = false;
	u64 next_t = 0;
	int i;

	if (!started)
		return;

	for (i = 0; i < MAX_CP; i++) {
		if (i >= (int)n_cp || cp_fired[i])
			continue;
		if (now >= cp_time[i]) {
			cp_fired[i] = true;
			dem_active[i] = true;
			dem_pid[i] = cur_pid;
			dem_prio[i] = cp_prio[i];
			dem_expire[i] = now + max_demote_ns;
			log_event(cur_pid, NULL, FUZZ_EVENT_DEMOTE, now,
				  cp_prio[i]);
			need_preempt = true;
		} else if (next_t == 0 || cp_time[i] < next_t) {
			next_t = cp_time[i];
		}
	}

	if (next_t)
		arm_timer(next_t - now);
	if (need_preempt)
		scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT);
}

s32 BPF_STRUCT_OPS(chaos_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/*
	 * Do not direct-dispatch here. Returning prev_cpu without inserting the
	 * task forces every wakeup through enqueue(), so the policy sees it.
	 */
	return prev_cpu;
}

void BPF_STRUCT_OPS(chaos_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns();
	u32 pid = BPF_CORE_READ(p, pid);
	u32 prio;
	u64 key;

	/* Fire any due change points before pricing this task. */
	advance_schedule(now);

	prio = task_prio(pid, now);
	key = KEY_BASE - prio;	/* higher priority -> lower key -> runs first */

	if (debug && dbg_logged < 64) {
		dbg_logged++;
		log_event(pid, BPF_CORE_READ(p, comm), FUZZ_EVENT_DEBUG, now,
			  pid);
	}

	scx_bpf_dsq_insert_vtime(p, FAIR_DSQ_ID, slice_ns, key, enq_flags);

	/*
	 * PCT runs the highest-priority enabled thread: if this waker outranks the
	 * task on the CPU, kick a preempt so it takes over at the next dispatch
	 * rather than waiting out the running slice.
	 */
	if (started && prio > cur_prio)
		scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(chaos_dispatch, s32 cpu, struct task_struct *prev)
{
	advance_schedule(bpf_ktime_get_ns());
	/* Run the highest-priority (lowest-key) runnable task. */
	scx_bpf_dsq_move_to_local(FAIR_DSQ_ID);
}

/* Track the running task so a change point knows whom to demote and so
 * wake-preemption can compare priorities. */
void BPF_STRUCT_OPS(chaos_running, struct task_struct *p)
{
	cur_pid = BPF_CORE_READ(p, pid);
	cur_prio = task_prio(cur_pid, bpf_ktime_get_ns());
}

/*
 * Per-execution epoch bracketing. A fresh PCT schedule is drawn whenever a new
 * governed *process leader* appears -- a task with pid == tgid (a process main,
 * not a worker thread) whose tgid differs from the current epoch's. This fires
 * for each fresh `thread-fuzz mptest` exec (a new tgid every run.sh iteration)
 * and for the IPC server it forks, so one boot yields many independent PCT
 * samples. It is deliberately NOT a "governed task count returned to zero"
 * trigger: sched_ext's enable/disable are class-transition hooks, not a balanced
 * task-lifetime bracket, so a counter drifts and never returns to zero -- which
 * pinned the whole boot to a single schedule. tgids are monotonic within a
 * deterministic boot, so each leader is seen once and never re-triggers.
 */
void BPF_STRUCT_OPS(chaos_enable, struct task_struct *p)
{
	u32 pid = BPF_CORE_READ(p, pid);
	u32 tgid = BPF_CORE_READ(p, tgid);

	if (pid == tgid && tgid != epoch_leader_tgid) {
		epoch_leader_tgid = tgid;
		started = true;
		start_epoch(bpf_ktime_get_ns());
	}
}

static int timer_cb(void *map, int *key, struct timer_wrap *tw)
{
	u32 nr = scx_bpf_nr_cpu_ids();
	u32 i;

	/*
	 * Kick the CPU(s) so dispatch re-runs and advance_schedule() fires the
	 * change point that just came due, even if the CPU was idle. On the
	 * single-vCPU target this is just CPU 0; the bounded loop keeps it correct
	 * on a multi-CPU host and keeps the verifier happy. Not re-armed here --
	 * advance_schedule() arms the next one.
	 */
	for (i = 0; i < MAX_CPUS; i++) {
		if (i >= nr)
			break;
		scx_bpf_kick_cpu(i, 0);
	}
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chaos_init)
{
	struct timer_wrap *tw;
	u32 zero = 0;
	s32 ret;

	ret = scx_bpf_create_dsq(FAIR_DSQ_ID, -1);
	if (ret)
		return ret;

	tw = bpf_map_lookup_elem(&timer_map, &zero);
	if (!tw)
		return -1;
	bpf_timer_init(&tw->timer, &timer_map, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tw->timer, timer_cb);
	/* Armed on demand by start_epoch/advance_schedule; no periodic timer. */

	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops chaos_ops = {
	.select_cpu = (void *)chaos_select_cpu,
	.enqueue    = (void *)chaos_enqueue,
	.dispatch   = (void *)chaos_dispatch,
	.running    = (void *)chaos_running,
	.enable     = (void *)chaos_enable,
	.init       = (void *)chaos_init,
	/*
	 * SCX_OPS_SWITCH_PARTIAL: govern only tasks whose policy is SCHED_EXT
	 * (thread-fuzz opts the workload in); everything else stays on stock CFS.
	 * SCX_OPS_ENQ_LAST: keep getting enqueue() for the last runnable task so a
	 * lone demoted thread still cycles through the policy.
	 */
	.flags      = SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST,
	.timeout_ms = 5000,
	.name       = "chaos_fuzz",
};
