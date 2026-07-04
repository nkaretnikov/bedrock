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
 * Mechanism -- a deterministic-fair base with PCT as a sparse overlay:
 *   - Base policy: weighted virtual-time fairness (like scx_simple), driven by
 *     each task's scx.dsq_vtime charged by the emulated-TSC runtime it consumes.
 *     The lowest-vtime runnable task runs next, so the base distribution of
 *     interleavings stays close to stock Linux (CFS/EEVDF) -- the regime the
 *     libmultiprocess CI repros actually lived in. Under the single vCPU +
 *     emulated TSC this fairness is fully deterministic (stock CFS's
 *     nondeterminism comes from wall-clock + SMP load-balancing, neither of
 *     which exists here).
 *   - PCT overlay: in a perturbed epoch, d-1 "change points" are placed in the
 *     execution. When one fires, the *currently running* thread's effective
 *     vtime is pushed forward by a penalty (the fair analog of textbook PCT's
 *     priority demotion), so the vtime-fair base runs a different thread. Those
 *     forced preemptions, placed randomly, are what expose depth-d bugs.
 *   - Realism knob (cp_prob_pct, per-boot rodata): only that fraction of epochs
 *     are perturbed; the rest run the pure fair base. cp_prob_pct = 0 is
 *     effectively stock-fair (maximum fidelity to the CI repro conditions), 100
 *     is aggressive PCT. boot_seed thus sweeps the fidelity axis.
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
 * Mechanism (sched_ext): one vtime-ordered DSQ keyed by each task's effective
 * vtime (fair dsq_vtime, floored to bound sleep credit, plus any live
 * change-point penalty), so dispatch() -- which pulls the lowest vtime -- runs
 * the task furthest behind. A thread that blocks leaves the DSQ; on wake it is
 * re-inserted at its current vtime. A change-point penalty takes effect the next
 * time the penalized thread is re-enqueued, hurried along by a preempt kick.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/* Single dispatch queue, ordered by effective vtime (see task_vtime). */
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
 * Read-only configuration, set by scx-init before the program is loaded.
 * "const volatile" is how sched_ext schedulers expose rodata to user space.
 * These are per-boot bounds; the actual per-epoch values (depth, horizon,
 * change-point placement) are drawn from the pool at runtime.
 */
const volatile u64 slice_ns;		/* base timeslice for the vtime-fair policy */
const volatile u64 horizon_min_ns;	/* change-point horizon, low bound */
const volatile u64 horizon_max_ns;	/* change-point horizon, high bound */
const volatile u64 max_demote_ns;	/* demotion penalty magnitude + lifetime (starvation cap) */
const volatile u32 max_depth;		/* max bug depth d (>= 2); depth drawn in [2, max_depth] */
const volatile u32 prio_spread;		/* retained for ABI; unused by the vtime-fair base */
const volatile u32 cp_prob_pct;		/* realism knob: % of epochs perturbed by change points */
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
static u64 base_seed;		/* per-epoch key for the perturb gate / hashing */
static u32 depth;		/* bug depth d drawn this epoch */
static u32 n_cp;		/* change points this epoch (0 in an unperturbed epoch) */
static u32 cur_pid;		/* pid of the task currently running */
static u64 cur_run_start;	/* emulated-TSC time cur_pid began running (vtime charge) */
static u64 cur_vtime;		/* cur_pid's effective vtime when it started (for preempt) */
static u64 vtime_now;		/* global fair virtual clock: max dispatched dsq_vtime */

/* The change-point schedule for this epoch, and the penalties it has produced. */
static u64 cp_time[MAX_CP];	/* emulated-TSC time each change point fires */
static bool cp_fired[MAX_CP];	/* whether it has fired yet */
static u32 dem_pid[MAX_CP];	/* pid penalized by change point i */
static u64 dem_expire[MAX_CP];	/* when the penalty lifts (starvation cap) */
static bool dem_active[MAX_CP];	/* whether this penalty is live */

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

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

/*
 * Interleaving-coverage bitmap (signal A). A single-entry array whose one value
 * is SCHED_COV_N saturating byte counters. BPF_F_MMAPABLE lets scx-init mmap the
 * map's backing pages and register them with the host as a feedback buffer, so
 * the host reads the same physical bytes the scheduler bumps -- zero-copy, out
 * of band, never visible to the guest.
 */
struct cov_buf {
	u8 bytes[SCHED_COV_N];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, u32);
	__type(value, struct cov_buf);
} cov_map SEC(".maps");

/* AFL-style hitcount bump: saturating-increment the counter for edge `h`. */
static __always_inline void cov_record(u64 h)
{
	u32 zero = 0;
	struct cov_buf *b = bpf_map_lookup_elem(&cov_map, &zero);
	u8 *cell;

	if (!b)
		return;
	cell = &b->bytes[h & (SCHED_COV_N - 1)];
	if (*cell != 0xff)
		(*cell)++;
}

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

/*
 * Last thread to touch each lock, for lock-ordering coverage (signal C). Keyed
 * by (futex uaddr, tgid) -- a uaddr is only meaningful within one address space,
 * so the tgid keeps two governed processes (e.g. mptest and a separate IPC
 * server) with a lock at the same virtual address from conflating -- valued by
 * the toucher's comm tag. Sized for the handful of hot IPC locks with headroom.
 */
struct lock_key {
	u64 uaddr;
	u32 tgid;
	u32 _pad;	/* zeroed so the raw-bytes hash-map key has no junk padding */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct lock_key);
	__type(value, u64);
} last_toucher SEC(".maps");

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

/*
 * Signal A interleaving-coverage state. prev_loc carries the previous handoff's
 * tag so the next switch records the edge (prev, cur); pending_preempt marks
 * that the next switch-in was forced by a change point, so a PCT-induced
 * reordering hashes to a distinct edge from a natural block/wake. Touched only
 * from the ops callbacks, serialized on the single vCPU like the epoch state.
 */
static u64 prev_loc;
static bool pending_preempt;

/*
 * Per-thread identity for coverage: a hash of the kernel comm, which libtag.c
 * (LD_PRELOAD) sets to the thread's spawn call-site ("mp:<offset>"), stable
 * across schedules and fork siblings. The untagged initial thread keeps comm
 * "mptest" -- a fine distinct "client" tag. FNV-1a over the 16-byte comm.
 */
static __always_inline u64 thread_tag(struct task_struct *p)
{
	char comm[FUZZ_COMM_LEN];
	u64 h = 1469598103934665603ULL;
	int i;

	BPF_CORE_READ_STR_INTO(&comm, p, comm);
	for (i = 0; i < FUZZ_COMM_LEN; i++) {
		if (comm[i] == '\0')
			break;
		h ^= (u8)comm[i];
		h *= 1099511628211ULL;
	}
	return h;
}

/*
 * Lock/access-ordering coverage (signal C). On each futex wait/wake, record the
 * ordered pair (previous toucher -> current toucher) on this lock as an edge,
 * keyed by the lock's identity (the futex uaddr). Distinct mutexes/condvars sit
 * at distinct addresses, so this captures the acquire/signal order per lock --
 * exactly where the mptest IPC races live (#35491 missed-wakeup between the
 * done-check and the post; #34014 fulfill racing a cancel). Folded into the same
 * schedcov bitmap as signal A.
 *
 * Gated to SCHED_EXT tasks so host daemons' futexes neither pollute the signal
 * nor leak nondeterminism. Guest-kernel reads only, no VM exits, and uaddr is a
 * pure function of governed guest state, so a given input replays identical edges.
 */
static __always_inline void cov_record_lock(u64 uaddr)
{
	struct task_struct *p = bpf_get_current_task_btf();
	struct lock_key k = {};
	u64 cur, prev, *last;

	if (BPF_CORE_READ(p, policy) != SCHED_EXT)
		return;

	k.uaddr = uaddr;
	k.tgid = BPF_CORE_READ(p, tgid);

	cur = thread_tag(p);
	last = bpf_map_lookup_elem(&last_toucher, &k);
	prev = last ? *last : 0;
	/* Fold tgid into the edge too, so same-address locks in different governed
	 * processes light distinct cells. */
	cov_record(hash2(uaddr, prev) ^ cur ^ ((u64)k.tgid << 20));
	bpf_map_update_elem(&last_toucher, &k, &cur, BPF_ANY);
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
 * Start a fresh epoch for a new governed execution. Draws the whole schedule
 * from this epoch's pool window (positional; see intf.h): a hash seed, a bug
 * depth d, a horizon, and -- only if this epoch is perturbed -- d-1 change-point
 * times scattered across it as cumulative gaps (so cp_time[] is monotonic by
 * construction, no sort). Whether the epoch is perturbed is the realism knob:
 * only a cp_prob_pct fraction of epochs carry change points, the rest run the
 * pure vtime-fair base. The gate is derived from base_seed, so it consumes no
 * extra pool slot and replays deterministically.
 */
static __always_inline void start_epoch(u64 now)
{
	u32 base = (u32)((epoch_no % EPOCHS_MAX) * SLOTS_PER_EPOCH);
	u64 horizon, span, t;
	bool perturb;
	u32 d;
	int i;

	base_seed = pool_at(base + 0);

	/* Realism knob: is this epoch perturbed by change points at all? */
	perturb = (u32)(hash2(base_seed, 0x50D1CEULL) % 100) < cp_prob_pct;

	/* Depth d in [2, max_depth]; n_cp = d-1 change points (0 if unperturbed). */
	d = 2 + (u32)(pool_at(base + 1) % (max_depth >= 2 ? max_depth - 1 : 1));
	if (d < 2)
		d = 2;
	if (d > max_depth)
		d = max_depth;
	depth = d;
	n_cp = perturb ? d - 1 : 0;
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
			cp_fired[i] = false;
		} else {
			cp_time[i] = 0;
			cp_fired[i] = true;		/* inert */
		}
		dem_active[i] = false;
		dem_pid[i] = 0;
		dem_expire[i] = 0;
	}

	log_event(depth, NULL, FUZZ_EVENT_EPOCH_BEGIN, now, horizon);

	if (n_cp)
		arm_timer(cp_time[0] - now);

	epoch_no++;
}

/* Signed vtime comparison: true if `a` is before `b` (wraparound-safe). */
static __always_inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Live change-point penalty on a thread: a virtual-time offset that pushes a
 * penalized thread behind its fair peers until the penalty expires (the
 * starvation cap). Uniform magnitude -- max_demote_ns of virtual time per live
 * change point that hit this pid -- summed. This is the fair-scheduler analog of
 * textbook PCT's priority demotion: rather than a strict-priority drop, the
 * victim's effective vtime jumps forward so the vtime-fair base runs someone else.
 */
static __always_inline u64 task_penalty(u32 pid, u64 now)
{
	u64 pen = 0;
	int i;

	for (i = 0; i < MAX_CP; i++) {
		if (dem_active[i] && dem_pid[i] == pid && now < dem_expire[i])
			pen += max_demote_ns;
	}
	return pen;
}

/*
 * Effective enqueue vtime for a task: its fair dsq_vtime, floored so a task that
 * slept a long time cannot monopolize the CPU (bounded backward credit, like
 * scx_simple), plus any live change-point penalty. Lowest effective vtime
 * dispatches first.
 */
static __always_inline u64 task_vtime(struct task_struct *p, u32 pid, u64 now)
{
	u64 vt = p->scx.dsq_vtime;

	if (vtime_before(vt, vtime_now - slice_ns))
		vt = vtime_now - slice_ns;
	return vt + task_penalty(pid, now);
}

/*
 * Advance the change-point schedule: fire every change point now due, penalizing
 * the currently-running thread's vtime, and re-arm the timer for the next one.
 * Called from the scheduling hooks and from the timer, all serialized on the
 * single vCPU. A preempt kick follows a firing so the just-penalized running
 * thread is re-enqueued (behind its peers) promptly.
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
			dem_expire[i] = now + max_demote_ns;
			log_event(cur_pid, NULL, FUZZ_EVENT_DEMOTE, now,
				  max_demote_ns);
			need_preempt = true;
		} else if (next_t == 0 || cp_time[i] < next_t) {
			next_t = cp_time[i];
		}
	}

	if (next_t)
		arm_timer(next_t - now);
	if (need_preempt) {
		/* Tag the next switch-in as change-point-forced for signal A. */
		pending_preempt = true;
		scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT);
	}
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
	u64 vtime;

	/* Fire any due change points before pricing this task. */
	advance_schedule(now);

	vtime = task_vtime(p, pid, now);

	if (debug && dbg_logged < 64) {
		dbg_logged++;
		log_event(pid, BPF_CORE_READ(p, comm), FUZZ_EVENT_DEBUG, now,
			  pid);
	}

	scx_bpf_dsq_insert_vtime(p, FAIR_DSQ_ID, slice_ns, vtime, enq_flags);

	/*
	 * Fair preemption: if this waking task is further behind (earlier effective
	 * vtime) than the one on the CPU, kick a preempt so ordering is honored at
	 * the next dispatch rather than waiting out the running slice. This is also
	 * how a change point's penalty lands promptly -- the penalized runner now
	 * sorts after this waker.
	 */
	if (started && pid != cur_pid && vtime_before(vtime, cur_vtime))
		scx_bpf_kick_cpu(0, SCX_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(chaos_dispatch, s32 cpu, struct task_struct *prev)
{
	advance_schedule(bpf_ktime_get_ns());
	/* Run the highest-priority (lowest-key) runnable task. */
	scx_bpf_dsq_move_to_local(FAIR_DSQ_ID);
}

/* Track the running task so a change point knows whom to penalize, so fair
 * preemption can compare vtimes, and so stopping() can charge the runtime. Also
 * advance the global fair clock to this task's vtime. */
void BPF_STRUCT_OPS(chaos_running, struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	u64 loc;

	cur_pid = BPF_CORE_READ(p, pid);
	cur_run_start = now;
	cur_vtime = task_vtime(p, cur_pid, now);

	/* Monotonically advance the fair clock toward the running task's vtime. */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/*
	 * Interleaving coverage (signal A): record this context switch as an
	 * AFL-style edge over consecutively-run threads, keyed by the stable
	 * comm tag. If a change point forced this switch, perturb the tag so the
	 * forced reordering lights a distinct edge from the same natural handoff.
	 * Host-read out of band; adds no VM exits, so the emulated TSC and the
	 * schedule are unchanged and a given input replays identical coverage.
	 */
	loc = thread_tag(p);
	if (pending_preempt) {
		loc ^= 0x9E3779B97F4A7C15ULL;
		pending_preempt = false;
	}
	cov_record(prev_loc ^ loc);
	prev_loc = loc >> 1;
}

/*
 * Charge the vtime a task consumed while running, so the vtime-fair base slides
 * it behind its peers in proportion to CPU time used -- the mechanism that makes
 * the base policy fair. Equal weights (the deterministic single-vCPU target has
 * no nice/cgroup weighting to track), so the vtime charge is just the emulated-
 * TSC runtime. Guard on cur_pid in case stopping fires for a task we did not
 * observe starting.
 */
void BPF_STRUCT_OPS(chaos_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns();

	if (BPF_CORE_READ(p, pid) != cur_pid)
		return;
	p->scx.dsq_vtime += now - cur_run_start;
	cur_run_start = now;
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

	/* A newly-governed task starts at the current fair clock, so it neither
	 * starves nor carries unbounded backward credit from a zero vtime. */
	p->scx.dsq_vtime = vtime_now;

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

/*
 * Signal C probes. futex_wait / futex_wake are the contended-lock slow paths for
 * glibc std::mutex and std::condition_variable -- the primitives mptest's
 * cross-thread IPC handoff uses (EventLoop::post's m_mutex/m_cv, clientInvoke's
 * Waiter). arg0 is the userspace futex address in both (kernel/futex/waitwake.c),
 * i.e. the lock identity. Both symbols are global, so fentry attaches via BTF.
 * Attached by scx-init; best-effort (the scheduler runs without them).
 */
SEC("fentry/futex_wait")
int BPF_PROG(on_futex_wait, u32 *uaddr, unsigned int flags, u32 val,
	     void *abs_time, u32 bitset)
{
	cov_record_lock((u64)uaddr);
	return 0;
}

SEC("fentry/futex_wake")
int BPF_PROG(on_futex_wake, u32 *uaddr, unsigned int flags, int nr_wake,
	     u32 bitset)
{
	cov_record_lock((u64)uaddr);
	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops chaos_ops = {
	.select_cpu = (void *)chaos_select_cpu,
	.enqueue    = (void *)chaos_enqueue,
	.dispatch   = (void *)chaos_dispatch,
	.running    = (void *)chaos_running,
	.stopping   = (void *)chaos_stopping,
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
