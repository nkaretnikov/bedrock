# Hardware data-breakpoint race detector (DataCollider-style) — plan

Goal: a FAST watchpoint mechanism that triggers ONLY when a race occurs, not on
every shared write. Demote the EPT write-watchpoint to a cheap *candidate
sampler*; make the race *trigger* a hardware data breakpoint (DR0-3). On one
vCPU a race manifests as a second thread touching the same exact byte/word with
no ordering; a hardware DR fires a precise #DB (no PEBS skid, deterministic) only
on that second access. Arming a DR is a register write (NO INVEPT), and the only
new exit is the conflict #DB, so the common case (non-conflicting writes) is free.

This is DataCollider (Erickson, OSDI 2010) adapted to bedrock's deterministic
single-vCPU model: reuse `raise_preempt_vector` to CREATE the interleaving, use
the DR to DETECT that the interleaving realized a conflict. RaceBench's own
injected-bug manifestation stays the ground-truth oracle.

## Enablers already in tree
- Exact faulting linear addr already read on EPT violations: `exits/ept.rs`
  `GuestLinearAddr` (currently discarded as `_guest_linear`).
- `#DB` intercept = 1 bit in the exception bitmap (`ExceptionBitmap` 0x4004,
  currently `#MC`-only at `traits/vmcs.rs:297`) + a branch in the existing
  `handle_exception_nmi` (`exits/misc.rs`) reading DR6.
- Guest DR0-3 currently unused (read back 0, `traits/registers.rs`), so we can
  own them; `GuestDr7` VMCS field 0x681A already loaded via the register path.
- Per-iteration host/guest hardware swap pattern already exists for PEBS
  `IA32_DS_AREA` in `traits/vm_run.rs` run_loop — DR save/restore mirrors it.

## Design

### 1. State: `DebugWatchState` (new, in cow.rs or a new dr_watch.rs)
4 slots. Each: `{ gva: u64, len: u8 (1/2/4/8), owner_tid: u64, arm_epoch: u32 }`.
Plus `dr7: u64` computed from occupied slots (L0-L3 local-enable + RW=11 write or
11b data + LEN encoding), `dr6_capture: u64` (read after exit), a small
round-robin `next_slot` cursor, and generation counter for stats.
Lives in `VmState` (boxed) next to the existing watchpoint fields.

### 2. Candidate capture (arm a DR)
Thread the faulting GVA into `handle_cow_fault` (add a `gva: u64` param; callers
in `exits/ept.rs` pass `_guest_linear`, others pass 0). Reuse the existing
CPL3 + confirmed-shared classifier. On a confirmed-shared CPL3 write, instead of
the coin-flip preempt, feed `(gva, tid)` to the DR allocator:
- if a slot is free (or evict the oldest by arm_epoch), arm slot on `gva` for
  `owner_tid = tid`, len = access width (default 4 for the volatile u32 bugs),
  RW = write-or-readwrite;
- then `raise_preempt_vector` to force a switch so another thread runs with the
  DR live (this is what makes the conflict observable).
Arming is register-only: set the slot, recompute dr7, mark `dr_dirty`. No INVEPT.

Keep the EPT layer's cull aggressive: once a page has contributed a DR candidate,
it can be culled (granted W) — the DR now does detection, EPT need not re-trap.

### 3. #DB handling (`handle_exception_nmi`, vector 1)
Gate on `debug_watch active`. Steps:
- read DR6 (from `dr6_capture` saved by the run loop), find fired slot(s)
  (DR6 bits 0-3 = B0-B3);
- read current tid (FS_BASE) + cpl;
- if `cpl==3 && tid != slot.owner_tid`  => RACE realized:
  `wp_dr_conflicts += 1`; `raise_preempt_vector` again (interleave further);
  optionally one-shot disarm the slot (avoid re-fire storms) or keep armed for a
  bounded epoch window; clear DR6; `Continue` (data #DB is a trap: the guest
  access already completed, just resume — do NOT reflect to guest);
- if `tid == owner_tid` (owner re-touched, not a race): `wp_dr_self += 1`, clear
  DR6, `Continue`. Optionally disarm to cut noise.
- NEVER `inject_exception(#DB)` — this #DB is ours.
Determinism: DR6 read + tid compare + IRR set are pure functions of guest state.

### 4. MOV DR trapping (guest can't see/clobber our DRs)
Set primary proc-based control "MOV-DR exiting". New handler emulates guest MOV
DR against a *shadow* DR set (reads return shadow, writes update shadow only,
never touch real DR0-3/DR7). RaceBench Linux workloads don't use DRs, so this is
cold; add `wp_dr_movdr` stat. Without this the guest could overwrite our DRs and
also break determinism.

### 5. Run-loop hardware swap (kernel only; `traits/vm_run.rs`, mirrors PEBS)
Gated on `debug_watch.any_armed()`:
- before VMRESUME: save host DR0-3/DR6/DR7; load guest DR0-3 from slots; write
  VMCS `GuestDr7` = computed dr7 (own it fully while active); set VMCS "load
  debug controls" entry control (already set by register path);
- after exit: read hardware DR6 into `dr6_capture`, then restore host
  DR0-3/DR6/DR7. Zero cost when no slot armed.
New Vmx trait primitives (real in kernel, mock in tests):
`write_dr0..3(u64)`, `write_dr7(u64)`, `read_dr6()->u64`, `write_dr6(u64)`,
`read_dr0..3()/read_dr7()` for host save. Model as `DebugRegAccess` on Machine
or static methods on `Vmx` (mirror `invept_single_context`).

### 6. Config knobs (bedrock-cli main.rs -> VmConfig -> ApicState/VmState)
- `BEDROCK_WATCHPOINT_DR=1` : enable the DR race detector (0/off default).
  Reuse `BEDROCK_WATCHPOINT_PCT` != 0 to keep the EPT candidate sampler on.
- `BEDROCK_WATCHPOINT_DR_LEN` (default 4), `..._RW` (default write).
- Slots fixed at 4 (hardware). `..._ONESHOT` (default 1) = disarm on conflict.

### 7. Stats (stats.rs + kernel ABI structs.rs)
`wp_dr_armed`, `wp_dr_conflicts`, `wp_dr_self`, `wp_dr_evictions`, `wp_dr_movdr`.
Surface in the exit-stats block next to the existing `wp_*` counters.

## Determinism invariants
- #DB is precise, no skid (better than PEBS/MTF). New exits shift exit-count TSC
  deterministically (same as EPT watchpoints today).
- Never leak host DR state to guest: full save/restore around VMRESUME; MOV DR
  emulated against a shadow.
- IRR-only preemption (never PEBS) — same rule as the existing path.

## Build order (each cargo-green)
1. State + config + stats + Vmx-trait primitive + mocks (no behavior yet).
2. Candidate capture + DR allocator + `handle_cow_fault` gva threading.
3. `#DB` handler + tid-compare conflict logic + tests.
4. MOV-DR shadow handler.
5. Kernel run-loop DR swap + exception-bitmap/proc-ctrl wiring (on-box build).
6. On-box: smoke, then sweep vs the EPT-only mechanism; diff bug-id coverage.

## Validation
`just test` at each step. On-box: parent/child flake targets with
`BEDROCK_WATCHPOINT_PCT=20 BEDROCK_WATCHPOINT_DR=1`; success = `wp_dr_conflicts`
> 0 and coverage of the streamcluster sweep beats the EPT-only mechanism.
