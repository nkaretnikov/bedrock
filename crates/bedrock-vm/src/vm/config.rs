// SPDX-License-Identifier: GPL-2.0

//! Configuration types for VM ioctls.

use crate::events::EventCategories;

pub use bedrock_vmx::ExitTrigger;

/// Single-step configuration for MTF (Monitor Trap Flag) mode.
///
/// Configures the VM to single-step (exit after each instruction) within
/// a specified emulated TSC range. This is useful for debugging determinism
/// issues by tracing every instruction in a specific region.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SingleStepConfig {
    /// Whether single-stepping is enabled.
    /// 0 = disabled, non-zero = enabled.
    pub enabled: u64,
    /// Start of TSC range (inclusive).
    pub tsc_start: u64,
    /// End of TSC range (exclusive).
    pub tsc_end: u64,
}

/// Synthetic exit reason for checkpoint records.
/// This value identifies an `Exit` record that is a periodic state snapshot
/// rather than an actual VM exit.
pub const EXIT_REASON_CHECKPOINT: u32 = 0xFFFFFFFF;

/// Bit flag: skip memory hashing in exit records (set `memory_hash` to 0).
pub const EXIT_FLAG_NO_MEMORY_HASH: u32 = 1 << 0;
/// Bit flag: intercept guest #PF exceptions for determinism analysis.
pub const EXIT_FLAG_INTERCEPT_PF: u32 = 1 << 1;
/// Bit flag: tolerate a PEBS skid larger than the host margin instead of
/// aborting the run. Absent (the default) means a skid past the margin is
/// fatal, since the armed deadline would be delivered late and break
/// determinism.
pub const EXIT_FLAG_IGNORE_PEBS_MARGIN: u32 = 1 << 2;
/// Bit flag: tolerate a late APIC-timer injection (the interrupt delivered on
/// an exit past its deadline) instead of aborting the run. Absent (the default)
/// means a late inject is fatal, since it means the timer landed at a different
/// instruction than the deadline and guest execution diverges. Separate from
/// [`EXIT_FLAG_IGNORE_PEBS_MARGIN`]: a skid past the margin is one cause of a
/// late inject, but the timer can also arrive late through other misses.
pub const EXIT_FLAG_IGNORE_LATE_INJECT: u32 = 1 << 3;

/// Unified event-stream configuration passed to the kernel via ioctl.
///
/// One struct configures the whole stream: enabling it allocates the 1 MB event
/// buffer (mmap'd to userspace) and installs the category mask, while the
/// `exit_*` fields carry the trigger policy for `Exit` records. The mask filters
/// records at emit time, so a disabled category costs a single bit test in the
/// hypervisor. The stream is fully opt-in: with `enabled = 0` (the default)
/// nothing is allocated and the hypervisor emits no events.
///
/// The category mask and the exit trigger are orthogonal dimensions: for `Exit`
/// records to appear, the [`EventCategories::EXIT`] bit must be set *and*
/// `exit_trigger` must be something other than [`ExitTrigger::Disabled`].
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EventConfig {
    /// Whether the event stream is enabled. The disabled->enabled transition
    /// allocates the event buffer; enabled->disabled frees it.
    pub enabled: u32,
    /// Category include mask (see [`EventCategories`]). Records whose category
    /// bit is clear are dropped at emit time.
    pub categories: u32,
    /// `Exit`-record trigger policy ([`ExitTrigger`] as u32).
    pub exit_trigger: u32,
    /// Exit flags bitfield (see `EXIT_FLAG_*` constants).
    pub exit_flags: u32,
    /// Mode-specific TSC for the exit trigger:
    /// - `AtTsc`: emit once when emulated_tsc >= this value
    /// - `Checkpoints`: interval between checkpoint records
    /// - others: ignored
    pub exit_target_tsc: u64,
    /// Universal start threshold — no `Exit` records until emulated_tsc reaches
    /// this value. 0 = capture from the start.
    pub exit_start_tsc: u64,
    /// Instruction-granular preemption period: retired instructions between
    /// deterministic forced preemptions. 0 (the default) disables the feature.
    /// See `ApicState::configure_preempt` in bedrock-vmx.
    pub preempt_period: u64,
    /// Seed for the preemption-interval jitter PRNG (only meaningful when
    /// `preempt_period != 0`). A dedicated stream, separate from RDRAND.
    pub preempt_seed: u64,
    /// EPT write-watchpoint directed preemption: percent chance [0, 100) of
    /// forcing a preemption at each watched shared-memory write. 0 (the default)
    /// disables the feature. See `ApicState::configure_watchpoints` in
    /// bedrock-vmx.
    pub watchpoint_pct: u32,
    /// Seed for the per-hit watchpoint decision PRNG (only meaningful when
    /// `watchpoint_pct != 0`). A dedicated stream, separate from RDRAND.
    pub watchpoint_seed: u64,
    /// Arm-then-cull: thread switches a single-writer watched page must survive
    /// before culling (0 = use default). See `ApicState::configure_watchpoints`.
    pub watchpoint_cull_epochs: u32,
    /// Arm-then-cull: fault-count backstop for a page that never spans a switch
    /// (0 = use default). See `ApicState::configure_watchpoints`.
    pub watchpoint_cull_cap: u32,
    /// Sampling re-arm interval in emulated-TSC ticks: how often let-through
    /// watchpoints are batch re-protected to R+E (0 = use default). See
    /// `ApicState::configure_watchpoints`.
    pub watchpoint_rearm: u64,
    /// Enable the hardware data-breakpoint race detector (DataCollider-style):
    /// confirmed-shared writes arm a `DR` on the exact address, and a `#DB` from
    /// a different thread is a realized race. Requires `watchpoint_pct != 0` for
    /// candidates. See `ApicState::configure_watchpoint_dr`.
    pub watchpoint_dr: bool,
    /// Watch length in bytes for `DR` slots (0 = default 4).
    pub watchpoint_dr_len: u8,
    /// Disarm a `DR` slot on its first conflict (default true).
    pub watchpoint_dr_oneshot: bool,
    /// Low bound (inclusive) of the RIP window a `DR` candidate must fault from
    /// to be armed (0 with `watchpoint_dr_rip_hi == 0` disables the filter). See
    /// `ApicState::watchpoint_dr_rip_allowed`.
    pub watchpoint_dr_rip_lo: u64,
    /// High bound (exclusive) of the `DR`-candidate RIP window (0 = filter off).
    pub watchpoint_dr_rip_hi: u64,
}

impl EventConfig {
    /// Disabled config (frees the buffer, emits nothing).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Enable the event stream with the given category mask. The exit trigger
    /// starts [`ExitTrigger::Disabled`]; add one with [`with_exit_trigger`](Self::with_exit_trigger).
    pub fn enabled(categories: EventCategories) -> Self {
        Self {
            enabled: 1,
            categories: categories.0,
            ..Default::default()
        }
    }

    /// Set the `Exit`-record trigger policy and its mode-specific TSC value
    /// (`AtTsc` threshold / `Checkpoints` interval; pass 0 for the others).
    pub fn with_exit_trigger(mut self, trigger: ExitTrigger, target_tsc: u64) -> Self {
        self.exit_trigger = trigger as u32;
        self.exit_target_tsc = target_tsc;
        self
    }

    /// Set the universal start threshold — no `Exit` records until the emulated
    /// TSC reaches this value.
    pub fn with_exit_start_tsc(mut self, start_tsc: u64) -> Self {
        self.exit_start_tsc = start_tsc;
        self
    }

    /// Skip memory hashing in exit records (`memory_hash` stays 0).
    pub fn with_no_memory_hash(mut self) -> Self {
        self.exit_flags |= EXIT_FLAG_NO_MEMORY_HASH;
        self
    }

    /// Intercept guest #PF exceptions for determinism analysis.
    pub fn with_intercept_pf(mut self) -> Self {
        self.exit_flags |= EXIT_FLAG_INTERCEPT_PF;
        self
    }

    /// Tolerate a PEBS skid larger than the host margin (the old best-effort
    /// behavior). Without this, such a skid aborts the run immediately.
    pub fn with_ignore_pebs_margin(mut self) -> Self {
        self.exit_flags |= EXIT_FLAG_IGNORE_PEBS_MARGIN;
        self
    }

    /// Tolerate a late APIC-timer injection (the old best-effort behavior).
    /// Without this, a timer delivered past its deadline aborts the run
    /// immediately.
    pub fn with_ignore_late_inject(mut self) -> Self {
        self.exit_flags |= EXIT_FLAG_IGNORE_LATE_INJECT;
        self
    }

    /// Enable deterministic instruction-granular preemption: inject an extra
    /// interrupt roughly every `period` retired instructions (0 = disabled),
    /// with per-interval jitter drawn from `seed`. See
    /// `ApicState::configure_preempt` in bedrock-vmx.
    pub fn with_preempt(mut self, period: u64, seed: u64) -> Self {
        self.preempt_period = period;
        self.preempt_seed = seed;
        self
    }

    /// Enable EPT write-watchpoint directed preemption: force a preemption at
    /// each watched shared-memory write with probability `pct` percent (0 =
    /// disabled), using `seed` for the per-hit decision PRNG. See
    /// `ApicState::configure_watchpoints` in bedrock-vmx.
    pub fn with_watchpoints(
        mut self,
        pct: u32,
        seed: u64,
        cull_epochs: u32,
        cull_cap: u32,
        rearm: u64,
    ) -> Self {
        self.watchpoint_pct = pct;
        self.watchpoint_seed = seed;
        self.watchpoint_cull_epochs = cull_epochs;
        self.watchpoint_cull_cap = cull_cap;
        self.watchpoint_rearm = rearm;
        self
    }

    /// Enable the hardware data-breakpoint race detector. `len` is the watch
    /// width in bytes (0 = default 4); `oneshot` disarms a slot on its first
    /// conflict. `rip_lo`/`rip_hi` bound the RIP window a candidate must fault
    /// from to be armed (`rip_hi == 0` disables the filter). Only effective
    /// alongside `with_watchpoints` (which supplies the candidate addresses).
    /// See `ApicState::configure_watchpoint_dr`.
    pub fn with_watchpoint_dr(mut self, len: u8, oneshot: bool, rip_lo: u64, rip_hi: u64) -> Self {
        self.watchpoint_dr = true;
        self.watchpoint_dr_len = len;
        self.watchpoint_dr_oneshot = oneshot;
        self.watchpoint_dr_rip_lo = rip_lo;
        self.watchpoint_dr_rip_hi = rip_hi;
        self
    }

    /// The configured category mask as an [`EventCategories`].
    pub fn categories(&self) -> EventCategories {
        EventCategories(self.categories)
    }
}
