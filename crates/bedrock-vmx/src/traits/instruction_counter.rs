// SPDX-License-Identifier: GPL-2.0

//! Instruction counter trait for deterministic guest execution.
//!
//! Backed by a hardware PMU counter in kernel builds. On VM entry/exit the CPU
//! swaps `IA32_PERF_GLOBAL_CTRL` automatically via VMCS controls, and the
//! counter value itself is saved/restored through VMCS MSR lists, so the count
//! reflects guest execution. The trait abstracts the implementation so the VM
//! run loop can be tested without hardware.

/// Error while preparing or restoring an instruction counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionCounterError {
    /// The host does not expose the PMU MSRs required by the counter.
    Unavailable,
    /// The counter could not program the host PMU.
    ProgramFailed,
    /// The counter could not restore the host PMU state.
    RestoreFailed,
}

/// Trait for counting guest instructions retired.
///
/// `prepare` is called once before the VM run loop starts (with preemption
/// disabled, on the CPU the loop will run on) and `finish` once after it
/// exits. `read` returns the current guest-instruction count and may be
/// called from inside the loop after each VM exit.
pub trait InstructionCounter {
    /// Prepare host PMU state for counting.
    ///
    /// Implementations may program PMU MSRs (e.g. `IA32_PERFEVTSEL0`) and
    /// reset the underlying counter. Must be called with preemption disabled.
    #[inline]
    fn prepare(&mut self) -> Result<(), InstructionCounterError> {
        Ok(())
    }

    /// Restore host PMU state.
    ///
    /// Called once after the VM run loop exits, on the same CPU as `prepare`.
    #[inline]
    fn finish(&mut self) -> Result<(), InstructionCounterError> {
        Ok(())
    }

    /// Read the current guest instruction count.
    fn read(&self) -> u64;

    /// Whether this counter is hardware-backed (`false` for the null impl).
    fn is_configured(&self) -> bool;

    /// `IA32_PERF_GLOBAL_CTRL` values for VMCS hardware-assisted switching.
    ///
    /// Returns `Some((guest_val, host_val))` when the counter wants the CPU
    /// to atomically swap the MSR on VM entry/exit; `None` for null counters.
    /// Only valid after `prepare` has been called.
    fn perf_global_ctrl_values(&self) -> Option<(u64, u64)>;

    /// Physical address of the 16-byte VMCS MSR-store entry used on VM exit.
    ///
    /// The CPU saves the counter's canonical read MSR into this entry. Returns
    /// `None` for implementations that don't need VMCS auto-save/load.
    #[inline]
    fn msr_exit_store_entry_phys(&self) -> Option<u64> {
        None
    }

    /// Physical address of the 16-byte VMCS MSR-load entry used on VM entry.
    ///
    /// This may differ from the exit-store entry when the architecture uses a
    /// separate full-width write alias. The implementation must keep its value
    /// synchronized with the most recent exit-store value.
    #[inline]
    fn msr_entry_load_entry_phys(&self) -> Option<u64> {
        None
    }
}

/// Null implementation for VMs without instruction counting.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullInstructionCounter;

impl InstructionCounter for NullInstructionCounter {
    #[inline]
    fn read(&self) -> u64 {
        0
    }

    #[inline]
    fn is_configured(&self) -> bool {
        false
    }

    #[inline]
    fn perf_global_ctrl_values(&self) -> Option<(u64, u64)> {
        None
    }
}

#[cfg(test)]
#[path = "instruction_counter_tests.rs"]
mod tests;
