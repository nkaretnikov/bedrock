// SPDX-License-Identifier: GPL-2.0

//! Direct MSR-based instruction counter using `IA32_PMC0`.
//!
//! Counts guest instructions retired (`INST_RETIRED.ANY_P`, event 0xC0) on
//! general-purpose counter 0, programmed directly via MSRs. Determinism is
//! achieved by hooking the counter MSR into the VMCS VM-exit MSR-store list
//! and VM-entry MSR-load lists, so:
//!
//! * Each VM entry atomically resets canonical `IA32_PMC0` to zero.
//! * On VM exit, the CPU atomically saves that iteration's delta before any
//!   host code runs.
//! * The host adds each delta to a software `u64` total. Hardware never has
//!   to round-trip a large cumulative value.
//!
//! `IA32_PMC0` is used here (rather than the more obvious `IA32_FIXED_CTR0`)
//! because the precise-VM-exit PEBS facility wants `IA32_FIXED_CTR0` for its
//! own arming (see `exits/pebs.rs`); putting the IC on a GP counter frees the
//! fixed counter for PEBS.
//!
//! Userspace must pin the thread to the desired CPU before creating the VM;
//! on hybrid CPUs that should be a P-core (where general-purpose counter 0
//! supports `INST_RETIRED.ANY_P`).

use super::page::{alloc_zeroed_page, KernelPage};
use crate::c_helpers;
use crate::vmx::traits::{InstructionCounter, InstructionCounterError};
use core::sync::atomic::{AtomicU64, Ordering};

/// Canonical read MSR for general-purpose counter 0.
const IA32_PMC0: u32 = 0xC1;
/// Full-width write alias used to reset general-purpose counter 0 on VM entry.
const IA32_A_PMC0: u32 = 0x4C1;
/// Performance event-select register for `IA32_PMC0`.
const IA32_PERFEVTSEL0: u32 = 0x186;
/// Global enable for performance counters (SDM Vol 4 Table 2-2).
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;

/// `IA32_PERFEVTSEL0` programming for `INST_RETIRED.ANY_P`: event select
/// 0xC0, unit mask 0x00, USR (bit 16), OS (bit 17), EN (bit 22). Counts
/// every retired instruction.
const PERFEVTSEL0_INST_RETIRED_ANY_P: u64 = (1u64 << 16) | (1u64 << 17) | (1u64 << 22) | 0xC0;
/// Bit 0 in `IA32_PERF_GLOBAL_CTRL` enables `IA32_PMC0`.
const PERF_GLOBAL_CTRL_PMC0: u64 = 1;

fn pmc_mask(width: u32) -> Option<u64> {
    match width {
        1..=63 => Some((1u64 << width) - 1),
        64 => Some(u64::MAX),
        _ => None,
    }
}

fn architectural_pmc_mask() -> Option<u64> {
    // CPUID leaf 0xA is architectural. EAX[23:16] reports the GP counter
    // width.
    let eax = core::arch::x86_64::__cpuid(0xA).eax;
    let version = eax & 0xff;
    let counter_count = (eax >> 8) & 0xff;
    let width = (eax >> 16) & 0xff;

    if version == 0 || counter_count == 0 {
        return None;
    }
    pmc_mask(width)
}

/// VMCS MSR-list entry layout (SDM Vol 3C Table 26-16).
#[repr(C)]
struct MsrListEntry {
    msr_index: u32,
    reserved: u32,
    msr_data: u64,
}

#[inline]
fn rdmsr(addr: u32) -> Result<u64, InstructionCounterError> {
    let mut value = 0;
    // SAFETY: `value` is a valid output pointer. The kernel helper catches
    // the #GP raised when the MSR is unavailable.
    let ret = unsafe { c_helpers::bedrock_rdmsr_safe(addr, &mut value) };
    if ret != 0 {
        return Err(InstructionCounterError::Unavailable);
    }
    Ok(value)
}

#[inline]
fn wrmsr(addr: u32, value: u64) -> Result<(), InstructionCounterError> {
    // SAFETY: The kernel helper catches the #GP raised when the MSR or value
    // is unavailable.
    let ret = unsafe { c_helpers::bedrock_wrmsr_safe(addr, value) };
    if ret != 0 {
        return Err(InstructionCounterError::ProgramFailed);
    }
    Ok(())
}

/// Direct MSR-based instruction counter for general-purpose counter 0.
pub(crate) struct LinuxInstructionCounter {
    /// VM-exit store entry for canonical `IA32_PMC0` reads.
    msr_exit_store_page: Option<KernelPage>,
    /// VM-entry load entry that resets `IA32_PMC0` through its write alias.
    msr_entry_load_page: Option<KernelPage>,
    /// Mask for the architectural GP counter width from CPUID leaf 0xA.
    counter_mask: u64,
    /// Cumulative guest instructions from consumed per-entry PMC deltas.
    total: AtomicU64,
    /// Saved `IA32_PERFEVTSEL0`, captured in `prepare`, restored in `finish`.
    saved_perfevtsel0: u64,
    /// Value the CPU loads into `IA32_PERF_GLOBAL_CTRL` on VM entry.
    guest_perf_global_ctrl: u64,
    /// Value the CPU loads into `IA32_PERF_GLOBAL_CTRL` on VM exit.
    host_perf_global_ctrl: u64,
    /// Whether `prepare` has run since the last `finish`.
    armed: bool,
}

// SAFETY: KernelPage is itself Send (its only state is a kernel `Page` and
// physical/virtual addresses). The MSR list entry it backs is accessed only
// while preemption is disabled inside the run loop, on the CPU that owns the
// VMCS, so there is no concurrent access.
unsafe impl Send for LinuxInstructionCounter {}

impl LinuxInstructionCounter {
    pub(crate) fn new() -> Self {
        let counter_mask = architectural_pmc_mask().unwrap_or(0);
        let pages = if counter_mask != 0 {
            alloc_zeroed_page().and_then(|exit_store| {
                alloc_zeroed_page().map(|entry_load| (exit_store, entry_load))
            })
        } else {
            None
        };

        let (msr_exit_store_page, msr_entry_load_page) = match pages {
            Some((exit_store, entry_load)) => {
                // SAFETY: both pages are freshly allocated, zeroed, and not
                // aliased. Only the first 16 bytes hold an MSR-list entry.
                unsafe {
                    core::ptr::write(
                        exit_store.virt.as_u64() as *mut MsrListEntry,
                        MsrListEntry {
                            msr_index: IA32_PMC0,
                            reserved: 0,
                            msr_data: 0,
                        },
                    );
                    core::ptr::write(
                        entry_load.virt.as_u64() as *mut MsrListEntry,
                        MsrListEntry {
                            msr_index: IA32_A_PMC0,
                            reserved: 0,
                            msr_data: 0,
                        },
                    );
                }
                (Some(exit_store), Some(entry_load))
            }
            None => (None, None),
        };

        Self {
            msr_exit_store_page,
            msr_entry_load_page,
            counter_mask,
            total: AtomicU64::new(0),
            saved_perfevtsel0: 0,
            guest_perf_global_ctrl: 0,
            host_perf_global_ctrl: 0,
            armed: false,
        }
    }

    /// Read the MSR-data field of the VMCS list entry. The CPU writes this
    /// atomically on VM exit, so it's the counter value at exit time.
    #[inline]
    fn consume_delta(&self) -> u64 {
        match (
            self.msr_exit_store_page.as_ref(),
            self.msr_entry_load_page.as_ref(),
        ) {
            (Some(exit_store), Some(entry_load)) => {
                // SAFETY: the entry was initialized in `new` and lives as
                // long as `self`. Between exits, no CPU accesses either page.
                // Consume the saved delta exactly once. Clearing the store
                // slot makes repeated reads between VM entries idempotent.
                unsafe {
                    let exit_entry = exit_store.virt.as_u64() as *mut MsrListEntry;
                    let entry_load_entry = entry_load.virt.as_u64() as *mut MsrListEntry;
                    let delta =
                        core::ptr::read_volatile(&(*exit_entry).msr_data) & self.counter_mask;
                    core::ptr::write_volatile(&mut (*exit_entry).msr_data, 0);
                    core::ptr::write_volatile(&mut (*entry_load_entry).msr_data, 0);
                    self.total.fetch_add(delta, Ordering::Relaxed) + delta
                }
            }
            _ => self.total.load(Ordering::Relaxed),
        }
    }
}

impl InstructionCounter for LinuxInstructionCounter {
    fn prepare(&mut self) -> Result<(), InstructionCounterError> {
        if self.msr_exit_store_page.is_none() {
            return Ok(());
        }

        // Compute PERF_GLOBAL_CTRL values for VMCS auto-load. These act as a
        // first-line gate: bit 0 is cleared on host so the counter is disabled
        // outside of guest execution. NMI handlers can still flip this bit,
        // but the VMCS auto-save/load of IA32_PMC0 makes any host-side ticks
        // irrelevant — they're overwritten on the next VM entry.
        let current_global = rdmsr(IA32_PERF_GLOBAL_CTRL)?;
        self.host_perf_global_ctrl = current_global & !PERF_GLOBAL_CTRL_PMC0;
        self.guest_perf_global_ctrl = self.host_perf_global_ctrl | PERF_GLOBAL_CTRL_PMC0;

        // Save the host's IA32_PERFEVTSEL0 and program ours.
        let saved = rdmsr(IA32_PERFEVTSEL0)?;
        self.saved_perfevtsel0 = saved;
        wrmsr(IA32_PERFEVTSEL0, PERFEVTSEL0_INST_RETIRED_ANY_P)?;

        self.armed = true;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), InstructionCounterError> {
        if !self.armed {
            return Ok(());
        }
        // Restore the host's IA32_PERFEVTSEL0. PERF_GLOBAL_CTRL was already
        // loaded by hardware on the most recent VM exit.
        if wrmsr(IA32_PERFEVTSEL0, self.saved_perfevtsel0).is_err() {
            return Err(InstructionCounterError::RestoreFailed);
        }
        self.armed = false;
        Ok(())
    }

    fn read(&self) -> u64 {
        // Each VM exit contributes one hardware delta to the software total.
        // Repeated reads before the next entry return the same cumulative value.
        self.consume_delta()
    }

    fn is_configured(&self) -> bool {
        self.msr_exit_store_page.is_some()
    }

    fn perf_global_ctrl_values(&self) -> Option<(u64, u64)> {
        if self.armed {
            Some((self.guest_perf_global_ctrl, self.host_perf_global_ctrl))
        } else {
            None
        }
    }

    fn msr_exit_store_entry_phys(&self) -> Option<u64> {
        self.msr_exit_store_page.as_ref().map(|p| p.phys.as_u64())
    }

    fn msr_entry_load_entry_phys(&self) -> Option<u64> {
        self.msr_entry_load_page.as_ref().map(|p| p.phys.as_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmc_mask_covers_exact_width() {
        assert_eq!(pmc_mask(0), None);
        assert_eq!(pmc_mask(32), Some(0xffff_ffff));
        assert_eq!(pmc_mask(48), Some(0xffff_ffff_ffff));
        assert_eq!(pmc_mask(64), Some(u64::MAX));
        assert_eq!(pmc_mask(65), None);
    }
}
