// SPDX-License-Identifier: GPL-2.0

//! Hardware debug-register (DR0-DR3, DR6, DR7) access for the data-breakpoint
//! race detector.
//!
//! VMX does not save/restore DR0-3 or DR6 across VM entry/exit (only guest DR7
//! lives in the VMCS), so the run loop must swap them by hand, exactly like the
//! PEBS `IA32_DS_AREA` swap: save the host values, program the guest breakpoints,
//! run, read back which fired (DR6), then restore the host values. KVM does the
//! same in `kvm_load_guest_debug_regs` / `switch_db_regs`.
//!
//! This is real hardware access, so it exists only in the kernel build. Under the
//! `cargo` feature the whole thing is a no-op: `program_guest_drs` returns an
//! empty token, `read_guest_dr6` returns 0, and `restore_host_drs` does nothing,
//! so the run loop and the `#DB` handler compile and run in unit tests with the
//! detector simply inert (DR6 always 0 -> every classified `#DB` is `NotOurs`).

use super::dr_watch::NUM_SLOTS;

/// Saved host DR state to restore after VM exit. Opaque; the run loop only holds
/// it and hands it back to `restore_host_drs`.
#[cfg(all(target_arch = "x86_64", not(feature = "cargo")))]
#[derive(Clone, Copy)]
pub struct HostDrState {
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
}

#[cfg(any(feature = "cargo", not(target_arch = "x86_64")))]
#[derive(Clone, Copy)]
pub struct HostDrState;

/// Save the host DR0-3/DR6/DR7, program hardware DR0-3 from `addrs` (0 = leave a
/// slot's address as-is; it is disabled via DR7 anyway), and clear DR6 so a
/// stale B-bit from a previous run cannot masquerade as this run's hit. Returns
/// the host state for `restore_host_drs`. The caller writes the guest DR7 into
/// the VMCS (`GuestDr7`) separately, since DR7 IS reloaded from the VMCS on entry.
#[cfg(all(target_arch = "x86_64", not(feature = "cargo")))]
pub fn program_guest_drs(addrs: &[u64; NUM_SLOTS]) -> HostDrState {
    // SAFETY: MOV to/from DR is valid at CPL 0 (the run loop runs in the kernel
    // with preemption and interrupts disabled). Reading and writing DRs has no
    // memory effects; each `mov` touches one debug register.
    unsafe {
        let (dr0, dr1, dr2, dr3, dr6, dr7): (u64, u64, u64, u64, u64, u64);
        core::arch::asm!("mov {}, dr0", out(reg) dr0, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr1", out(reg) dr1, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr2", out(reg) dr2, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr3", out(reg) dr3, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, dr7", out(reg) dr7, options(nostack, preserves_flags));
        let saved = HostDrState {
            dr0,
            dr1,
            dr2,
            dr3,
            dr6,
            dr7,
        };
        // Program the guest breakpoint addresses.
        core::arch::asm!("mov dr0, {}", in(reg) addrs[0], options(nostack, preserves_flags));
        core::arch::asm!("mov dr1, {}", in(reg) addrs[1], options(nostack, preserves_flags));
        core::arch::asm!("mov dr2, {}", in(reg) addrs[2], options(nostack, preserves_flags));
        core::arch::asm!("mov dr3, {}", in(reg) addrs[3], options(nostack, preserves_flags));
        // Clear DR6 (write-1-to-clear does not apply: DR6 is written directly).
        core::arch::asm!("mov dr6, {}", in(reg) 0u64, options(nostack, preserves_flags));
        saved
    }
}

/// Read hardware DR6 after VM exit: bits 0-3 (`B0-B3`) say which breakpoints
/// fired during guest execution.
#[cfg(all(target_arch = "x86_64", not(feature = "cargo")))]
pub fn read_guest_dr6() -> u64 {
    // SAFETY: reading DR6 at CPL 0 has no side effects.
    unsafe {
        let dr6: u64;
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nostack, preserves_flags));
        dr6
    }
}

/// Restore the host DR state saved by `program_guest_drs`. DR7 is written last so
/// the host's breakpoints are only re-enabled once DR0-3 hold the host values.
#[cfg(all(target_arch = "x86_64", not(feature = "cargo")))]
pub fn restore_host_drs(s: &HostDrState) {
    // SAFETY: MOV to DR is valid at CPL 0; restoring the previously-read host
    // values leaves the host debug facility exactly as it was.
    unsafe {
        core::arch::asm!("mov dr0, {}", in(reg) s.dr0, options(nostack, preserves_flags));
        core::arch::asm!("mov dr1, {}", in(reg) s.dr1, options(nostack, preserves_flags));
        core::arch::asm!("mov dr2, {}", in(reg) s.dr2, options(nostack, preserves_flags));
        core::arch::asm!("mov dr3, {}", in(reg) s.dr3, options(nostack, preserves_flags));
        core::arch::asm!("mov dr6, {}", in(reg) s.dr6, options(nostack, preserves_flags));
        core::arch::asm!("mov dr7, {}", in(reg) s.dr7, options(nostack, preserves_flags));
    }
}

// -----------------------------------------------------------------------------
// Cargo / non-x86 stubs: the detector is inert (no hardware DRs).
// -----------------------------------------------------------------------------

#[cfg(any(feature = "cargo", not(target_arch = "x86_64")))]
pub fn program_guest_drs(_addrs: &[u64; NUM_SLOTS]) -> HostDrState {
    HostDrState
}

#[cfg(any(feature = "cargo", not(target_arch = "x86_64")))]
pub fn read_guest_dr6() -> u64 {
    0
}

#[cfg(any(feature = "cargo", not(target_arch = "x86_64")))]
pub fn restore_host_drs(_s: &HostDrState) {}
