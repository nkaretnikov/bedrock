// SPDX-License-Identifier: GPL-2.0

//! Hardware data-breakpoint race detector (DataCollider-style).
//!
//! The EPT write-watchpoint mechanism fires on every write to a shared page,
//! but a write to a shared page is not a race: a race is a *second* thread
//! touching the *same exact location* with no ordering between the accesses.
//! EPT is page-granular and cannot catch the second accessor without re-trapping
//! every access (the slow path we are trying to avoid). Hardware debug registers
//! can: a data breakpoint on the exact byte/word fires a precise `#DB` only when
//! some access matches, and arming one is a register write with no INVEPT.
//!
//! This module is the pure-logic core: it owns the 4 hardware slots, decides
//! which candidate to watch, computes the `DR7` value the run loop programs, and
//! classifies a `#DB` (read from `DR6`) as a real cross-thread conflict or the
//! owner re-touching its own location. It never touches hardware, so it is fully
//! unit-testable; the run loop (`traits/vm_run.rs`) does the actual `DR0-3`/`DR7`
//! load-and-restore around VMRESUME, keyed off `dr7()` and `slot()`.
//!
//! On one vCPU a race manifests as an interleaving, so the detector is paired
//! with `raise_preempt_vector`: arming a slot also forces a preemption so another
//! thread runs while the breakpoint is live (this creates the interleaving); the
//! `#DB` then confirms the interleaving realized a conflict. RaceBench's own
//! injected-bug manifestation stays the ground-truth oracle.

/// Number of hardware data breakpoints (DR0-DR3). Fixed by the architecture.
pub const NUM_SLOTS: usize = 4;

/// One armed hardware data breakpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrSlot {
    /// Guest linear address being watched (the exact faulting address captured
    /// from the EPT violation, not a page).
    pub gva: u64,
    /// Watch length in bytes: 1, 2, 4, or 8. Must match `gva` alignment.
    pub len: u8,
    /// Thread (guest FS_BASE) that armed this slot. A `#DB` from a *different*
    /// tid is the race signal; the same tid is just the owner re-touching it.
    pub owner_tid: u64,
    /// Watchpoint epoch (observed userspace thread switches) at arm time. Used
    /// to evict the oldest slot when all four are occupied.
    pub arm_epoch: u32,
}

/// Result of arming a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmResult {
    /// Newly armed in the given slot.
    Armed { slot: usize },
    /// Armed in `slot`, evicting the breakpoint that was there.
    Evicted { slot: usize },
    /// `gva` was already watched; nothing changed.
    AlreadyWatched { slot: usize },
}

/// Classification of a `#DB` VM exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbOutcome {
    /// A different thread touched a watched location: a race is realized.
    Conflict {
        slot: usize,
        /// The watched guest linear address (the racing location).
        gva: u64,
        owner_tid: u64,
        tid: u64,
    },
    /// The owner thread re-touched its own watched location: not a race.
    OwnerReaccess { slot: usize },
    /// The `#DB` did not come from any of our slots (guest's own breakpoint, or
    /// a stale/spurious `DR6`); the caller should reflect it to the guest.
    NotOurs,
}

/// The 4-slot data-breakpoint table. The oneshot policy is passed to `on_db` by
/// the caller (it lives in `ApicState` config, inherited by forked VMs), so this
/// table carries no configuration and starts empty in every VM.
pub struct DebugWatch {
    slots: [Option<DrSlot>; NUM_SLOTS],
    /// Round-robin cursor for eviction when all slots are full.
    evict_cursor: usize,
    /// Diagnostic: number of slots evicted while still armed.
    pub evictions: u64,
}

impl Default for DebugWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugWatch {
    pub fn new() -> Self {
        Self {
            slots: [None; NUM_SLOTS],
            evict_cursor: 0,
            evictions: 0,
        }
    }

    /// True when at least one slot is armed (the run loop only swaps hardware DR
    /// state when this holds, so the feature is zero-cost while idle).
    pub fn any_armed(&self) -> bool {
        self.slots.iter().any(|s| s.is_some())
    }

    /// Read-only view of a slot for the run loop's `DR0-3` programming.
    pub fn slot(&self, i: usize) -> Option<DrSlot> {
        self.slots.get(i).copied().flatten()
    }

    /// Arm a data breakpoint on `gva` for `owner_tid`. If `gva` is already
    /// watched, returns that slot unchanged. Otherwise uses a free slot, or
    /// evicts the round-robin-selected slot when all four are occupied.
    pub fn arm(&mut self, gva: u64, len: u8, owner_tid: u64, arm_epoch: u32) -> ArmResult {
        let len = normalize_len(len, gva);
        // Already watching this exact address: keep the existing owner so a later
        // access by a different thread still reads as a conflict.
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(slot) = s {
                if slot.gva == gva {
                    return ArmResult::AlreadyWatched { slot: i };
                }
            }
        }
        let new = DrSlot {
            gva,
            len,
            owner_tid,
            arm_epoch,
        };
        // Prefer a free slot.
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.is_none() {
                *s = Some(new);
                return ArmResult::Armed { slot: i };
            }
        }
        // All full: evict via the round-robin cursor. (Round-robin over the 4
        // hot slots gives every recently-seen shared address a turn without
        // needing a full LRU scan; arm_epoch is retained for observability.)
        let victim = self.evict_cursor % NUM_SLOTS;
        self.evict_cursor = (self.evict_cursor + 1) % NUM_SLOTS;
        self.slots[victim] = Some(new);
        self.evictions += 1;
        ArmResult::Evicted { slot: victim }
    }

    /// Disarm a slot (e.g. after a one-shot conflict, or when its page is culled).
    pub fn disarm(&mut self, slot: usize) {
        if let Some(s) = self.slots.get_mut(slot) {
            *s = None;
        }
    }

    /// Disarm every slot (e.g. on reconfigure). Returns whether anything changed.
    pub fn clear(&mut self) -> bool {
        let was = self.any_armed();
        self.slots = [None; NUM_SLOTS];
        was
    }

    /// Classify a `#DB` given the captured `DR6` and the faulting thread.
    ///
    /// `dr6` bits 0-3 (`B0-B3`) indicate which breakpoint(s) matched. We report
    /// the lowest-numbered matching slot. A CPL-0 fault is never a userspace race
    /// (FS_BASE at CPL 0 is not the thread id), so it is treated as the owner
    /// re-touching (no conflict) but still consumed as ours.
    ///
    /// `oneshot`: when true, a slot is disarmed the moment it reports a conflict
    /// (avoids re-fire storms on a hot shared word); when false the slot stays
    /// armed to catch further conflicts.
    pub fn on_db(&mut self, dr6: u64, tid: u64, cpl: u8, oneshot: bool) -> DbOutcome {
        let fired = (dr6 & 0xF) as usize;
        if fired == 0 {
            return DbOutcome::NotOurs;
        }
        for i in 0..NUM_SLOTS {
            if fired & (1 << i) == 0 {
                continue;
            }
            let Some(slot) = self.slots[i] else {
                // A B-bit set for a slot we do not own: not ours to handle.
                continue;
            };
            if cpl == 3 && tid != slot.owner_tid {
                let owner_tid = slot.owner_tid;
                let gva = slot.gva;
                if oneshot {
                    self.slots[i] = None;
                }
                return DbOutcome::Conflict {
                    slot: i,
                    gva,
                    owner_tid,
                    tid,
                };
            }
            return DbOutcome::OwnerReaccess { slot: i };
        }
        DbOutcome::NotOurs
    }

    /// Compute the `DR7` value that enables exactly the armed slots. Each slot
    /// gets its local-enable bit and a read/write, len encoding. Bit 10 (reserved,
    /// must be 1) is set as the architecture requires.
    pub fn dr7(&self) -> u64 {
        // Bit 10 is reserved and must be written as 1 (Intel SDM Vol 3B 17.2.4).
        let mut dr7: u64 = 1 << 10;
        for (i, s) in self.slots.iter().enumerate() {
            if s.is_none() {
                continue;
            }
            let slot = s.unwrap();
            // Local enable Ln = bit 2*i.
            dr7 |= 1 << (2 * i);
            // R/W and LEN live at bits 16+4*i (R/W) and 18+4*i (LEN).
            // R/W = 0b11 => break on data read or write (catches either side of
            // a conflicting access). LEN per byte width.
            let rw: u64 = 0b11;
            let len_bits: u64 = match slot.len {
                1 => 0b00,
                2 => 0b01,
                8 => 0b10,
                _ => 0b11, // 4 bytes
            };
            dr7 |= rw << (16 + 4 * i);
            dr7 |= len_bits << (18 + 4 * i);
        }
        dr7
    }
}

/// Clamp a watch length to a legal value (1/2/4/8) and to `gva` alignment. A
/// data breakpoint address must be aligned to its length, so an unaligned
/// candidate is narrowed to the largest length its address supports.
fn normalize_len(len: u8, gva: u64) -> u8 {
    let mut l = match len {
        1 | 2 | 4 | 8 => len,
        _ => 4,
    };
    while l > 1 && (gva & (u64::from(l) - 1)) != 0 {
        l /= 2;
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arms_into_free_slots_then_evicts() {
        let mut w = DebugWatch::new();
        assert!(!w.any_armed());
        assert_eq!(w.arm(0x1000, 4, 1, 0), ArmResult::Armed { slot: 0 });
        assert_eq!(w.arm(0x2000, 4, 1, 0), ArmResult::Armed { slot: 1 });
        assert_eq!(w.arm(0x3000, 4, 1, 0), ArmResult::Armed { slot: 2 });
        assert_eq!(w.arm(0x4000, 4, 1, 0), ArmResult::Armed { slot: 3 });
        assert!(w.any_armed());
        // Fifth arm evicts (round-robin starts at slot 0).
        assert_eq!(w.arm(0x5000, 4, 1, 1), ArmResult::Evicted { slot: 0 });
        assert_eq!(w.evictions, 1);
        assert_eq!(w.slot(0).unwrap().gva, 0x5000);
    }

    #[test]
    fn dedups_same_address() {
        let mut w = DebugWatch::new();
        assert_eq!(w.arm(0x1000, 4, 7, 0), ArmResult::Armed { slot: 0 });
        // Re-arming the same gva keeps the original owner.
        assert_eq!(
            w.arm(0x1000, 4, 9, 5),
            ArmResult::AlreadyWatched { slot: 0 }
        );
        assert_eq!(w.slot(0).unwrap().owner_tid, 7);
    }

    #[test]
    fn different_thread_write_is_a_conflict() {
        let mut w = DebugWatch::new();
        w.arm(0x1000, 4, /*owner*/ 111, 0);
        // Owner re-touches: not a race.
        assert_eq!(
            w.on_db(0b0001, /*tid*/ 111, 3, true),
            DbOutcome::OwnerReaccess { slot: 0 }
        );
        // Slot still armed after an owner re-access.
        assert!(w.any_armed());
        // A different thread touches it: race.
        assert_eq!(
            w.on_db(0b0001, /*tid*/ 222, 3, true),
            DbOutcome::Conflict {
                slot: 0,
                gva: 0x1000,
                owner_tid: 111,
                tid: 222
            }
        );
        // One-shot: slot disarmed after the conflict.
        assert!(!w.any_armed());
    }

    #[test]
    fn kernel_fault_is_never_a_race() {
        let mut w = DebugWatch::new();
        w.arm(0x1000, 4, 111, 0);
        // Different tid but CPL 0: FS_BASE is not a thread id, so not a race.
        assert_eq!(
            w.on_db(0b0001, 222, /*cpl*/ 0, true),
            DbOutcome::OwnerReaccess { slot: 0 }
        );
        assert!(w.any_armed());
    }

    #[test]
    fn db_for_unowned_slot_is_not_ours() {
        let mut w = DebugWatch::new();
        // Nothing armed: any DR6 is not ours.
        assert_eq!(w.on_db(0b0010, 5, 3, true), DbOutcome::NotOurs);
        // Slot 0 armed, but DR6 reports slot 1 fired: not ours.
        w.arm(0x1000, 4, 111, 0);
        assert_eq!(w.on_db(0b0010, 5, 3, true), DbOutcome::NotOurs);
    }

    #[test]
    fn non_oneshot_keeps_slot_after_conflict() {
        let mut w = DebugWatch::new();
        w.arm(0x1000, 4, 111, 0);
        assert!(matches!(
            w.on_db(0b0001, 222, 3, false),
            DbOutcome::Conflict { .. }
        ));
        // Persistent mode: slot stays armed to catch further conflicts.
        assert!(w.any_armed());
    }

    #[test]
    fn dr7_encodes_enable_rw_and_len() {
        let mut w = DebugWatch::new();
        // No slots: only the reserved bit 10.
        assert_eq!(w.dr7(), 1 << 10);
        w.arm(0x1000, 4, 1, 0); // slot 0, 4-byte
        let dr7 = w.dr7();
        assert_eq!(dr7 & 1, 1); // L0 set
        assert_eq!((dr7 >> 16) & 0b11, 0b11); // R/W0 = read/write
        assert_eq!((dr7 >> 18) & 0b11, 0b11); // LEN0 = 4 bytes
        assert_eq!(dr7 & (1 << 10), 1 << 10); // reserved bit
    }

    #[test]
    fn len_is_clamped_to_alignment() {
        // 4-byte watch on a 2-aligned (not 4-aligned) address narrows to 2.
        assert_eq!(normalize_len(4, 0x1002), 2);
        // 8-byte watch on an odd address narrows to 1.
        assert_eq!(normalize_len(8, 0x1001), 1);
        // Aligned stays.
        assert_eq!(normalize_len(4, 0x1000), 4);
        // Illegal length defaults to 4 (then alignment-clamped).
        assert_eq!(normalize_len(3, 0x1000), 4);
    }
}
