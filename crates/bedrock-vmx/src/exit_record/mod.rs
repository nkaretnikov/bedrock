// SPDX-License-Identifier: GPL-2.0

//! Exit-record structure for non-determinism diagnosis.
//!
//! [`ExitRecord`] is the payload of an `EventKind::Exit` event: a snapshot of a VM
//! exit capturing the TSC, exit reason and qualification, guest registers,
//! per-device state hashes (APIC, serial, IOAPIC, RTC, MTRR, RDRAND) and a full
//! guest-memory hash. Emitting and draining it is handled by the event stream
//! (see `crate::events`).

mod hash;
mod record;

pub use hash::{hash_guest_memory, StateHash, Xxh64Hasher};
pub use record::{ExitRecord, EXIT_RECORD_FLAG_DETERMINISTIC, EXIT_RECORD_SIZE};
