// SPDX-License-Identifier: GPL-2.0

//! Unified event stream: a single time-ordered, userspace-configurable log that
//! merges serial output, injected interrupts, served randomness, I/O channel
//! transactions, and exit records into one TLV byte stream.
//!
//! This module holds the **wire-format types**, defined once so the producer
//! (the hypervisor core, in both the kernel-module and `cargo` builds) and the
//! userspace reader share one layout — no "must match the kernel exactly"
//! duplicate. The userspace **reader** (TLV iterator + JSON output) lives in the
//! `bedrock-vm` crate (`bedrock_vm::events`), which has `std`; this crate is
//! `#![no_std]`.
//!
//! The `zerocopy`/`serde` derives on these types are `cfg`-gated to the `cargo`
//! feature so the kernel build (Rust-for-Linux Kbuild, `core`/`alloc`/`kernel`
//! only) never sees a crates.io dependency.

mod types;

pub use types::{
    align_up, EventCategories, EventHeader, EventKind, InjectPayload, InjectSource,
    IoChannelPayload, IoChannelPhase, RandomPayload, RandomSource, EVENT_BUFFER_PAGES,
    EVENT_BUFFER_SIZE, EVENT_FLAG_DETERMINISTIC, EVENT_HEADER_SIZE,
};
