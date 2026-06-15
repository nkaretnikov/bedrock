// SPDX-License-Identifier: GPL-2.0

//! Event sink — how lab consumers observe what's happening inside the tree.
//!
//! Every tree owns a single [`EventSink`]. Branches forward serial output
//! (one event per complete line), branch creation, and checkpoint creation
//! to the sink so the consumer can persist, stream, or discard the data
//! however it likes (BigQuery, a local database, stdout, or `/dev/null`).

use bedrock_vm::events::EventKind;
use bedrock_vm::{EventRecord, EventStream, Vm};

use crate::branch::BranchId;
use crate::checkpoint::CheckpointId;
use crate::error::Result;
use crate::time::VirtTime;

/// An observable event in the lab's execution tree.
///
/// `#[non_exhaustive]` so new variants can be added without breaking sinks.
#[non_exhaustive]
#[derive(Debug)]
pub enum Event<'a> {
    /// One complete line of serial output from a branch's guest.
    ///
    /// `line` is the bytes between line starts (trailing `\n` stripped) and
    /// borrows from a per-branch buffer for the duration of the `on_event`
    /// call — copy out if the sink needs to retain it. `at` is the emulated
    /// TSC at which the *first* byte of this line was written (carried
    /// across `vm.run()` drains and across `Checkpoint::branch` so a line
    /// continued from a parent checkpoint keeps its original start time).
    ///
    /// Partial lines pending at branch drop are silently discarded;
    /// partial lines pending at `Branch::checkpoint` are propagated into
    /// the new checkpoint so descendant branches glue onto the same line.
    /// [`BranchId(0)`](crate::BranchId) is reserved for root-VM boot/setup
    /// output emitted before the ready checkpoint exists.
    SerialLine {
        branch: BranchId,
        at: VirtTime,
        line: &'a [u8],
    },
    /// A new branch was forked from `origin`.
    BranchCreated {
        branch: BranchId,
        origin: CheckpointId,
        at: VirtTime,
    },
    /// A checkpoint was created. `from_branch` is `None` for the root
    /// checkpoint; `parent` is `None` for the root.
    CheckpointCreated {
        checkpoint: CheckpointId,
        from_branch: Option<BranchId>,
        parent: Option<CheckpointId>,
        at: VirtTime,
    },
    /// The guest registered a feedback buffer with identifier `id` of `size`
    /// bytes, assigned to host slot `slot`. Fires once per successful
    /// `HYPERCALL_REGISTER_FEEDBACK_BUFFER` call.
    ///
    /// `id` borrows from a kernel-mapped struct for the duration of the
    /// `on_event` call; copy out if the sink needs to retain it. IDs are
    /// not unique — two registrations with the same `id` represent two
    /// instances of the same domain (e.g. two processes running the same
    /// binary). Read the buffers on the originating branch via
    /// [`Branch::feedback_buffers`](crate::Branch::feedback_buffers);
    /// descendant branches inherit the registration through CoW.
    /// [`BranchId(0)`](crate::BranchId) is reserved for registrations that
    /// occur during root-VM boot/setup before the ready checkpoint exists.
    FeedbackBufferRegistered {
        branch: BranchId,
        at: VirtTime,
        id: &'a [u8],
        slot: usize,
        size: u64,
    },
    /// One record drained from the branch's unified event stream — an exit
    /// snapshot, served randomness, an injected interrupt, an I/O-channel
    /// transaction, etc. Fires once per record for branches that have enabled
    /// the stream via [`Branch::set_event_config`](crate::Branch::set_event_config).
    ///
    /// Inspect the kind/payload with [`record.event()`](bedrock_vm::EventRecord::event)
    /// or serialize it with [`record.to_json()`](bedrock_vm::EventRecord::to_json).
    /// `record` borrows from the kernel-mapped event buffer for the duration of
    /// the `on_event` call — copy out if the sink needs to retain it.
    Record {
        branch: BranchId,
        record: EventRecord<'a>,
    },
}

/// Receives every [`Event`] produced by the tree.
///
/// Implementations must be cheap and non-blocking; `on_event` runs on the
/// thread driving the branch and any long wait stalls guest execution.
/// Offload heavy work (DB writes, network) to a background worker.
///
/// Internal scratch branches created by
/// [`Checkpoint::rewind`](crate::Checkpoint::rewind) emit events like any
/// other branch — filter on `BranchId` if you only want user-visible work.
pub trait EventSink: Send + Sync {
    fn on_event(&self, event: Event<'_>);
}

/// Default sink used when the caller doesn't supply one — discards everything.
pub(crate) struct Discard;

impl EventSink for Discard {
    fn on_event(&self, _event: Event<'_>) {}
}

/// Per-branch partial-line state. A line that doesn't see its trailing
/// `\n` within one `vm.run()` drain (or within one branch's lifetime
/// before checkpointing) survives here until completion.
#[derive(Default, Clone, Debug)]
pub(crate) struct PartialLine {
    pub(crate) bytes: Vec<u8>,
    /// Emulated TSC at which the first byte of `bytes` was written.
    /// Meaningful only when `bytes.is_empty() == false`.
    pub(crate) start_tsc: u64,
}

/// Feed one `Serial` event record's bytes through the per-branch line
/// reassembler, emitting one [`Event::SerialLine`] per `\n`-terminated line.
///
/// The kernel accumulates a console line and emits it as one `Serial` record
/// stamped with the emulated TSC of its *first* byte, so a fresh line takes the
/// record's TSC as its start time; a line continued from an earlier record (a
/// line longer than the kernel's accumulator, split across records) keeps the
/// earlier start TSC. Bytes not yet terminated by `\n` stay in `partial` until
/// a later record completes them.
pub(crate) fn serial_record_into_sink(
    bytes: &[u8],
    record_tsc: u64,
    freq: u64,
    branch: BranchId,
    sink: &dyn EventSink,
    partial: &mut PartialLine,
) {
    for &byte in bytes {
        if partial.bytes.is_empty() {
            partial.start_tsc = record_tsc;
        }
        if byte == b'\n' {
            let at = VirtTime::from_instructions(partial.start_tsc, freq);
            sink.on_event(Event::SerialLine {
                branch,
                at,
                line: &partial.bytes,
            });
            partial.bytes.clear();
        } else {
            partial.bytes.push(byte);
        }
    }
}

/// Feed every `Serial` record in a drained event buffer through
/// [`serial_record_into_sink`]. Used by the root-boot loop, which has no other
/// per-record handling; a live [`Branch`](crate::Branch) inlines the same call
/// into its single event drain so it can also forward non-serial records.
pub(crate) fn drain_serial_events(
    drained: &[u8],
    freq: u64,
    branch: BranchId,
    sink: &dyn EventSink,
    partial: &mut PartialLine,
) {
    for record in EventStream::new(drained) {
        if record.kind() == EventKind::Serial.as_u16() {
            serial_record_into_sink(record.payload, record.tsc(), freq, branch, sink, partial);
        }
    }
}

/// Read the guest GPRs after a successful `HYPERCALL_REGISTER_FEEDBACK_BUFFER`
/// exit, look up the assigned slot's identifier via the kernel module, and
/// emit an [`Event::FeedbackBufferRegistered`].
///
/// Returns `(slot, size)` for callers that need the registration in their
/// own bookkeeping; `None` if the slot lookup didn't find a registered
/// buffer (only possible if the hypercall actually failed, in which case
/// RAX would be `u64::MAX` and we treat it as "nothing was registered").
pub(crate) fn emit_feedback_buffer_registered(
    vm: &Vm,
    at: VirtTime,
    branch: BranchId,
    sink: &dyn EventSink,
) -> Result<Option<(usize, u64)>> {
    let regs = vm.get_regs()?;
    let rax = regs.gprs.rax;
    if rax == u64::MAX {
        // The hypercall reported failure. No slot to look up.
        return Ok(None);
    }
    let slot = rax as usize;
    let size = regs.gprs.rcx;
    // Pull the id from the slot the hypercall just populated.
    let info = vm.get_feedback_buffer_info_at(slot)?;
    if let Some(info) = info {
        sink.on_event(Event::FeedbackBufferRegistered {
            branch,
            at,
            id: info.id_bytes(),
            slot,
            size,
        });
        Ok(Some((slot, size)))
    } else {
        Ok(None)
    }
}
