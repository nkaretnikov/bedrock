// SPDX-License-Identifier: GPL-2.0

//! Tests for reconstructing an [`InputRecording`] from event-stream records.
//!
//! These exercise the pure decode path ([`InputRecording::record_event`]) with
//! hand-built event bytes, so they need no VM and run under `cargo test`.

use super::{InputRecording, InputSource, IoInput, RecordedInputSource, RngInput};
use crate::bash::BashTarget;
use crate::time::VirtTime;
use bedrock_vm::events::{
    EventKind, IoChannelPayload, IoChannelPhase, RandomPayload, EVENT_FLAG_DETERMINISTIC,
    EVENT_HEADER_SIZE,
};
use bedrock_vm::io_channel::encode_request;
use bedrock_vm::EventStream;

const FREQ: u64 = 2_995_200_000;

/// Append one TLV record to `buf`, padding to an 8-byte boundary — mirrors the
/// kernel producer's framing (see `bedrock-vm/src/events_tests.rs`).
fn push_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, kind: u16, payload: &[u8]) {
    let before = buf.len();
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&tsc.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes()); // real_tsc — ignored on decode
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(&EVENT_FLAG_DETERMINISTIC.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    assert_eq!(buf.len() - before, EVENT_HEADER_SIZE);
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

fn random_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, value: u64) {
    let p = RandomPayload {
        value,
        source: 0, // RDRAND
        width: 8,
        _pad: [0; 6],
    };
    push_record(buf, seq, tsc, EventKind::Randomness.as_u16(), p.as_bytes());
}

fn io_record(buf: &mut Vec<u8>, seq: u64, tsc: u64, phase: IoChannelPhase, envelope: &[u8]) {
    let meta = IoChannelPayload {
        phase: phase as u8,
        _pad: [0; 7],
        // Source-driven requests are queued fire-ASAP, so the wire `target_tsc`
        // is 0; the header `tsc` is what the recording uses for `at`.
        target_tsc: 0,
    };
    let mut payload = meta.as_bytes().to_vec();
    payload.extend_from_slice(envelope);
    push_record(buf, seq, tsc, EventKind::IoChannel.as_u16(), &payload);
}

/// Drive every record in `buf` through `record_event`, as `drain_events` does.
fn recording_from(buf: &[u8]) -> InputRecording {
    let mut rec = InputRecording::new();
    for record in EventStream::new(buf) {
        rec.record_event(&record, FREQ);
    }
    rec
}

#[test]
fn randomness_events_become_rng_inputs() {
    let mut buf = Vec::new();
    random_record(&mut buf, 0, 1_000, 0xDEAD_BEEF);
    random_record(&mut buf, 1, 2_000, 0x0BAD_F00D);

    let rec = recording_from(&buf);
    assert_eq!(rec.io_inputs().len(), 0);
    assert_eq!(
        rec.rng_inputs(),
        &[
            RngInput {
                at: VirtTime::from_instructions(1_000, FREQ),
                value: 0xDEAD_BEEF,
            },
            RngInput {
                at: VirtTime::from_instructions(2_000, FREQ),
                value: 0x0BAD_F00D,
            },
        ]
    );
}

#[test]
fn io_request_events_become_io_inputs() {
    let mut buf = Vec::new();
    io_record(
        &mut buf,
        0,
        3_000,
        IoChannelPhase::Request,
        &encode_request(None, "echo hi", true),
    );
    io_record(
        &mut buf,
        1,
        4_000,
        IoChannelPhase::Request,
        &encode_request(Some("bitcoind1"), "bitcoin-cli getinfo", false),
    );

    let rec = recording_from(&buf);
    assert_eq!(rec.rng_inputs().len(), 0);
    assert_eq!(
        rec.io_inputs(),
        &[
            IoInput {
                at: VirtTime::from_instructions(3_000, FREQ),
                target: BashTarget::Host,
                command: "echo hi".to_string(),
                record_output: true,
            },
            IoInput {
                at: VirtTime::from_instructions(4_000, FREQ),
                target: BashTarget::container("bitcoind1"),
                command: "bitcoin-cli getinfo".to_string(),
                record_output: false,
            },
        ]
    );
}

#[test]
fn responses_and_other_kinds_are_ignored() {
    let mut buf = Vec::new();
    // An I/O channel *response* carries host-derived output, not an input.
    io_record(
        &mut buf,
        0,
        10,
        IoChannelPhase::Response,
        b"opaque response",
    );
    // A serial line is not an input either.
    push_record(&mut buf, 1, 20, EventKind::Serial.as_u16(), b"hello\n");
    // ...but a request between them still records.
    io_record(
        &mut buf,
        2,
        30,
        IoChannelPhase::Request,
        &encode_request(None, "true", false),
    );

    let rec = recording_from(&buf);
    assert_eq!(rec.rng_inputs().len(), 0);
    assert_eq!(rec.io_inputs().len(), 1);
    assert_eq!(rec.io_inputs()[0].command, "true");
}

#[test]
fn recording_round_trips_through_replay_source() {
    let mut buf = Vec::new();
    random_record(&mut buf, 0, 1_000, 0x11);
    io_record(
        &mut buf,
        1,
        2_000,
        IoChannelPhase::Request,
        &encode_request(None, "first", false),
    );
    random_record(&mut buf, 2, 3_000, 0x22);
    io_record(
        &mut buf,
        3,
        4_000,
        IoChannelPhase::Request,
        &encode_request(None, "second", true),
    );

    let rec = recording_from(&buf);
    let mut source = RecordedInputSource::new(rec);

    // RNG and I/O each replay in capture order, on independent cursors.
    assert_eq!(source.next_rng_u64(), Some(0x11));
    assert_eq!(source.next_rng_u64(), Some(0x22));
    assert_eq!(source.next_rng_u64(), None);

    let first = source.next_io_input().unwrap();
    assert_eq!(first.command, "first");
    assert!(!first.record_output);
    let second = source.next_io_input().unwrap();
    assert_eq!(second.command, "second");
    assert!(second.record_output);
    assert!(source.next_io_input().is_none());
}
