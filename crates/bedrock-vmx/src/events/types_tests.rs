// SPDX-License-Identifier: GPL-2.0

//! Tests for the event-stream wire-format types.

use super::*;

#[test]
fn header_is_32_bytes_no_padding() {
    assert_eq!(core::mem::size_of::<EventHeader>(), 32);
    assert_eq!(core::mem::size_of::<EventHeader>(), EVENT_HEADER_SIZE);
}

#[test]
fn payload_sizes_are_fixed() {
    assert_eq!(core::mem::size_of::<InjectPayload>(), 16);
    assert_eq!(core::mem::size_of::<RandomPayload>(), 16);
    assert_eq!(core::mem::size_of::<IoChannelPayload>(), 16);
}

#[test]
fn align_up_rounds_to_eight() {
    assert_eq!(align_up(0, 8), 0);
    assert_eq!(align_up(1, 8), 8);
    assert_eq!(align_up(8, 8), 8);
    assert_eq!(align_up(9, 8), 16);
    assert_eq!(align_up(32 + 16, 8), 48);
    // Serial line of 13 bytes -> record body padded to 16.
    assert_eq!(align_up(13, 8), 16);
}

#[test]
fn kind_to_category_mapping() {
    assert_eq!(EventKind::Exit.category(), EventCategories::EXIT);
    assert_eq!(EventKind::Serial.category(), EventCategories::SERIAL);
    assert_eq!(EventKind::Inject.category(), EventCategories::INJECT);
    assert_eq!(
        EventKind::Randomness.category(),
        EventCategories::RANDOMNESS
    );
    assert_eq!(EventKind::IoChannel.category(), EventCategories::IO_CHANNEL);
    assert_eq!(
        EventKind::Diagnostic.category(),
        EventCategories::DIAGNOSTIC
    );
}

#[test]
fn default_flags_clear_deterministic_only_for_diagnostic() {
    assert_eq!(EventKind::Serial.default_flags(), EVENT_FLAG_DETERMINISTIC);
    assert_eq!(EventKind::Exit.default_flags(), EVENT_FLAG_DETERMINISTIC);
    assert_eq!(
        EventKind::Randomness.default_flags(),
        EVENT_FLAG_DETERMINISTIC
    );
    assert_eq!(EventKind::Diagnostic.default_flags(), 0);
}

#[test]
fn categories_contains_and_union() {
    let mask = EventCategories::SERIAL.union(EventCategories::RANDOMNESS);
    assert!(mask.contains(EventCategories::SERIAL));
    assert!(mask.contains(EventCategories::RANDOMNESS));
    assert!(!mask.contains(EventCategories::EXIT));
    assert!(!mask.contains(EventCategories::INJECT));
    assert!(EventCategories::empty().0 == 0);
    // contains(empty) is always true.
    assert!(EventCategories::empty().contains(EventCategories::empty()));
}

#[test]
fn kind_as_u16_matches_discriminant() {
    assert_eq!(EventKind::Exit.as_u16(), 0);
    assert_eq!(EventKind::Serial.as_u16(), 1);
    assert_eq!(EventKind::Inject.as_u16(), 2);
    assert_eq!(EventKind::Randomness.as_u16(), 3);
    assert_eq!(EventKind::IoChannel.as_u16(), 4);
    assert_eq!(EventKind::Diagnostic.as_u16(), 5);
}
