// SPDX-License-Identifier: GPL-2.0

use super::*;

#[test]
fn test_log_entry_size() {
    assert_eq!(core::mem::size_of::<ExitRecord>(), 512);
}
