// SPDX-License-Identifier: GPL-2.0

//! Serial input buffer type passed to the guest's emulated UART.
//!
//! Guest serial *output* is no longer collected through a dedicated buffer —
//! it flows through the unified event stream as `Serial` records (one per
//! line, stamped with the line-start emulated TSC). Only the host->guest
//! *input* path lives here.

/// Serial input buffer passed to the kernel via ioctl.
///
/// Maximum size is SERIAL_INPUT_MAX_SIZE bytes.
#[repr(C)]
pub struct SerialInput {
    /// Length of valid data in buf.
    pub len: u32,
    /// Reserved for alignment.
    pub _reserved: u32,
    /// Input data buffer.
    pub buf: [u8; SERIAL_INPUT_MAX_SIZE],
}

/// Maximum size of serial input buffer.
pub const SERIAL_INPUT_MAX_SIZE: usize = 256;
