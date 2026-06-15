// SPDX-License-Identifier: GPL-2.0

//! I/O channel bash execution.
//!
//! The hypervisor exposes a deterministic guest↔host I/O channel; in
//! combination with the in-guest `bedrock-io.ko` module it lets the lab run a
//! shell command on the guest host or inside a container. This module wraps the
//! wire protocol (defined once in [`bedrock_vm::io_channel`]) in the lab's
//! `BashTarget` / [`BashOutput`] types.

use bedrock_vm::io_channel;

/// Where a [`Branch::bash`](crate::Branch::bash) command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BashTarget {
    /// Run on the guest host (outside any container).
    Host,
    /// Run inside the named container.
    Container(String),
}

impl BashTarget {
    /// Construct a [`BashTarget::Host`].
    pub fn host() -> Self {
        Self::Host
    }

    /// Construct a [`BashTarget::Container`] without typing `.into()`.
    pub fn container(name: impl Into<String>) -> Self {
        Self::Container(name.into())
    }

    /// The container name, or `None` for the host.
    pub(crate) fn container_name(&self) -> Option<&str> {
        match self {
            BashTarget::Host => None,
            BashTarget::Container(name) => Some(name),
        }
    }
}

/// Result of a [`Branch::bash`](crate::Branch::bash) call.
#[derive(Debug, Clone)]
pub struct BashOutput {
    /// Action-level status from the guest module. `0` means the command was
    /// dispatched and run; a negative value is an errno from the module before
    /// the command could run (e.g. a malformed request).
    pub status: i32,
    /// Exit code of the bash command itself.
    pub exit_code: i32,
    /// The command's combined stdout+stderr, captured from the output feedback
    /// buffer — non-empty only when the invocation requested recording. The
    /// output always also streams to the guest journal regardless.
    pub output: Vec<u8>,
}

impl BashOutput {
    /// Returns `true` iff the action dispatched and bash exited with 0.
    pub fn success(&self) -> bool {
        self.status == 0 && self.exit_code == 0
    }

    /// The recorded output as a utf8-lossy string (empty if not recorded).
    pub fn output_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.output)
    }
}

/// Encode a bash request for `target`/`cmd`, optionally recording its output.
pub(crate) fn encode_request(target: &BashTarget, cmd: &str, record_output: bool) -> Vec<u8> {
    io_channel::encode_request(target.container_name(), cmd, record_output)
}
