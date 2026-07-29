use alloc::string::String;
use core::fmt::{self, Display, LowerHex};

use miden_utils_diagnostics::{Diagnostic, miette};

use crate::Felt;

mod options;
pub use options::{ExecutionOptions, ExecutionOptionsError};

/// The minimum length of an execution trace required to support range checks.
pub const MIN_TRACE_LEN: usize = 64;

/// Identifies an execution context.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContextId(u32);

impl ContextId {
    pub const fn root() -> Self {
        Self(0)
    }

    pub const fn is_root(&self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for ContextId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ContextId> for u32 {
    fn from(context_id: ContextId) -> Self {
        context_id.0
    }
}

impl From<ContextId> for u64 {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl From<ContextId> for Felt {
    fn from(context_id: ContextId) -> Self {
        Felt::from_u32(context_id.0)
    }
}

impl Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies a memory address.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct MemoryAddress(u32);

impl MemoryAddress {
    pub const fn new(address: u32) -> Self {
        Self(address)
    }
}

impl From<u32> for MemoryAddress {
    fn from(address: u32) -> Self {
        Self(address)
    }
}

impl From<MemoryAddress> for u32 {
    fn from(address: MemoryAddress) -> Self {
        address.0
    }
}

impl Display for MemoryAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl LowerHex for MemoryAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl core::ops::Add<MemoryAddress> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: MemoryAddress) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Add<u32> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// Lightweight error type for memory operations.
///
/// This enum captures error conditions without expensive source context. Execution engines can add
/// source context when converting it into their top-level execution error.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum MemoryError {
    #[error("memory address cannot exceed 2^32 but was {addr}")]
    AddressOutOfBounds { addr: u64 },
    #[error(
        "memory address {addr} in context {ctx} was read and written, or written twice, in the same clock cycle {clk}"
    )]
    IllegalMemoryAccess { ctx: ContextId, addr: u32, clk: Felt },
    #[error(
        "memory range start address cannot exceed end address, but was ({start_addr}, {end_addr})"
    )]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error(
        "word access at memory address {addr} in context {ctx} is unaligned: word accesses require addresses that are multiples of 4"
    )]
    UnalignedWordAccess { addr: u32, ctx: ContextId },
    #[error("failed to read from memory: {0}")]
    MemoryReadFailed(String),
    #[error(
        "writing to memory address {addr} in context {ctx} would exceed the maximum number of memory elements {max}"
    )]
    #[diagnostic(help(
        "increase the limit via `ExecutionOptions::with_max_memory_elements`, or reduce the number of distinct memory addresses the program writes to"
    ))]
    MemoryElementLimitExceeded { ctx: ContextId, addr: u32, max: usize },
}
