use alloc::{boxed::Box, vec::Vec};
use core::{error::Error, fmt};

use super::EventId;
use crate::{
    ContextId, ExecutionOptions, Felt, MemoryAddress, MemoryError, Word,
    advice::{AdviceMap, AdviceMutation},
    deferred::{Digest, Node, PrecompileError},
};

/// A generic error returned by an [`EventHandler`].
pub type EventError = Box<dyn Error + Send + Sync + 'static>;

/// Read-only capabilities an execution engine provides to an [`EventContext`].
///
/// This interface is intended for execution-engine adapters. Event handlers should use
/// [`EventContext`] instead of depending on a concrete adapter.
pub trait EventContextProvider: Sync {
    fn stack_item(&self, position: usize) -> Felt;

    fn stack_word(&self, start: usize) -> Word;

    fn stack_snapshot(&self) -> Vec<Felt>;

    fn clock(&self) -> u32;

    fn memory_value(&self, address: u32) -> Option<Felt>;

    fn memory_word(&self, address: u32) -> Result<Option<Word>, MemoryError>;

    fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)>;

    fn advice_stack_snapshot(&self) -> Vec<Felt>;

    fn advice_map(&self) -> &AdviceMap;

    fn advice_map_entry(&self, key: &Word) -> Option<&[Felt]>;

    fn advice_tree_node(&self, root: Word, depth: Felt, index: Felt) -> Result<Word, EventError>;

    /// Returns the processor execution options used by built-in precompile handlers.
    #[doc(hidden)]
    fn execution_options(&self) -> &ExecutionOptions;

    fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError>;
}

/// A read-only view of execution state exposed to an [`EventHandler`].
///
/// The context exposes capabilities required by handlers without revealing the execution engine's
/// concrete processor state. Event handlers are trusted host code: they can inspect operand-stack,
/// memory, advice, and deferred-state data, including private witness values.
pub struct EventContext<'a> {
    pub(super) provider: &'a dyn EventContextProvider,
    // Retained only for the deprecated ProcessorState compatibility methods. New handlers always
    // access memory in the active execution context and do not need its identifier.
    pub(super) compatibility_context_id: ContextId,
}

impl fmt::Debug for EventContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventContext").finish_non_exhaustive()
    }
}

impl<'a> EventContext<'a> {
    /// Creates an event context backed by an execution-engine adapter.
    pub fn new(provider: &'a dyn EventContextProvider, context_id: ContextId) -> Self {
        Self {
            provider,
            compatibility_context_id: context_id,
        }
    }

    /// Returns the identifier of the emitted event.
    pub fn event_id(&self) -> EventId {
        EventId::from_felt(self.stack_item(0))
    }

    /// Returns the value at `position` on the operand stack.
    pub fn stack_item(&self, position: usize) -> Felt {
        self.provider.stack_item(position)
    }

    /// Returns the word starting at `start` on the operand stack.
    pub fn stack_word(&self, start: usize) -> Word {
        self.provider.stack_word(start)
    }

    /// Returns an allocated snapshot of the complete operand stack.
    pub fn stack_snapshot(&self) -> Vec<Felt> {
        self.provider.stack_snapshot()
    }

    /// Returns the current clock cycle.
    pub fn clock(&self) -> u32 {
        self.provider.clock()
    }

    /// Returns the value at `address` in the active execution context.
    pub fn memory_value(&self, address: u32) -> Option<Felt> {
        self.provider.memory_value(address)
    }

    /// Returns the word at `address` in the active execution context.
    pub fn memory_word(&self, address: u32) -> Result<Option<Word>, MemoryError> {
        self.provider.memory_word(address)
    }

    /// Returns an allocated snapshot of memory in the active execution context.
    pub fn memory_snapshot(&self) -> Vec<(MemoryAddress, Felt)> {
        self.provider.memory_snapshot()
    }

    /// Reads a half-open memory range from two operand-stack positions.
    pub fn memory_range_from_stack(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, MemoryError> {
        let start_addr = self.stack_item(start_position).as_canonical_u64();
        let end_addr = self.stack_item(end_position).as_canonical_u64();

        if start_addr > u32::MAX as u64 {
            return Err(MemoryError::AddressOutOfBounds { addr: start_addr });
        }
        if end_addr > u32::MAX as u64 {
            return Err(MemoryError::AddressOutOfBounds { addr: end_addr });
        }
        if start_addr > end_addr {
            return Err(MemoryError::InvalidMemoryRange { start_addr, end_addr });
        }

        Ok(start_addr as u32..end_addr as u32)
    }

    /// Returns an allocated snapshot of the complete advice stack.
    pub fn advice_stack_snapshot(&self) -> Vec<Felt> {
        self.provider.advice_stack_snapshot()
    }

    /// Returns the advice map.
    pub fn advice_map(&self) -> &AdviceMap {
        self.provider.advice_map()
    }

    /// Returns the advice-map entry for `key`.
    pub fn advice_map_entry(&self, key: &Word) -> Option<&[Felt]> {
        self.provider.advice_map_entry(key)
    }

    /// Returns an advice Merkle-tree node.
    pub fn advice_tree_node(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<Word, EventError> {
        self.provider.advice_tree_node(root, depth, index)
    }

    /// Returns the processor execution options used by built-in precompile handlers.
    #[doc(hidden)]
    pub fn execution_options(&self) -> &ExecutionOptions {
        self.provider.execution_options()
    }

    pub fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError> {
        self.provider.require_canonical_deferred_node(digest)
    }
}

/// Handles an event emitted by the VM.
pub trait EventHandler: Send + Sync + 'static {
    fn on_event(&self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError>;
}

impl<F> EventHandler for F
where
    F: for<'a> Fn(&EventContext<'a>) -> Result<Vec<AdviceMutation>, EventError>
        + Send
        + Sync
        + 'static,
{
    fn on_event(&self, context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        self(context)
    }
}

/// An event handler that leaves advice unchanged.
pub struct NoopEventHandler;

impl EventHandler for NoopEventHandler {
    fn on_event(&self, _context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}
