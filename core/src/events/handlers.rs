use alloc::{boxed::Box, vec::Vec};
use core::{error::Error, fmt};

use crate::{
    Felt, Word,
    advice::{AdviceMap, AdviceMutation},
    deferred::{Digest, Node, PrecompileError},
    execution::{ContextId, MemoryAddress, MemoryError},
};

/// A generic error returned by an [`EventHandler`].
pub type EventError = Box<dyn Error + Send + Sync + 'static>;

/// Read-only capabilities an execution engine provides to an [`EventContext`].
///
/// This interface is intended for execution-engine adapters. Event handlers should use
/// [`EventContext`] instead of depending on a concrete adapter.
pub trait EventContextProvider {
    fn get_stack_item(&self, position: usize) -> Felt;

    fn get_stack_word(&self, start: usize) -> Word;

    fn get_stack_state(&self) -> Vec<Felt>;

    fn clock(&self) -> u32;

    fn context_id(&self) -> ContextId;

    fn get_mem_value(&self, context: ContextId, address: u32) -> Option<Felt>;

    fn get_mem_word(&self, context: ContextId, address: u32) -> Result<Option<Word>, MemoryError>;

    fn get_mem_state(&self, context: ContextId) -> Vec<(MemoryAddress, Felt)>;

    fn advice_stack(&self) -> Vec<Felt>;

    fn advice_map(&self) -> &AdviceMap;

    fn get_advice_map_entry(&self, key: &Word) -> Option<&[Felt]>;

    fn get_advice_tree_node(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<Word, EventError>;

    fn max_hash_len_bytes(&self) -> usize;

    fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError>;
}

/// A read-only view of execution state exposed to an [`EventHandler`].
///
/// The context exposes capabilities required by handlers without revealing the execution engine's
/// concrete processor state.
pub struct EventContext<'a> {
    provider: &'a dyn EventContextProvider,
}

impl fmt::Debug for EventContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventContext").finish_non_exhaustive()
    }
}

impl<'a> EventContext<'a> {
    pub fn new(provider: &'a dyn EventContextProvider) -> Self {
        Self { provider }
    }

    pub fn get_stack_item(&self, position: usize) -> Felt {
        self.provider.get_stack_item(position)
    }

    pub fn get_stack_word(&self, start: usize) -> Word {
        self.provider.get_stack_word(start)
    }

    pub fn get_stack_state(&self) -> Vec<Felt> {
        self.provider.get_stack_state()
    }

    pub fn clock(&self) -> u32 {
        self.provider.clock()
    }

    pub fn ctx(&self) -> ContextId {
        self.provider.context_id()
    }

    pub fn get_mem_value(&self, context: ContextId, address: u32) -> Option<Felt> {
        self.provider.get_mem_value(context, address)
    }

    pub fn get_mem_word(
        &self,
        context: ContextId,
        address: u32,
    ) -> Result<Option<Word>, MemoryError> {
        self.provider.get_mem_word(context, address)
    }

    pub fn get_mem_state(&self, context: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.provider.get_mem_state(context)
    }

    pub fn get_mem_addr_range(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, MemoryError> {
        let start_addr = self.get_stack_item(start_position).as_canonical_u64();
        let end_addr = self.get_stack_item(end_position).as_canonical_u64();

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

    pub fn advice_stack(&self) -> Vec<Felt> {
        self.provider.advice_stack()
    }

    pub fn advice_map(&self) -> &AdviceMap {
        self.provider.advice_map()
    }

    pub fn get_advice_map_entry(&self, key: &Word) -> Option<&[Felt]> {
        self.provider.get_advice_map_entry(key)
    }

    pub fn get_advice_tree_node(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<Word, EventError> {
        self.provider.get_advice_tree_node(root, depth, index)
    }

    pub fn max_hash_len_bytes(&self) -> usize {
        self.provider.max_hash_len_bytes()
    }

    pub fn require_canonical_deferred_node(
        &self,
        digest: Digest,
    ) -> Result<(Digest, &Node), PrecompileError> {
        self.provider.require_canonical_deferred_node(digest)
    }

    /// Returns a compatibility view of the advice provider.
    #[deprecated(note = "use EventContext advice accessors directly")]
    pub fn advice_provider(&self) -> AdviceProviderView<'a> {
        AdviceProviderView { provider: self.provider }
    }

    /// Returns a compatibility view of execution options used by event handlers.
    #[deprecated(note = "use EventContext::max_hash_len_bytes")]
    pub fn execution_options(&self) -> ExecutionOptionsView<'a> {
        ExecutionOptionsView { provider: self.provider }
    }
}

/// Temporary read-only compatibility view for handlers that access the advice provider directly.
pub struct AdviceProviderView<'a> {
    provider: &'a dyn EventContextProvider,
}

impl<'a> AdviceProviderView<'a> {
    pub fn stack(&self) -> Vec<Felt> {
        self.provider.advice_stack()
    }

    pub fn map(&self) -> &'a AdviceMap {
        self.provider.advice_map()
    }

    pub fn get_mapped_values(&self, key: &Word) -> Option<&'a [Felt]> {
        self.provider.get_advice_map_entry(key)
    }

    pub fn get_tree_node(&self, root: Word, depth: Felt, index: Felt) -> Result<Word, EventError> {
        self.provider.get_advice_tree_node(root, depth, index)
    }
}

/// Temporary compatibility view for execution limits used by event handlers.
pub struct ExecutionOptionsView<'a> {
    provider: &'a dyn EventContextProvider,
}

impl ExecutionOptionsView<'_> {
    pub fn max_hash_len_bytes(&self) -> usize {
        self.provider.max_hash_len_bytes()
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
