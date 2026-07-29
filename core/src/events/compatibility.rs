//! Migration guide and temporary compatibility interface for event handlers.
//!
//! Event-handler interfaces moved from `miden-processor` to `miden-core`. The deprecated methods
//! in this module preserve common existing handler implementations during the transition; they do
//! not reproduce the complete former `ProcessorState` interface.
//!
//! # Imports
//!
//! Existing handlers can migrate from:
//!
//! ```rust,ignore
//! use miden_processor::{
//!     ProcessorState,
//!     advice::AdviceMutation,
//!     event::{EventError, EventHandler},
//! };
//! ```
//!
//! to:
//!
//! ```rust,ignore
//! use miden_core::{
//!     advice::AdviceMutation,
//!     events::{EventContext, EventError, EventHandler},
//! };
//! ```
//!
//! # Accessor changes
//!
//! | Previous accessor | Replacement |
//! | --- | --- |
//! | `get_stack_item(position)` | `stack_item(position)` |
//! | `get_stack_word(start)` | `stack_word(start)` |
//! | `get_stack_state()` | `stack_snapshot()` |
//! | `get_mem_value(context, address)` | `memory_value(address)` |
//! | `get_mem_word(context, address)` | `memory_word(address)` |
//! | `get_mem_state(context)` | `memory_snapshot()` |
//! | `get_mem_addr_range(start, end)` | `memory_range_from_stack(start, end)` |
//! | `advice_provider().stack()` | `advice_stack_snapshot()` |
//! | `advice_provider().map()` | `advice_map()` |
//! | `advice_provider().get_mapped_values(key)` | `advice_map_entry(key)` |
//! | `advice_provider().get_tree_node(...)` | `advice_tree_node(...)` |
//! | `get_stack_item(0)` for the event identity | `event_id()` |
//!
//! New memory accessors always read the active execution context, so handlers no longer obtain or
//! pass a `ContextId`. The compatibility memory methods retain their old parameters but ignore the
//! supplied context and read active-context memory.
//!
//! `stack_snapshot()`, `memory_snapshot()`, and `advice_stack_snapshot()` allocate owned snapshots.
//!
//! # Intentional differences
//!
//! - `clock()` returns `u32` rather than `miden_air::trace::RowIndex`.
//! - The complete concrete `AdviceProvider` interface is not exposed.
//! - Optional deferred-state lookup methods are not preserved.
//! - Execution-options access is reserved for Miden's built-in precompile handlers and hidden from
//!   the public handler documentation.
//!
//! # Example
//!
//! Before:
//!
//! ```rust,ignore
//! fn handle(process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
//!     let event = EventId::from_felt(process.get_stack_item(0));
//!     let context = process.ctx();
//!     let value = process.get_mem_value(context, 0);
//!     let advice = process.advice_provider().get_mapped_values(&process.get_stack_word(1));
//!     // ...
//! }
//! ```
//!
//! After:
//!
//! ```rust,ignore
//! fn handle(context: &EventContext<'_>) -> Result<Vec<AdviceMutation>, EventError> {
//!     let event = context.event_id();
//!     let value = context.memory_value(0);
//!     let advice = context.advice_map_entry(&context.stack_word(1));
//!     // ...
//! }
//! ```

use alloc::vec::Vec;

use super::{EventContext, EventContextProvider, EventError};
use crate::{ContextId, Felt, MemoryAddress, MemoryError, Word, advice::AdviceMap};

impl<'a> EventContext<'a> {
    #[deprecated(note = "use EventContext::stack_item")]
    pub fn get_stack_item(&self, position: usize) -> Felt {
        self.stack_item(position)
    }

    #[deprecated(note = "use EventContext::stack_word")]
    pub fn get_stack_word(&self, start: usize) -> Word {
        self.stack_word(start)
    }

    #[deprecated(note = "use EventContext::stack_snapshot; it returns an allocated snapshot")]
    pub fn get_stack_state(&self) -> Vec<Felt> {
        self.stack_snapshot()
    }

    #[deprecated(note = "new handlers do not need an execution context identifier")]
    pub fn ctx(&self) -> ContextId {
        self.compatibility_context_id
    }

    #[deprecated(note = "use EventContext::memory_value; it reads active-context memory")]
    pub fn get_mem_value(&self, _context: ContextId, address: u32) -> Option<Felt> {
        self.memory_value(address)
    }

    #[deprecated(note = "use EventContext::memory_word; it reads active-context memory")]
    pub fn get_mem_word(
        &self,
        _context: ContextId,
        address: u32,
    ) -> Result<Option<Word>, MemoryError> {
        self.memory_word(address)
    }

    #[deprecated(
        note = "use EventContext::memory_snapshot; it returns an allocated active-context snapshot"
    )]
    pub fn get_mem_state(&self, _context: ContextId) -> Vec<(MemoryAddress, Felt)> {
        self.memory_snapshot()
    }

    #[deprecated(note = "use EventContext::memory_range_from_stack")]
    pub fn get_mem_addr_range(
        &self,
        start_position: usize,
        end_position: usize,
    ) -> Result<core::ops::Range<u32>, MemoryError> {
        self.memory_range_from_stack(start_position, end_position)
    }

    #[allow(deprecated)]
    #[deprecated(note = "use EventContext advice accessors directly")]
    pub fn advice_provider(&self) -> AdviceProviderView<'a> {
        AdviceProviderView { provider: self.provider }
    }
}

/// Temporary read-only compatibility view for handlers that accessed the advice provider directly.
#[deprecated(note = "use EventContext advice accessors directly")]
pub struct AdviceProviderView<'a> {
    provider: &'a dyn EventContextProvider,
}

#[allow(deprecated)]
impl<'a> AdviceProviderView<'a> {
    /// Returns an allocated snapshot of the advice stack.
    pub fn stack(&self) -> Vec<Felt> {
        self.provider.advice_stack_snapshot()
    }

    pub fn map(&self) -> &'a AdviceMap {
        self.provider.advice_map()
    }

    pub fn get_mapped_values(&self, key: &Word) -> Option<&'a [Felt]> {
        self.provider.advice_map_entry(key)
    }

    pub fn get_tree_node(&self, root: Word, depth: Felt, index: Felt) -> Result<Word, EventError> {
        self.provider.advice_tree_node(root, depth, index)
    }
}
