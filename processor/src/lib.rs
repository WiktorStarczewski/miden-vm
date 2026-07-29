#![no_std]
// Trace tests intentionally use index-based `for i in a..b` over column slices; clippy's iterator
// suggestion is noisier than helpful there.
#![cfg_attr(test, allow(clippy::needless_range_loop))]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::ops::ControlFlow;

use miden_mast_package::debug_info::DebugSourceNodeId;

mod continuation_stack;
mod errors;
mod execution;
mod execution_options;
mod fast;
mod host;
mod processor;
mod tracer;

use miden_core::mast::ExecutableMastForest;

use crate::{
    advice::{AdviceInputs, AdviceProvider},
    continuation_stack::ContinuationStack,
    errors::{MapExecErr, MapExecErrNoCtx},
    trace::RowIndex,
};

#[cfg(any(test, feature = "testing"))]
mod test_utils;
#[cfg(any(test, feature = "testing"))]
pub use test_utils::{ProcessorStateSnapshot, TestHost};

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

pub use continuation_stack::Continuation;
pub use errors::{
    AceError, ExecutionError, HostError, PackageSourceDebugContext,
    advice_error_with_package_source_context, event_error_with_package_source_context,
    procedure_not_found_with_package_source_context,
};
pub use execution_options::{ExecutionOptions, ExecutionOptionsError};
pub use fast::{BreakReason, ExecutionOutput, FastProcessor, ResumeContext};
pub use host::{
    BaseHost, FutureMaybeSend, Host, LoadedMastForest, MastForestStore, MemMastForestStore,
    SyncHost,
    default::{DefaultHost, HostLibrary},
};
pub use miden_core::{
    ContextId, EMPTY_WORD, Felt, MemoryAddress, MemoryError, ONE, WORD_SIZE, Word, ZERO, crypto,
    events::debug::{StdoutWriter, format_value, write_interval, write_stack},
    field, mast,
    program::{
        InputError, KernelDescriptor, MIN_STACK_DEPTH, Program, ProgramInfo, StackInputs,
        StackOutputs,
    },
    serde, utils,
};
pub use trace::{TraceBuildInputs, TraceGenerationContext};

pub mod advice {
    pub use miden_core::advice::{
        AdviceInputs, AdviceMap, AdviceMutation, AdviceStack, MAX_ADVICE_STACK_SIZE,
    };

    pub use super::host::advice::{AdviceError, AdviceProvider};
}

pub mod event {
    pub use miden_core::events::{
        AdviceProviderView, EventContext, EventContextProvider, EventError, EventHandler, EventId,
        EventName, ExecutionOptionsView, NoopEventHandler, SystemEvent, debug,
    };

    pub use crate::host::handlers::EventHandlerRegistry;
}

/// Compatibility alias for the event context exposed to host callbacks.
pub type ProcessorState<'a> = miden_core::events::EventContext<'a>;

pub mod operation {
    pub use miden_core::operations::*;

    pub use crate::errors::{BinaryValueErrorContext, OperationError};
}

pub mod trace;

// EXECUTORS
// ================================================================================================

/// Executes the provided program against the provided inputs and returns the resulting execution
/// output.
///
/// The `host` parameter is used to provide the external environment to the program being executed,
/// such as access to the advice provider and libraries that the program depends on.
///
/// # Errors
/// Returns an error if program execution fails for any reason.
#[tracing::instrument("execute_program", skip_all)]
pub async fn execute(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ExecutionOptions,
) -> Result<ExecutionOutput, ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
        .map_exec_err_no_ctx()?;
    processor.execute(program, host).await
}

/// Synchronous wrapper for the async `execute()` function.
///
/// This method is only available on non-wasm32 targets. On wasm32, use the async `execute()`
/// method directly since wasm32 runs in the browser's event loop.
///
/// # Panics
/// Panics if called from within an existing Tokio runtime. Use the async `execute()` method
/// instead in async contexts.
#[cfg(not(target_family = "wasm"))]
#[tracing::instrument("execute_program_sync", skip_all)]
pub fn execute_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    options: ExecutionOptions,
) -> Result<ExecutionOutput, ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
        .map_exec_err_no_ctx()?;
    processor.execute_sync(program, host)
}

// STOPPER
// ===============================================================================================

/// A trait for types that determine whether execution should be stopped after each clock cycle.
///
/// This allows for flexible control over the execution process, enabling features such as stepping
/// through execution (see [`crate::FastProcessor::step`]) or limiting execution to a certain number
/// of clock cycles (used in parallel trace generation to fill the trace for a predetermined trace
/// fragment).
pub trait Stopper {
    type Processor;

    /// The forest representation used by the executor this stopper is paired with.
    ///
    /// For live execution this is `Arc<MastForest>`; for replay it is `Arc<SparseMastForest>`.
    type Forest: ExecutableMastForest + Clone;

    /// Determines whether execution should be stopped at the end of each clock cycle.
    ///
    /// This method is guaranteed to be called at the end of each clock cycle, *after* the processor
    /// state has been updated to reflect the effects of the operations executed during that cycle
    /// (*including* the processor clock). Hence, a processor clock of `N` indicates that clock
    /// cycle `N - 1` has just completed.
    ///
    /// The `continuation_after_stop` is provided in cases where simply resuming execution from the
    /// top of the continuation stack is not sufficient to continue execution correctly. For
    /// example, when stopping execution in the middle of a basic block, we need to provide a
    /// `ResumeBasicBlock` continuation to ensure that execution resumes at the correct operation
    /// within the basic block (i.e. the operation right after the one that was last executed before
    /// being stopped). No continuation is provided in case of error, since it is expected that
    /// execution will not be resumed.
    fn should_stop(
        &self,
        processor: &Self::Processor,
        continuation_stack: &ContinuationStack<Self::Forest>,
        continuation_after_stop: impl FnOnce() -> Option<(
            Continuation<Self::Forest>,
            Option<DebugSourceNodeId>,
        )>,
    ) -> ControlFlow<BreakReason<Self::Forest>>;
}

// HELPERS
// ===============================================================================================

/// Lifts an [`Option<T>`] into a [`ControlFlow`] suitable for the execution loop, mapping `None`
/// to a break carrying an [`ExecutionError::Internal`] with `err_msg`.
///
/// Intended for use with `?` at sites where a `None` represents a violated internal invariant —
/// most commonly a missing node returned by
/// [`ExecutableMastForest::get_node_by_id`](miden_core::mast::ExecutableMastForest::get_node_by_id).
/// For functions returning `ControlFlow<InternalBreakReason<F>>`, chain
/// `.map_break(InternalBreakReason::from)` before `?`.
#[track_caller]
fn option_map_break_reason<F, T>(
    opt: Option<T>,
    err_msg: &'static str,
) -> ControlFlow<BreakReason<F>, T> {
    match opt {
        Some(value) => ControlFlow::Continue(value),
        None => ControlFlow::Break(BreakReason::Err(ExecutionError::Internal(err_msg))),
    }
}
