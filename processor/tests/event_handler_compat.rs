#![allow(deprecated, clippy::unnecessary_wraps)]

use std::sync::Arc;

use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};

struct ExistingHandler;

impl EventHandler for ExistingHandler {
    fn on_event(&self, process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        existing_handler_body(process)
    }
}

fn existing_handler(process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
    existing_handler_body(process)
}

fn existing_handler_body(process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
    let key = process.get_stack_word(0);
    let context = process.ctx();
    let _stack = process.get_stack_state();
    let _memory = process.get_mem_value(context, 0);
    let _advice_stack = process.advice_provider().stack();
    let _mapped_values = process.advice_provider().get_mapped_values(&key);

    Ok(Vec::new())
}

#[test]
fn deprecated_processor_event_interface_accepts_existing_handlers() {
    let custom: Arc<dyn EventHandler> = Arc::new(ExistingHandler);
    let function: Arc<dyn EventHandler> = Arc::new(existing_handler);

    drop((custom, function));
}
