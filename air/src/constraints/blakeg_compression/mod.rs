#![allow(
    dead_code,
    reason = "compiled ahead of the atomic MVM cutover; remove this allowance when the AIR is wired"
)]

//! Standalone 32-row BlakeG compression arithmetization.
//!
//! Each cycle contains 28 fused G rows followed by four footer rows. The fused rows execute the
//! seven BlakeG rounds; the footer rows assemble the message, input chaining value, compression
//! output, and XOF output used by the external buses.
//!
//! # Physical-cycle binding
//!
//! Every cycle carries a canonical `compression_cycle_id`: the first cycle is zero, the value is
//! constant over all 32 rows, and it increments between cycles. Every internal message-word and
//! chaining-value binding includes that identity. For the chaining-value bus, the cycle and pair
//! are packed injectively as `4 * compression_cycle_id + pair_index`; message-word slots carry the
//! ID directly. This prevents inputs from one physical compression from satisfying the internal
//! lookups of another.
//!
//! # Integration status
//!
//! This module is deliberately dormant until the atomic MVM cutover wires its constraints,
//! periodic columns, lookup columns, and trace builder into a `BlakeGCompressionAir`. Keeping the
//! module dormant makes this extraction reviewable without changing the active Poseidon2 proof
//! relation.

mod algebra;

pub(crate) mod layout;

#[cfg(test)]
mod layout_tests;

pub(crate) mod lookup;

#[cfg(test)]
mod lookup_tests;

pub(crate) mod constraints;

#[cfg(test)]
mod constraints_tests;

pub(crate) mod model;

#[cfg(test)]
mod model_tests;

pub(crate) mod periodic;

#[cfg(test)]
mod periodic_tests;

pub(crate) mod selectors;

#[cfg(test)]
mod selectors_tests;

pub(crate) mod schedule;

#[cfg(test)]
mod schedule_tests;

pub(crate) mod trace;

#[cfg(test)]
mod trace_tests;

#[cfg(test)]
pub(crate) mod views;

#[cfg(test)]
mod views_tests;

pub use layout::NUM_COLS;
pub use lookup::BlakeGCompressionCols;
pub use trace::{
    BlakeGByteLookup, BlakeGFeltRow, BlakeGFeltTraceBlock, ByteLookupRecorder, TraceMode,
    generate_felt_trace_block, write_felt_trace_block,
    write_felt_trace_block_into_zeroed_with_lookups,
};
