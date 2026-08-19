//! PVM-owned 32-row BlakeG compression core.
//!
//! This module intentionally owns its layout, constraints, selectors, lookup plan, and trace
//! writer. It shares the BlakeG primitive and the fixed byte-pair table semantics with the Miden
//! VM, but it does not import the Miden VM's compression AIR or trace layout.

mod algebra;
pub(crate) mod constraints;
#[cfg(test)]
mod constraints_tests;
pub(crate) mod layout;
mod lookup;
mod model;
mod periodic;
mod schedule;
pub(crate) mod selectors;
pub(crate) mod trace;

pub(crate) use lookup::{
    BLAKEG_LOOKUP_COLUMN_SHAPE, BlakeGCompressionCols, BlakeGCompressionLookupBuilder,
    emit_lookup_columns,
};
pub(crate) use periodic::{NUM_PERIODIC_COLUMNS, get_periodic_column_values};
