//! Transcript chiplets.
//!
//! The commitment machinery that content-addresses the precompile
//! transcript DAG. The [`nodes`] registry pins the protocol's node
//! tags; the [`eidos`] source module now contains the transcript's native 32-row
//! [`BlakeGCompressionAir`](eidos::BlakeGCompressionAir), which implements Eidos framing while
//! retaining the established input/output relation topology. The [`chunk`](crate::hash::chunk)
//! chiplet drives it to content-commit hasher inputs; the [`eval`] chiplet folds truthy bindings
//! into the public transcript root.
//! Uint / group leaf + eval arms join as the language grows.

pub mod binding;
pub mod eidos;
pub mod eval;
pub mod nodes;
