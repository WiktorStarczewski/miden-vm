//! Eidos hash function built on BlakeG compression.
//!
//! Eidos digests occupy a 252-bit packed subspace: the high bit of each odd BlakeG output lane
//! is cleared before two `u32` lanes are packed into one Goldilocks field element. The resulting
//! generic collision-resistance bound is 126 bits.

mod challenger;
mod framing;
mod lmcs;
mod primitive;

/// Reference helpers for the Eidos-based AEAD construction.
///
/// These functions support protocol-vector generation and cross-language conformance tests. They
/// do not manage nonces; callers are responsible for enforcing nonce uniqueness.
pub mod aead_ref;

#[cfg(test)]
mod tests;

pub use challenger::{EidosChallenger, MidenEidosChallenger};
pub use framing::{DIGEST_WIDTH, Eidos, PACKED_LANES, PackedBlock, PackedDigest, PackedFelt, RATE};
pub use lmcs::{EidosLmcs, config as lmcs_config};
