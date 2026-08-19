//! Shared expression-level helpers for the BlakeG main and lookup constraints.

use miden_core::field::PrimeCharacteristicRing;

#[inline]
pub(super) fn xor_from_and<E: PrimeCharacteristicRing>(lhs: E, rhs: E, and: E) -> E {
    lhs + rhs - and.clone() - and
}

#[inline]
pub(super) fn pack_u32_le<E: PrimeCharacteristicRing>(b0: E, b1: E, b2: E, b3: E) -> E {
    b0 + E::from_u64(1 << 8) * b1 + E::from_u64(1 << 16) * b2 + E::from_u64(1 << 24) * b3
}
