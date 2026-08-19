//! LogUp interface messages for the native Eidos/BlakeG compression chiplet.
//!
//! The `EidosIn` and `EidosOut` relation symbols are retained so the surrounding PVM bus
//! topology remains unchanged; the provider is now
//! [`BlakeGCompressionAir`](super::BlakeGCompressionAir) itself, not a Poseidon2 permutation or a
//! separate bridge.
//!
//! Two messages, one per bus:
//! - [`EidosInMsg`] (bus [`BusId::EidosIn`]) carries a 6-tuple `(absorption_id, tag, c0, c1, c2,
//!   c3)` with `tag ∈ {0, 1, 2, 3, 4}` selecting rate0 / rate1 / generic cap / AND cap / CHUNKS
//!   cap. Payload rows provide the rate halves and chain heads additionally provide a cap.
//! - [`EidosOutMsg`] (bus [`BusId::EidosOut`]) carries a 5-tuple `(absorption_id, d0, d1, d2, d3)`
//!   for the terminal Eidos chaining word.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// Tag value for the `rate0` chunk on [`BusId::EidosIn`].
pub const EIDOS_IN_TAG_RATE0: u8 = 0;
/// Tag value for the `rate1` chunk on [`BusId::EidosIn`].
pub const EIDOS_IN_TAG_RATE1: u8 = 1;
/// Tag value for a generic tagged-node cap on [`BusId::EidosIn`].
pub const EIDOS_IN_TAG_CAP_NODE: u8 = 2;
/// Tag value for the framework AND cap on [`BusId::EidosIn`].
pub const EIDOS_IN_TAG_CAP_AND: u8 = 3;
/// Tag value for the framework CHUNKS cap on [`BusId::EidosIn`].
pub const EIDOS_IN_TAG_CAP_CHUNKS: u8 = 4;

/// LogUp message for the `EidosIn` relation: a 6-tuple
/// `(absorption_id, tag, c0, c1, c2, c3)` carrying one 4-felt chunk of the
/// logical Eidos input block or semantic cap.
///
/// - `absorption_id` — sequential logical absorption identifier, unique per cycle.
/// - `tag` — chunk selector: `0 = rate0` (state[0..4]), `1 = rate1` (state[4..8]), `2 = capacity`
///   (state[8..12]).
/// - `c0..c3` — the four felts of the selected chunk.
///
/// Encoded as `bus_prefix[EidosIn] + β⁰·absorption_id + β¹·tag +
/// β²·c0 + β³·c1 + β⁴·c2 + β⁵·c3`.
#[derive(Debug, Clone)]
pub struct EidosInMsg<E> {
    pub absorption_id: E,
    pub tag: E,
    pub c: [E; 4],
}

impl<E> EidosInMsg<E>
where
    E: PrimeCharacteristicRing,
{
    /// Build an `InRate0` message.
    pub fn rate0(absorption_id: E, chunk: [E; 4]) -> Self {
        Self {
            absorption_id,
            tag: E::from_u8(EIDOS_IN_TAG_RATE0),
            c: chunk,
        }
    }

    /// Build an `InRate1` message.
    pub fn rate1(absorption_id: E, chunk: [E; 4]) -> Self {
        Self {
            absorption_id,
            tag: E::from_u8(EIDOS_IN_TAG_RATE1),
            c: chunk,
        }
    }

    /// Build a generic tagged-node `InCap` message.
    pub fn cap(absorption_id: E, chunk: [E; 4]) -> Self {
        Self::cap_node(absorption_id, chunk)
    }

    pub fn cap_node(absorption_id: E, chunk: [E; 4]) -> Self {
        Self {
            absorption_id,
            tag: E::from_u8(EIDOS_IN_TAG_CAP_NODE),
            c: chunk,
        }
    }

    pub fn cap_and(absorption_id: E, chunk: [E; 4]) -> Self {
        Self {
            absorption_id,
            tag: E::from_u8(EIDOS_IN_TAG_CAP_AND),
            c: chunk,
        }
    }

    pub fn cap_chunks(absorption_id: E, chunk: [E; 4]) -> Self {
        Self {
            absorption_id,
            tag: E::from_u8(EIDOS_IN_TAG_CAP_CHUNKS),
            c: chunk,
        }
    }
}

impl<E, EF> LookupMessage<E, EF> for EidosInMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [c0, c1, c2, c3] = self.c.clone();
        challenges.encode(
            BusId::EidosIn as usize,
            [self.absorption_id.clone(), self.tag.clone(), c0, c1, c2, c3],
        )
    }
}

/// LogUp message for the `EidosOut` relation: a 5-tuple
/// `(absorption_id, d0, d1, d2, d3)` carrying the 4-felt digest output of a
/// Eidos absorption.
///
/// The digest is the terminal four-felt packed Eidos chaining word.
///
/// Encoded as `bus_prefix[EidosOut] + β⁰·absorption_id + β¹·d0 + β²·d1 +
/// β³·d2 + β⁴·d3`.
#[derive(Debug, Clone)]
pub struct EidosOutMsg<E> {
    pub absorption_id: E,
    pub digest: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for EidosOutMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [d0, d1, d2, d3] = self.digest.clone();
        challenges.encode(BusId::EidosOut as usize, [self.absorption_id.clone(), d0, d1, d2, d3])
    }
}
