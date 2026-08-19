//! BlakeG compression chiplet for the deferred transcript.
//!
//! This is the direct PVM replacement for the former 16-row Poseidon2 permutation chiplet. Each
//! logical Eidos compression occupies one physical 32-row BlakeG cycle. The surrounding transcript
//! keeps its input/output relations and logical absorption IDs; those relations are emitted
//! directly from the BlakeG cycle rather than through a separate bridge AIR.

pub(crate) mod blakeg;
pub mod digest;
pub mod messages;
pub mod trace;

use alloc::{vec, vec::Vec};
use core::{array, borrow::Borrow};

use blakeg::{
    BLAKEG_LOOKUP_COLUMN_SHAPE, BlakeGCompressionCols, BlakeGCompressionLookupBuilder,
    NUM_PERIODIC_COLUMNS as BLAKEG_PERIODIC_COLS,
    constraints::{enforce_footer_rows, enforce_fused_rows},
    emit_lookup_columns, get_periodic_column_values,
    layout::{
        BLOCK_PERIOD as BLAKEG_COMPRESSION_CYCLE_LEN, F_C_BASE_COL, F_D_BASE_COL, F_R_BASE_COL,
        NUM_COLS as NUM_BLAKEG_COMPRESSION_COLS,
    },
    selectors::BlakeGSelectors,
};
pub use digest::{EidosCap, EidosDigest};
pub use messages::{
    EIDOS_IN_TAG_CAP_AND, EIDOS_IN_TAG_CAP_CHUNKS, EIDOS_IN_TAG_CAP_NODE, EIDOS_IN_TAG_RATE0,
    EIDOS_IN_TAG_RATE1, EidosInMsg, EidosOutMsg,
};
use miden_air::{
    logup::{BusId as MidenBusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        ConstraintLookupBuilder as MidenConstraintLookupBuilder, LookupAir,
        build_logup_aux_trace as build_miden_aux_trace,
    },
};
use miden_core::{
    Felt,
    deferred::{DEFERRED_CHUNKS_DOMAIN, DEFERRED_NODE_DOMAIN, DEFERRED_ROOT_DOMAIN},
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess};

use crate::{
    composite::{SubAirBuilder, concatenate_bands, extract_band},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES, build_logup_aux_trace,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================

/// The first 128 columns are the PVM-owned wide BlakeG compression layout.
pub const COL_BLAKEG_BEGIN: usize = 0;
pub const COL_BLAKEG_END: usize = NUM_BLAKEG_COMPRESSION_COLS;

/// Cycle-constant logical input-block identifier.
pub const COL_ABSORPTION_ID: usize = COL_BLAKEG_END;
pub const COL_IN_MULTIPLICITY: usize = COL_ABSORPTION_ID + 1;
pub const COL_OUT_MULTIPLICITY: usize = COL_IN_MULTIPLICITY + 1;
pub const COL_IS_HEAD: usize = COL_OUT_MULTIPLICITY + 1;
pub const COL_IS_ABSORB: usize = COL_IS_HEAD + 1;
pub const COL_IS_PAYLOAD: usize = COL_IS_ABSORB + 1;
pub const COL_IS_OUTPUT: usize = COL_IS_PAYLOAD + 1;
pub const COL_IS_AND: usize = COL_IS_OUTPUT + 1;
pub const COL_IS_CHUNKS: usize = COL_IS_AND + 1;
pub const COL_IS_GENERIC: usize = COL_IS_CHUNKS + 1;
pub const COL_REMAINING: usize = COL_IS_GENERIC + 1;
pub const COL_REMAINING_INV: usize = COL_REMAINING + 1;
pub const COL_CAP_BEGIN: usize = COL_REMAINING_INV + 1;
pub const COL_CAP_END: usize = COL_CAP_BEGIN + 4;
pub const COL_CV_IN_BEGIN: usize = COL_CAP_END;
pub const COL_CV_IN_END: usize = COL_CV_IN_BEGIN + 4;
pub const NUM_MAIN_COLS: usize = COL_CV_IN_END;

const PVM_AUX_COLS: usize = 3;
const BLAKEG_AUX_COLS: usize = BLAKEG_LOOKUP_COLUMN_SHAPE.len();
pub const NUM_AUX_COLS: usize = PVM_AUX_COLS + BLAKEG_AUX_COLS;
const PVM_COLUMN_SHAPE: [usize; PVM_AUX_COLS] = [1, 2, 1];

const PVM_VALUE_OFFSET: usize = 0;
const BLAKEG_VALUE_OFFSET: usize = 1;

// The two lookup families deliberately share alpha/beta but use different bus-prefix exponents:
// PVM prefixes sit at beta^18, while native Miden BlakeG/And8 prefixes sit at beta^16. This keeps
// their denominator polynomials domain-separated even though both BusId enums start at zero.
// Equal widths would make cross-family bus-id collisions possible.
const _: () = assert!(MAX_MESSAGE_WIDTH != MIDEN_MAX_MESSAGE_WIDTH);

// PUBLIC AIR
// ================================================================================================

/// PVM-native BlakeG compression AIR. One compression occupies exactly 32 rows.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlakeGCompressionAir;

impl BaseAir<Felt> for BlakeGCompressionAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for BlakeGCompressionAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        2
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let (pvm_aux, pvm_values) =
            BlakeGInterfaceAir.build_aux_trace(main, air_inputs, aux_inputs, challenges);
        let blakeg_main = extract_band(main, COL_BLAKEG_BEGIN..COL_BLAKEG_END);
        let (blakeg_aux, blakeg_values) =
            BlakeGNarrowAir.build_aux_trace(&blakeg_main, air_inputs, aux_inputs, challenges);
        assert_eq!(pvm_values.len(), 1);
        assert_eq!(blakeg_values.len(), 1);

        (concatenate_bands(&pvm_aux, &blakeg_aux), vec![pvm_values[0], blakeg_values[0]])
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let mut interface = SubAirBuilder::new(
                builder,
                0..NUM_MAIN_COLS,
                0..0,
                0..PVM_AUX_COLS,
                PVM_VALUE_OFFSET..PVM_VALUE_OFFSET + 1,
                0..BLAKEG_PERIODIC_COLS,
            );
            <BlakeGInterfaceAir as LiftedAir<Felt, QuadFelt>>::eval(
                &BlakeGInterfaceAir,
                &mut interface,
            );
        }
        {
            let mut compression = SubAirBuilder::new(
                builder,
                COL_BLAKEG_BEGIN..COL_BLAKEG_END,
                0..0,
                PVM_AUX_COLS..NUM_AUX_COLS,
                BLAKEG_VALUE_OFFSET..BLAKEG_VALUE_OFFSET + 1,
                0..BLAKEG_PERIODIC_COLS,
            );
            <BlakeGNarrowAir as LiftedAir<Felt, QuadFelt>>::eval(
                &BlakeGNarrowAir,
                &mut compression,
            );
        }
    }
}

// BLAKEG COMPRESSION CORE
// ================================================================================================

/// The intrinsic BlakeG constraints and byte/range lookups, without Miden VM controller or AEAD
/// singleton links. The PVM interface below occupies those boundaries directly.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BlakeGNarrowAir;

impl BaseAir<Felt> for BlakeGNarrowAir {
    fn width(&self) -> usize {
        NUM_BLAKEG_COMPRESSION_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for BlakeGNarrowAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        BLAKEG_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_miden_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = BlakeGSelectors::new(&periodic_values, 0);
            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
        }

        let mut lb = MidenConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for BlakeGNarrowAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        BLAKEG_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &BLAKEG_LOOKUP_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        MidenBusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &BlakeGCompressionCols<_> = main.current_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = BlakeGSelectors::new(&periodic_values, 0);
        emit_lookup_columns(builder, local, &selectors);
    }
}

// PVM INTERFACE
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BlakeGInterfaceAir;

impl BaseAir<Felt> for BlakeGInterfaceAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }
}

impl LiftedAir<Felt, QuadFelt> for BlakeGInterfaceAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        PVM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_logup_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periodic_values: Vec<AB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = BlakeGSelectors::new(&periodic_values, 0);
        let is_last = selectors.is_footer_row(3);
        let not_last = AB::Expr::ONE - is_last.clone();

        let head: AB::Expr = local[COL_IS_HEAD].into();
        let absorb: AB::Expr = local[COL_IS_ABSORB].into();
        let payload: AB::Expr = local[COL_IS_PAYLOAD].into();
        let output: AB::Expr = local[COL_IS_OUTPUT].into();
        let is_and: AB::Expr = local[COL_IS_AND].into();
        let is_chunks: AB::Expr = local[COL_IS_CHUNKS].into();
        let is_generic: AB::Expr = local[COL_IS_GENERIC].into();
        let remaining: AB::Expr = local[COL_REMAINING].into();
        let remaining_inv: AB::Expr = local[COL_REMAINING_INV].into();
        let active = head.clone() + absorb.clone();
        let next_head: AB::Expr = next[COL_IS_HEAD].into();
        let next_absorb: AB::Expr = next[COL_IS_ABSORB].into();
        let next_active = next_head + next_absorb.clone();
        let next_payload: AB::Expr = next[COL_IS_PAYLOAD].into();

        for col in [
            COL_IS_HEAD,
            COL_IS_ABSORB,
            COL_IS_PAYLOAD,
            COL_IS_OUTPUT,
            COL_IS_AND,
            COL_IS_CHUNKS,
            COL_IS_GENERIC,
        ] {
            builder.assert_bool(local[col]);
        }

        builder.assert_zero(head.clone() * absorb.clone());
        builder
            .assert_zero(is_and.clone() + is_chunks.clone() + is_generic.clone() - active.clone());
        builder.assert_zero(payload.clone() * (AB::Expr::ONE - active.clone()));
        builder.assert_zero(output.clone() * (AB::Expr::ONE - active.clone()));
        builder.assert_zero(head.clone() * (payload.clone() - AB::Expr::ONE));

        builder.assert_zero(is_and.clone() * (payload.clone() - AB::Expr::ONE));
        builder.assert_zero(is_and.clone() * (output.clone() - AB::Expr::ONE));
        builder.assert_zero(is_and.clone() * (remaining.clone() - AB::Expr::ONE));
        builder.assert_zero(is_chunks.clone() * (payload.clone() - AB::Expr::ONE));
        builder
            .assert_zero(is_generic.clone() * (payload.clone() + output.clone() - AB::Expr::ONE));

        let remaining_minus_one = remaining.clone() - AB::Expr::ONE;
        builder.assert_zero(active.clone() * output.clone() * remaining_minus_one.clone());
        builder.assert_zero(
            active.clone()
                * (remaining_minus_one * remaining_inv - (AB::Expr::ONE - output.clone())),
        );

        builder.when_first_row().assert_zero(local[COL_ABSORPTION_ID]);
        builder.when_first_row().assert_zero(absorb.clone());

        // Every metadata column is constant throughout its physical 32-row compression cycle.
        for col in COL_ABSORPTION_ID..NUM_MAIN_COLS {
            builder.assert_zero(
                not_last.clone() * (AB::Expr::from(next[col]) - AB::Expr::from(local[col])),
            );
        }

        // Logical ids advance for payload compressions. A generic tag-finalization compression
        // reuses the payload tail's id, exactly as the surrounding buses expect.
        builder.when_transition().assert_zero(
            is_last.clone()
                * next_active.clone()
                * (AB::Expr::from(next[COL_ABSORPTION_ID])
                    - AB::Expr::from(local[COL_ABSORPTION_ID])
                    - next_payload.clone()),
        );

        builder.when_transition().assert_zero(
            is_last.clone()
                * active.clone()
                * (AB::Expr::ONE - output.clone())
                * (AB::Expr::ONE - next_absorb.clone()),
        );
        builder
            .when_transition()
            .assert_zero(is_last.clone() * output.clone() * next_absorb.clone());
        builder
            .when_last_row()
            .assert_zero(active.clone() * (AB::Expr::ONE - output.clone()));

        builder.when_transition().assert_zero(
            is_last.clone()
                * next_absorb.clone()
                * (AB::Expr::from(next[COL_REMAINING]) - remaining.clone() + AB::Expr::ONE),
        );
        for col in [COL_IS_AND, COL_IS_CHUNKS, COL_IS_GENERIC] {
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[col]) - AB::Expr::from(local[col])),
            );
        }
        for i in 0..4 {
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[COL_CAP_BEGIN + i])
                        - AB::Expr::from(local[COL_CAP_BEGIN + i])),
            );
            builder.when_transition().assert_zero(
                is_last.clone()
                    * next_absorb.clone()
                    * (AB::Expr::from(next[COL_CV_IN_BEGIN + i])
                        - AB::Expr::from(local[F_D_BASE_COL + i])),
            );
            builder.assert_zero(
                is_last.clone()
                    * (AB::Expr::from(local[COL_CV_IN_BEGIN + i])
                        - AB::Expr::from(local[F_C_BASE_COL + i])),
            );
        }

        let and_init = DEFERRED_ROOT_DOMAIN.into_elements();
        let chunks_init =
            Eidos::init_chaining_word(DEFERRED_CHUNKS_DOMAIN.as_canonical_u64() as u32, 0)
                .into_elements();
        let generic_init =
            Eidos::init_chaining_word(DEFERRED_NODE_DOMAIN.as_canonical_u64() as u32, 0)
                .into_elements();
        for i in 0..4 {
            let mut expected = is_and.clone() * AB::Expr::from(and_init[i])
                + is_chunks.clone() * AB::Expr::from(chunks_init[i])
                + is_generic.clone() * AB::Expr::from(generic_init[i]);
            if i == 3 {
                expected = expected
                    + is_chunks.clone() * remaining.clone() * AB::Expr::from(Felt::from_u8(8))
                    + is_generic.clone()
                        * (remaining.clone() * AB::Expr::from(Felt::from_u8(8))
                            - AB::Expr::from(Felt::from_u8(4)));
            }
            builder.assert_zero(
                head.clone() * (AB::Expr::from(local[COL_CV_IN_BEGIN + i]) - expected),
            );
        }

        let cap: [AB::Expr; 4] = array::from_fn(|i| local[COL_CAP_BEGIN + i].into());
        let and_cap = EidosCap::and().as_array();
        let chunks_cap = EidosCap::chunk().as_array();
        for i in 0..4 {
            builder.assert_zero(is_and.clone() * (cap[i].clone() - AB::Expr::from(and_cap[i])));
            builder
                .assert_zero(is_chunks.clone() * (cap[i].clone() - AB::Expr::from(chunks_cap[i])));
            builder.assert_zero(
                is_last.clone()
                    * is_generic.clone()
                    * output.clone()
                    * (AB::Expr::from(local[F_R_BASE_COL + i]) - cap[i].clone()),
            );
            builder.assert_zero(
                is_last.clone()
                    * is_generic.clone()
                    * output.clone()
                    * AB::Expr::from(local[F_R_BASE_COL + 4 + i]),
            );
        }

        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for BlakeGInterfaceAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        PVM_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &PVM_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = BlakeGSelectors::new(&periodic_values, 0);
        let is_last = selectors.is_footer_row(3);

        let absorption_id: LB::Expr = local[COL_ABSORPTION_ID].into();
        let in_mult: LB::Expr = local[COL_IN_MULTIPLICITY].into();
        let out_mult: LB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let head: LB::Expr = local[COL_IS_HEAD].into();
        let payload: LB::Expr = local[COL_IS_PAYLOAD].into();
        let output: LB::Expr = local[COL_IS_OUTPUT].into();
        let is_and: LB::Expr = local[COL_IS_AND].into();
        let is_chunks: LB::Expr = local[COL_IS_CHUNKS].into();
        let is_generic: LB::Expr = local[COL_IS_GENERIC].into();

        let block: [LB::Expr; 8] = array::from_fn(|i| local[F_R_BASE_COL + i].into());
        let rate0: [LB::Expr; 4] = array::from_fn(|i| block[i].clone());
        let rate1: [LB::Expr; 4] = array::from_fn(|i| block[4 + i].clone());
        let cap: [LB::Expr; 4] = array::from_fn(|i| local[COL_CAP_BEGIN + i].into());
        let digest: [LB::Expr; 4] = array::from_fn(|i| local[F_D_BASE_COL + i].into());
        let cap_tag = is_generic * LB::Expr::from(Felt::from_u8(EIDOS_IN_TAG_CAP_NODE))
            + is_and * LB::Expr::from(Felt::from_u8(EIDOS_IN_TAG_CAP_AND))
            + is_chunks * LB::Expr::from(Felt::from_u8(EIDOS_IN_TAG_CAP_CHUNKS));

        let m_in = LB::Expr::ZERO - is_last.clone() * in_mult.clone() * payload;
        let m_cap = LB::Expr::ZERO - is_last.clone() * in_mult * head;
        let m_out = LB::Expr::ZERO - is_last * out_mult * output;
        let one = Deg { v: 1, u: 1 };
        let batch_one = Deg { v: 4, u: 3 };
        let batch_two = Deg { v: 4, u: 3 };
        let group = Deg { v: 5, u: 4 };

        builder.next_column(
            |col| {
                col.group(
                    "blakeg-pvm-rate0",
                    |g| {
                        g.batch(
                            "frac",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "in-rate0",
                                    m_in.clone(),
                                    EidosInMsg::rate0(absorption_id.clone(), rate0),
                                    one,
                                );
                            },
                            batch_one,
                        );
                    },
                    group,
                );
            },
            group,
        );
        builder.next_column(
            |col| {
                col.group(
                    "blakeg-pvm-rate1-out",
                    |g| {
                        g.batch(
                            "frac",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "in-rate1",
                                    m_in,
                                    EidosInMsg::rate1(absorption_id.clone(), rate1),
                                    one,
                                );
                                b.insert(
                                    "out-digest",
                                    m_out,
                                    EidosOutMsg {
                                        absorption_id: absorption_id.clone(),
                                        digest,
                                    },
                                    one,
                                );
                            },
                            batch_two,
                        );
                    },
                    group,
                );
            },
            group,
        );
        builder.next_column(
            |col| {
                col.group(
                    "blakeg-pvm-cap",
                    |g| {
                        g.batch(
                            "frac",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "in-cap",
                                    m_cap,
                                    EidosInMsg { absorption_id, tag: cap_tag, c: cap },
                                    one,
                                );
                            },
                            batch_one,
                        );
                    },
                    group,
                );
            },
            group,
        );
    }
}

const _: () = assert!(BLAKEG_COMPRESSION_CYCLE_LEN == 32);
