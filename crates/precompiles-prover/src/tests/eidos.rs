//! Tests for the deferred transcript's native 32-row BlakeG compression AIR.

use std::{fs, path::Path, string::String, vec, vec::Vec};

use miden_air::{
    BaseAir,
    logup::{BusId as MidenBusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        Challenges as MidenChallenges,
        debug::{check_trace_balance, trace::BalanceReport},
    },
    trace::blakeg_compression::{
        self as mvm_blakeg, TraceMode as MvmTraceMode,
        generate_felt_trace_block as generate_mvm_block,
    },
};
use miden_core::{
    Felt,
    deferred::{DEFERRED_CHUNKS_DOMAIN, DEFERRED_NODE_DOMAIN, DEFERRED_ROOT_DOMAIN, Tag},
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;
use miden_lifted_air::LiftedAir;
use miden_precompiles::{CurvePrecompile, Keccak256Precompile};

use crate::{
    logup::{Challenges, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::Session,
    transcript::eidos::{
        BlakeGCompressionAir, BlakeGNarrowAir, COL_ABSORPTION_ID, COL_BLAKEG_END, COL_CAP_BEGIN,
        COL_CV_IN_BEGIN, COL_IS_ABSORB, COL_IS_GENERIC, COL_IS_HEAD, COL_IS_OUTPUT, COL_IS_PAYLOAD,
        COL_REMAINING, EidosCap, EidosDigest, EidosInMsg, EidosOutMsg, NUM_AUX_COLS, NUM_MAIN_COLS,
        blakeg::{
            layout::{
                BLOCK_PERIOD as BLAKEG_COMPRESSION_CYCLE_LEN, BYTE_SLOT_WIDTH, F_C_BASE_COL,
                F_C_CANON_INV_COL, F_C_CANON_Z_COL, F_COMPRESSION_CYCLE_ID_COL, F_D_BASE_COL,
                F_FUTURE_W_BASE_COL, F_HIN_SLOT_BASE_COL, F_MSG_GROUP_BASE_COL, F_MSG_GROUP_SLOTS,
                F_R_BASE_COL, F_R_CANON_INV_BASE_COL, F_R_CANON_Z_BASE_COL, FOOTER_ROWS,
                FOOTER_START, G_A_BASE_COL, G_C_BASE_COL, G_K2_BASE_COL, G_K3_BIT0_BASE_COL,
                G_K3_BIT1_BASE_COL, NUM_COLS as NUM_BLAKEG_COMPRESSION_COLS,
                footer_future_w_indices, g_bd_rot_slot_col, g_msg_slot_col,
            },
            trace::{
                BlakeGFeltTraceBlock, generate_felt_trace_block_with_cycle_id,
                rewrite_felt_footer_for_test,
            },
        },
        trace::{EidosRequires, generate_traces},
    },
};

fn block(a: u32) -> ([Felt; 4], [Felt; 4]) {
    (
        core::array::from_fn(|i| Felt::from(a + i as u32)),
        core::array::from_fn(|i| Felt::from(a + 4 + i as u32)),
    )
}

#[test]
fn full_empty_session_bus_stack_balances() {
    let mut session = Session::new();
    let root = session.assert_and_fold(core::iter::empty());
    let traces = session.finish(root);
    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let residual =
        crate::tests::bus_balance::session_stack_residual(&traces.mains(), &[], &challenges);
    assert!(residual.is_empty(), "{residual:#?}");
}

fn as_block((lo, hi): ([Felt; 4], [Felt; 4])) -> [Felt; 8] {
    let mut out = [Felt::ZERO; 8];
    out[..4].copy_from_slice(&lo);
    out[4..].copy_from_slice(&hi);
    out
}

fn unpack_felts<const N: usize>(values: &[Felt]) -> [u32; N] {
    let words: Vec<u32> = values
        .iter()
        .flat_map(|value| {
            let packed = value.as_canonical_u64();
            [packed as u32, (packed >> 32) as u32]
        })
        .collect();
    words.try_into().unwrap_or_else(|words: Vec<u32>| {
        panic!("expected {N} unpacked words, got {}", words.len())
    })
}

fn two_cycle_matrix(
    first: &BlakeGFeltTraceBlock,
    second: &BlakeGFeltTraceBlock,
) -> RowMajorMatrix<Felt> {
    let values = first
        .rows
        .iter()
        .chain(&second.rows)
        .flat_map(|row| row.iter().copied())
        .collect();
    RowMajorMatrix::new(values, NUM_BLAKEG_COMPRESSION_COLS)
}

fn miden_lookup_challenges() -> MidenChallenges<QuadFelt> {
    MidenChallenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MIDEN_MAX_MESSAGE_WIDTH,
        MidenBusId::COUNT,
    )
}

fn narrow_balance(
    trace: &RowMajorMatrix<Felt>,
    challenges: &MidenChallenges<QuadFelt>,
) -> BalanceReport {
    let air = BlakeGNarrowAir;
    check_trace_balance(&air, trace, &air.periodic_columns(), &[], &[], challenges)
}

fn net_multiplicity(report: &BalanceReport, denominator: QuadFelt) -> Felt {
    report
        .unmatched
        .iter()
        .find(|entry| entry.denom == denominator)
        .map_or(Felt::ZERO, |entry| entry.net_multiplicity)
}

#[test]
fn caps_match_vm_sources() {
    let len_bytes = 136u32;
    assert_eq!(EidosCap::chunk().as_array(), Tag::CHUNKS.as_word());
    assert_eq!(EidosCap::and().as_array(), Tag::AND.as_word());
    assert_eq!(
        EidosCap::keccak256_assertion(len_bytes).as_array(),
        Keccak256Precompile::assert_tag(len_bytes).as_word(),
    );
    assert_eq!(
        EidosCap::ec_msm_iv().as_array(),
        [
            CurvePrecompile::id(),
            Felt::from_u32(CurvePrecompile::MSM_OP_ID as u32),
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
}

#[test]
fn typed_cap_messages_are_domain_distinct() {
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::from_u64(7),
        QuadFelt::from_u64(5),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let seq = Felt::from_u32(1);
    let chunk = [Felt::ZERO; 4];
    let messages = [
        EidosInMsg::rate0(seq, chunk).encode(&challenges),
        EidosInMsg::rate1(seq, chunk).encode(&challenges),
        EidosInMsg::cap_node(seq, chunk).encode(&challenges),
        EidosInMsg::cap_and(seq, chunk).encode(&challenges),
        EidosInMsg::cap_chunks(seq, chunk).encode(&challenges),
    ];
    for (i, lhs) in messages.iter().enumerate() {
        for rhs in messages.iter().skip(i + 1) {
            assert_ne!(lhs, rhs);
        }
    }
    assert_ne!(
        EidosInMsg::rate0(seq, chunk).encode(&challenges),
        EidosOutMsg { absorption_id: seq, digest: chunk }.encode(&challenges),
    );
}

#[test]
fn air_layout_matches_32_row_blakeg_spec() {
    assert_eq!(BLAKEG_COMPRESSION_CYCLE_LEN, 32);
    assert_eq!(COL_BLAKEG_END, 128);
    assert_eq!(COL_IS_HEAD, 131);
    assert_eq!(COL_IS_ABSORB, 132);
    assert_eq!(COL_CAP_BEGIN, 140);
    assert_eq!(COL_CV_IN_BEGIN, 144);
    assert_eq!(NUM_MAIN_COLS, 148);

    let layout =
        <BlakeGCompressionAir as LiftedAir<Felt, QuadFelt>>::air_layout(&BlakeGCompressionAir);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, 2);
    assert_eq!(layout.num_periodic_columns, 14);
    assert_eq!(
        <BlakeGCompressionAir as BaseAir<Felt>>::periodic_columns(&BlakeGCompressionAir)
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![BLAKEG_COMPRESSION_CYCLE_LEN; 14],
    );
}

#[test]
fn digests_match_eidos_framing_and_integrated_blakeg_air_holds() {
    let and_block = block(10);
    let chunk_blocks = [block(20), block(30), block(40)];
    let generic_blocks = [block(50), block(60)];
    let generic_cap = EidosCap::keccak256_assertion(17);

    let mut requires = EidosRequires::new();
    let and = requires.require_absorption(EidosCap::and(), [and_block]);
    let chunks = requires.require_absorption(EidosCap::chunk(), chunk_blocks);
    let generic = requires.require_absorption(generic_cap, generic_blocks);
    for digest in [and.digest, chunks.digest, generic.digest] {
        requires.require_digest(digest).expect("recorded digest");
    }

    let expected_and = Eidos::compress_block(DEFERRED_ROOT_DOMAIN, as_block(and_block));
    assert_eq!(and.digest, EidosDigest(expected_and.into_elements()));

    let mut expected_chunks =
        Eidos::init_chaining_word(DEFERRED_CHUNKS_DOMAIN.as_canonical_u64() as u32, 24);
    for input in chunk_blocks {
        expected_chunks = Eidos::compress_block(expected_chunks, as_block(input));
    }
    assert_eq!(chunks.digest, EidosDigest(expected_chunks.into_elements()));

    let mut expected_generic =
        Eidos::init_chaining_word(DEFERRED_NODE_DOMAIN.as_canonical_u64() as u32, 20);
    for input in generic_blocks {
        expected_generic = Eidos::compress_block(expected_generic, as_block(input));
    }
    let mut final_block = [Felt::ZERO; 8];
    final_block[..4].copy_from_slice(&generic_cap.as_array());
    expected_generic = Eidos::compress_block(expected_generic, final_block);
    assert_eq!(generic.digest, EidosDigest(expected_generic.into_elements()));

    let traces = generate_traces(requires);
    crate::tests::check_local(BlakeGCompressionAir, &traces.compression);

    // Seven real compressions occupy seven full 32-row cycles, padded to eight cycles.
    assert_eq!(traces.compression.values.len() / NUM_MAIN_COLS, 8 * 32);
    let row = |cycle: usize, c: usize| {
        traces.compression.values[cycle * BLAKEG_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS + c]
    };
    assert_eq!(row(0, COL_IS_HEAD), Felt::ONE);
    assert_eq!(row(1, COL_REMAINING), Felt::from_u32(3));
    assert_eq!(row(4, COL_IS_GENERIC), Felt::ONE);
    assert_eq!(row(6, COL_IS_PAYLOAD), Felt::ZERO);
    assert_eq!(row(6, COL_IS_OUTPUT), Felt::ONE);

    // The PVM output relation reads the digest directly from the native BlakeG footer. There is
    // no bridge trace between the compression witness and the value seen by transcript consumers.
    let footer_digest = |cycle: usize| {
        let footer = cycle * BLAKEG_COMPRESSION_CYCLE_LEN + BLAKEG_COMPRESSION_CYCLE_LEN - 1;
        core::array::from_fn(|i| {
            traces.compression.values[footer * NUM_MAIN_COLS + F_D_BASE_COL + i]
        })
    };
    assert_eq!(footer_digest(0), and.digest.as_array());
    assert_eq!(footer_digest(3), chunks.digest.as_array());
    assert_eq!(footer_digest(6), generic.digest.as_array());

    for cycle in 0..7 {
        let first = cycle * BLAKEG_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS;
        for row in 1..BLAKEG_COMPRESSION_CYCLE_LEN {
            let current = first + row * NUM_MAIN_COLS;
            assert_eq!(
                &traces.compression.values[current + COL_ABSORPTION_ID..current + NUM_MAIN_COLS],
                &traces.compression.values[first + COL_ABSORPTION_ID..first + NUM_MAIN_COLS],
                "PVM metadata changed within physical BlakeG cycle {cycle} at row {row}",
            );
        }
    }
}

#[test]
fn identical_blakeg_states_remain_distinct_ordered_pvm_cycles() {
    let payload = block(70);
    let mut requires = EidosRequires::new();
    let first = requires.require_absorption(EidosCap::keccak256_assertion(8), [payload]);
    let second = requires.require_absorption(EidosCap::keccak256_assertion(9), [payload]);
    assert_ne!(first.digest, second.digest);
    assert_eq!(requires.total_cycles(), 2);

    let compression = generate_traces(requires).compression;
    let row = |cycle: usize, col: usize| {
        compression.values[cycle * BLAKEG_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS + col]
    };

    // Both generic absorptions start from the same Eidos init CV and payload block, so their first
    // BlakeG states are identical. They must nevertheless remain two physical cycles because the
    // external absorption IDs and distinct tag-finalization cycles are ordered protocol data.
    let second_start = 2 * BLAKEG_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS;
    let cycle_id_cells = core::array::from_fn::<_, 4, _>(|g| g_msg_slot_col(g, 2));
    for col in 0..NUM_BLAKEG_COMPRESSION_COLS {
        if !cycle_id_cells.contains(&col) {
            assert_eq!(compression.values[col], compression.values[second_start + col]);
        }
    }
    assert_eq!(row(0, COL_ABSORPTION_ID), Felt::ZERO);
    assert_eq!(row(1, COL_ABSORPTION_ID), Felt::ZERO);
    assert_eq!(row(2, COL_ABSORPTION_ID), Felt::ONE);
    assert_eq!(row(3, COL_ABSORPTION_ID), Felt::ONE);
    crate::tests::check_local(BlakeGCompressionAir, &compression);
}

#[test]
fn physical_cycle_id_rejects_two_cycle_cv_swap() {
    let block_a = core::array::from_fn(|i| 10 + i as u32);
    let block_b = core::array::from_fn(|i| 100 + i as u32);
    let cv_a = core::array::from_fn(|i| 1_000 + i as u32);
    let cv_b = core::array::from_fn(|i| 2_000 + i as u32);

    // Each computation consumes the other cycle's CV. Its footer continues to advertise the CV
    // assigned to this physical cycle, reproducing the formerly anonymous-bus forgery.
    let mut forged_a = generate_felt_trace_block_with_cycle_id(block_a, cv_b, 0);
    let mut forged_b = generate_felt_trace_block_with_cycle_id(block_b, cv_a, 1);
    rewrite_felt_footer_for_test(&mut forged_a.rows, block_a, cv_a, forged_a.final_v, 0);
    rewrite_felt_footer_for_test(&mut forged_b.rows, block_b, cv_b, forged_b.final_v, 1);

    let forged = two_cycle_matrix(&forged_a, &forged_b);
    // Every polynomial constraint still holds; rejection comes specifically from the tagged
    // internal CV bus when the complete LogUp balance is checked.
    crate::tests::check_local(BlakeGNarrowAir, &forged);
    let challenges = miden_lookup_challenges();
    let report = narrow_balance(&forged, &challenges);
    for (cycle_id, consumed, advertised) in [(0u64, cv_b, cv_a), (1, cv_a, cv_b)] {
        for pair in 0..FOOTER_ROWS {
            let encode = |cv: [u32; 8]| {
                challenges.encode(
                    MidenBusId::BlakeGInputWord as usize,
                    [
                        Felt::new_unchecked(FOOTER_ROWS as u64 * cycle_id + pair as u64),
                        Felt::from(cv[2 * pair]),
                        Felt::from(cv[2 * pair + 1]),
                    ],
                )
            };
            assert_eq!(net_multiplicity(&report, encode(consumed)), -Felt::ONE);
            assert_eq!(net_multiplicity(&report, encode(advertised)), Felt::ONE);
        }
    }
}

#[test]
fn physical_cycle_id_rejects_two_cycle_message_swap() {
    let block_a = core::array::from_fn(|i| 10 + i as u32);
    let block_b = core::array::from_fn(|i| 100 + i as u32);
    let cv_a = core::array::from_fn(|i| 1_000 + i as u32);
    let cv_b = core::array::from_fn(|i| 2_000 + i as u32);

    // Each computation consumes the other cycle's block. Replace only its footer's advertised
    // block, leaving the computed BlakeG output intact.
    let advertised_a = generate_felt_trace_block_with_cycle_id(block_a, cv_a, 0);
    let advertised_b = generate_felt_trace_block_with_cycle_id(block_b, cv_b, 1);
    let mut forged_a = generate_felt_trace_block_with_cycle_id(block_b, cv_a, 0);
    let mut forged_b = generate_felt_trace_block_with_cycle_id(block_a, cv_b, 1);
    for (forged, advertised) in [(&mut forged_a, &advertised_a), (&mut forged_b, &advertised_b)] {
        for row in FOOTER_START..BLAKEG_COMPRESSION_CYCLE_LEN {
            forged.rows[row]
                [F_MSG_GROUP_BASE_COL..F_MSG_GROUP_BASE_COL + BYTE_SLOT_WIDTH * F_MSG_GROUP_SLOTS]
                .copy_from_slice(
                    &advertised.rows[row][F_MSG_GROUP_BASE_COL
                        ..F_MSG_GROUP_BASE_COL + BYTE_SLOT_WIDTH * F_MSG_GROUP_SLOTS],
                );
            forged.rows[row][F_R_BASE_COL..F_R_BASE_COL + 8]
                .copy_from_slice(&advertised.rows[row][F_R_BASE_COL..F_R_BASE_COL + 8]);
            forged.rows[row][F_R_CANON_INV_BASE_COL..F_R_CANON_INV_BASE_COL + 2].copy_from_slice(
                &advertised.rows[row][F_R_CANON_INV_BASE_COL..F_R_CANON_INV_BASE_COL + 2],
            );
            forged.rows[row][F_R_CANON_Z_BASE_COL..F_R_CANON_Z_BASE_COL + 2].copy_from_slice(
                &advertised.rows[row][F_R_CANON_Z_BASE_COL..F_R_CANON_Z_BASE_COL + 2],
            );
        }
    }

    let forged = two_cycle_matrix(&forged_a, &forged_b);
    crate::tests::check_local(BlakeGNarrowAir, &forged);
    let challenges = miden_lookup_challenges();
    let report = narrow_balance(&forged, &challenges);
    let seven = Felt::from_u8(7);
    for (cycle_id, consumed, advertised) in [(0u64, block_b, block_a), (1, block_a, block_b)] {
        for word_index in 0..16 {
            let encode = |block: [u32; 16]| {
                challenges.encode(
                    MidenBusId::BlakeGMessageWord as usize,
                    [
                        Felt::from_usize(word_index),
                        Felt::from(block[word_index]),
                        Felt::new_unchecked(cycle_id),
                    ],
                )
            };
            assert_eq!(net_multiplicity(&report, encode(consumed)), seven);
            assert_eq!(net_multiplicity(&report, encode(advertised)), -seven);
        }
    }
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_is_pinned_to_zero() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let first = generate_felt_trace_block_with_cycle_id(block, cv, 1);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);

    crate::tests::check_local(BlakeGNarrowAir, &two_cycle_matrix(&first, &second));
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_is_constant_across_fused_rows() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 1);
    first.rows[1][g_msg_slot_col(0, 2)] = Felt::ONE;

    crate::tests::check_local(BlakeGNarrowAir, &two_cycle_matrix(&first, &second));
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_bridges_fused_rows_to_footer() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);
    rewrite_felt_footer_for_test(&mut first.rows, block, cv, first.final_v, 1);

    crate::tests::check_local(BlakeGNarrowAir, &two_cycle_matrix(&first, &second));
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_increments_between_cycles() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);

    crate::tests::check_local(BlakeGNarrowAir, &two_cycle_matrix(&first, &second));
}

#[test]
#[should_panic(expected = "packed BlakeG input must be a canonical field element")]
fn pvm_trace_writer_rejects_noncanonical_packed_input() {
    let mut block = [0; 16];
    block[0] = 1;
    block[1] = u32::MAX;
    let _ = generate_felt_trace_block_with_cycle_id(block, [0; 8], 0);
}

#[test]
fn mvm_and_pvm_writers_agree_on_shared_blakeg_witness() {
    const TWO_POW_32: Felt = Felt::new_unchecked(1 << 32);
    const MISSING_ROTATION_G: usize = mvm_blakeg::NUM_G - 1;
    const MISSING_ROTATION_BYTE: usize = mvm_blakeg::BYTES_PER_WORD - 1;

    assert_eq!(NUM_BLAKEG_COMPRESSION_COLS, 128);
    assert_eq!(mvm_blakeg::NUM_BLAKEG_COMPRESSION_COLS, 108);

    for case in 0..16_u32 {
        let block = core::array::from_fn(|i| {
            0x1020_3040_u32
                .wrapping_add(0x0102_0304_u32.wrapping_mul(i as u32))
                .rotate_left(case)
        });
        let cv = core::array::from_fn(|i| {
            0x5060_7080_u32
                .wrapping_add(0x0001_0203_u32.wrapping_mul(i as u32))
                .rotate_right(case)
        });
        let pvm = generate_felt_trace_block_with_cycle_id(block, cv, 0);
        let mvm = generate_mvm_block(block, cv, MvmTraceMode::Compression);

        assert_eq!(pvm.final_v, mvm.final_v, "final working state differs in case {case}");

        for row in 0..FOOTER_START {
            for col in 0..mvm_blakeg::g_msg_word_col(0) {
                assert_eq!(
                    pvm.rows[row][col], mvm.rows[row][col],
                    "MVM/PVM shared fused cell mismatch in case {case}, row {row}, column {col}",
                );
            }

            // The MVM omits this result cell and reconstructs it from the next-row B total.
            let next_b_sum = (0..mvm_blakeg::NUM_G).fold(Felt::ZERO, |sum, g| {
                sum + (0..mvm_blakeg::BYTES_PER_WORD).fold(Felt::ZERO, |word, byte| {
                    word + Felt::new_unchecked(1 << (8 * byte))
                        * mvm.rows[row + 1][mvm_blakeg::g_bd_rot_slot_col(g, byte, 0)]
                })
            });
            let stored_rotation_sum = (0..mvm_blakeg::NUM_G).fold(Felt::ZERO, |sum, g| {
                sum + (0..mvm_blakeg::BYTES_PER_WORD).fold(Felt::ZERO, |word, byte| {
                    match mvm_blakeg::g_bd_rot_result_col(g, byte) {
                        Some(col) => word + mvm.rows[row][col],
                        None => word,
                    }
                })
            });
            assert_eq!(
                pvm.rows[row][g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 2)],
                next_b_sum - stored_rotation_sum,
                "MVM-derived/PVM-stored rotation mismatch in case {case}, row {row}",
            );

            assert_eq!(
                &pvm.rows[row][G_K2_BASE_COL..G_K2_BASE_COL + 4],
                &mvm.rows[row][mvm_blakeg::G_K2_BASE_COL..mvm_blakeg::G_K2_BASE_COL + 4],
                "MVM/PVM carry mismatch in case {case}, row {row}",
            );

            for g in 0..4 {
                let pack_slot_field = |column: fn(usize, usize, usize) -> usize, field| {
                    (0..4).fold(Felt::ZERO, |value, byte| {
                        value
                            + Felt::new_unchecked(1 << (8 * byte))
                                * mvm.rows[row][column(g, byte, field)]
                    })
                };
                let a_new = pack_slot_field(mvm_blakeg::g_ac_byte_slot_col, 1);
                let b = pack_slot_field(mvm_blakeg::g_bd_rot_slot_col, 0);
                let msg = mvm.rows[row][mvm_blakeg::g_msg_word_col(g)];
                let k3 = mvm.rows[row][mvm_blakeg::g_k3_col(g)];
                let pvm_k3 = pvm.rows[row][G_K3_BIT0_BASE_COL + g]
                    + Felt::from_u8(2) * pvm.rows[row][G_K3_BIT1_BASE_COL + g];
                assert_eq!(pvm_k3, k3, "MVM/PVM k3 mismatch in case {case}, row {row}, G {g}");
                assert_eq!(
                    pvm.rows[row][G_A_BASE_COL + g],
                    a_new + TWO_POW_32 * k3 - b - msg,
                    "MVM reconstruction of PVM a input failed in case {case}, row {row}, G {g}",
                );

                let c_new = pack_slot_field(mvm_blakeg::g_bd_rot_slot_col, 1);
                let xor_word = (0..4).fold(0_u32, |word, byte| {
                    let base = mvm_blakeg::g_ac_byte_slot_col(g, byte, 0);
                    let lhs = mvm.rows[row][base].as_canonical_u64() as u8;
                    let rhs = mvm.rows[row][base + 1].as_canonical_u64() as u8;
                    word | (u32::from(lhs ^ rhs) << (8 * byte))
                });
                let first_rotation = if row % 2 == 0 { 16 } else { 8 };
                let d_new = Felt::from_u32(xor_word.rotate_right(first_rotation));
                let k2 = mvm.rows[row][mvm_blakeg::G_K2_BASE_COL + g];
                assert_eq!(
                    pvm.rows[row][G_C_BASE_COL + g],
                    c_new + TWO_POW_32 * k2 - d_new,
                    "MVM reconstruction of PVM c input failed in case {case}, row {row}, G {g}",
                );
            }
        }

        for footer in 0..FOOTER_ROWS {
            let row = FOOTER_START + footer;
            for col in 0..F_HIN_SLOT_BASE_COL {
                assert_eq!(
                    pvm.rows[row][col], mvm.rows[row][col],
                    "MVM/PVM shared footer cell mismatch in case {case}, footer {footer}, column {col}",
                );
            }

            for idx in 0..2 * footer {
                assert_eq!(
                    pvm.rows[row][F_R_BASE_COL + idx],
                    mvm.rows[row][mvm_blakeg::footer_r_col(footer, idx)],
                    "MVM/PVM carried R mismatch in case {case}, footer {footer}, field {idx}",
                );
            }
            for pair in 0..2 {
                let lo = mvm.rows[row][mvm_blakeg::footer_msg_word_col(2 * pair)];
                let hi = mvm.rows[row][mvm_blakeg::footer_msg_word_col(2 * pair + 1)];
                assert_eq!(
                    pvm.rows[row][F_R_BASE_COL + 2 * footer + pair],
                    lo + TWO_POW_32 * hi,
                    "MVM/PVM current R mismatch in case {case}, footer {footer}, pair {pair}",
                );
            }

            for idx in 0..=footer {
                assert_eq!(
                    pvm.rows[row][F_D_BASE_COL + idx],
                    mvm.rows[row][mvm_blakeg::footer_interface_tail_col(idx)],
                    "MVM/PVM output field mismatch in case {case}, footer {footer}, field {idx}",
                );
            }
            for idx in 0..footer_future_w_indices(footer).len() {
                assert_eq!(
                    pvm.rows[row][F_FUTURE_W_BASE_COL + idx],
                    mvm.rows[row][mvm_blakeg::footer_future_w_col(footer, idx)],
                    "MVM/PVM future-state mismatch in case {case}, footer {footer}, field {idx}",
                );
            }

            for pair in 0..2 {
                assert_eq!(
                    pvm.rows[row][F_R_CANON_INV_BASE_COL + pair],
                    mvm.rows[row][mvm_blakeg::F_R_CANON_INV_BASE_COL + pair],
                    "MVM/PVM R inverse mismatch in case {case}, footer {footer}, pair {pair}",
                );
                assert_eq!(
                    pvm.rows[row][F_R_CANON_Z_BASE_COL + pair],
                    mvm.rows[row][mvm_blakeg::F_R_CANON_Z_BASE_COL + pair],
                    "MVM/PVM R zero flag mismatch in case {case}, footer {footer}, pair {pair}",
                );
            }
            assert_eq!(
                pvm.rows[row][F_C_CANON_INV_COL],
                mvm.rows[row][mvm_blakeg::F_C_CANON_INV_COL],
                "MVM/PVM CV inverse mismatch in case {case}, footer {footer}",
            );
            assert_eq!(
                pvm.rows[row][F_C_CANON_Z_COL],
                mvm.rows[row][mvm_blakeg::F_C_CANON_Z_COL],
                "MVM/PVM CV zero flag mismatch in case {case}, footer {footer}",
            );
            assert_eq!(
                pvm.rows[row][F_COMPRESSION_CYCLE_ID_COL],
                mvm.rows[row][mvm_blakeg::F_COMPRESSION_CYCLE_ID_COL],
                "MVM/PVM cycle ID mismatch in case {case}, footer {footer}",
            );

            for idx in 0..=footer {
                let expected =
                    Felt::from_u32(cv[2 * idx]) + TWO_POW_32 * Felt::from_u32(cv[2 * idx + 1]);
                assert_eq!(
                    pvm.rows[row][F_C_BASE_COL + idx],
                    expected,
                    "PVM packed CV mismatch in case {case}, footer {footer}, field {idx}",
                );
            }
        }
    }
}

#[test]
fn production_pvm_sources_do_not_import_mvm_blakeg_implementation() {
    fn visit_rust_sources(path: &Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(path).expect("read PVM Eidos source directory") {
            let path = entry.expect("read PVM Eidos source entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                visit_rust_sources(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    visit_rust_sources(&root, &mut files);
    assert!(!files.is_empty(), "PVM Eidos source inventory must not be empty");

    for path in files {
        let source = fs::read_to_string(&path).expect("read PVM Eidos source");
        let compact: String = source.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
        let miden_air_imports = compact.split(';').filter_map(|statement| {
            statement.rfind("usemiden_air").map(|start| &statement[start..])
        });

        for import in miden_air_imports {
            for forbidden in [
                "blakeg_compression",
                "BlakeGCompressionCols",
                "NUM_BLAKEG_COMPRESSION_COLS",
                "generate_felt_trace_block",
            ] {
                assert!(
                    !import.contains(forbidden),
                    "{} imports the MVM BlakeG implementation through `{import}`",
                    path.display(),
                );
            }
        }
        for forbidden in [
            "miden_air::trace::blakeg_compression",
            "miden_air::constraints::blakeg_compression",
            "miden_air::blakeg_compression",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} imports the MVM BlakeG implementation through {forbidden}",
                path.display(),
            );
        }
    }
}

#[test]
fn interning_reuses_logical_span_and_tallies_multiplicity() {
    let mut requires = EidosRequires::new();
    let first = requires.require_absorption(EidosCap::chunk(), vec![block(7), block(17)]);
    let second = requires.require_absorption(EidosCap::chunk(), vec![block(7), block(17)]);
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.head(), second.head());
    assert_eq!(first.tail(), second.tail());
    assert_eq!(requires.total_cycles(), 2);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn padding_cycle_cannot_emit_unproved_payload() {
    let mut requires = EidosRequires::new();
    let and = requires.require_absorption(EidosCap::and(), [block(1)]);
    let generic = requires.require_absorption(EidosCap::keccak256_assertion(8), [block(10)]);
    requires.require_digest(and.digest);
    requires.require_digest(generic.digest);
    let mut compression = generate_traces(requires).compression;
    // Three real cycles round to four. A padding cycle cannot impersonate a payload cycle.
    let padding_row = 3 * BLAKEG_COMPRESSION_CYCLE_LEN;
    compression.values[padding_row * NUM_MAIN_COLS + COL_IS_PAYLOAD] = Felt::ONE;
    crate::tests::check_local(BlakeGCompressionAir, &compression);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn continuation_payload_id_must_follow_the_chain() {
    let mut requires = EidosRequires::new();
    let chunks = requires.require_absorption(EidosCap::chunk(), [block(1), block(11)]);
    requires.require_digest(chunks.digest);
    let mut compression = generate_traces(requires).compression;
    for row in BLAKEG_COMPRESSION_CYCLE_LEN..2 * BLAKEG_COMPRESSION_CYCLE_LEN {
        compression.values[row * NUM_MAIN_COLS + COL_ABSORPTION_ID] += Felt::ONE;
    }
    crate::tests::check_local(BlakeGCompressionAir, &compression);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn native_blakeg_core_witness_is_not_a_free_bridge_input() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(EidosCap::and(), [block(1)]);
    requires.require_digest(output.digest);
    let mut compression = generate_traces(requires).compression;

    let row = FOOTER_START + 1;
    compression.values[row * NUM_MAIN_COLS + F_R_BASE_COL + 2] += Felt::ONE;
    crate::tests::check_local(BlakeGCompressionAir, &compression);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_blakeg_cycles_must_carry_the_previous_chaining_word() {
    let second_block = block(11);
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(EidosCap::chunk(), [block(1), second_block]);
    requires.require_digest(output.digest);
    let mut compression = generate_traces(requires).compression;

    // Replace the second compression with a separately valid native BlakeG cycle using a forged
    // input CV, and keep its cycle-constant PVM metadata self-consistent. The only broken fact is
    // the physical carry from cycle 0's BlakeG output into cycle 1's BlakeG input.
    let mut forged_cv: [Felt; 4] = core::array::from_fn(|i| {
        compression.values[BLAKEG_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS + COL_CV_IN_BEGIN + i]
    });
    forged_cv[0] += Felt::ONE;
    let (rate0, rate1) = second_block;
    let mut state = [Felt::ZERO; 12];
    state[..4].copy_from_slice(&rate0);
    state[4..8].copy_from_slice(&rate1);
    state[8..].copy_from_slice(&forged_cv);
    let forged = generate_felt_trace_block_with_cycle_id(
        unpack_felts::<16>(&state[..8]),
        unpack_felts::<8>(&forged_cv),
        1,
    );

    for row in 0..BLAKEG_COMPRESSION_CYCLE_LEN {
        let dst = (BLAKEG_COMPRESSION_CYCLE_LEN + row) * NUM_MAIN_COLS;
        compression.values[dst..dst + NUM_BLAKEG_COMPRESSION_COLS]
            .copy_from_slice(&forged.rows[row]);
        compression.values[dst + COL_CV_IN_BEGIN..dst + COL_CV_IN_BEGIN + 4]
            .copy_from_slice(&forged_cv);
    }

    crate::tests::check_local(BlakeGCompressionAir, &compression);
}
