use alloc::vec::Vec;

use miden_core::field::{Field, PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::{
    air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
    matrix::RowMajorMatrix,
};

use super::{
    constraints::{enforce_footer_rows, enforce_fused_rows},
    layout::*,
    model::initial_working_state,
    periodic::get_periodic_column_values,
    schedule::BLAKEG_IV,
    selectors::BlakeGSelectors,
    trace::{
        BlakeGFeltRow, TraceMode, generate_felt_trace_block,
        generate_felt_trace_block_with_cycle_id,
        generate_felt_trace_block_with_initial_state_for_test, rewrite_felt_footer_for_test,
    },
};
use crate::Felt;

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,
    preprocessed_window: RowWindow<'static, Felt>,
    is_first_row: Felt,
    is_last_row: Felt,
}

impl ConstraintEvalBuilder {
    fn new(
        local: &[Felt; NUM_COLS],
        next: &[Felt; NUM_COLS],
        periodic_values: Vec<Felt>,
        row_idx: usize,
        trace_len: usize,
    ) -> Self {
        let mut main = Felt::zero_vec(2 * NUM_COLS);
        main[..NUM_COLS].copy_from_slice(local);
        main[NUM_COLS..].copy_from_slice(next);

        Self {
            main: RowMajorMatrix::new(main, NUM_COLS),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2], 1),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values,
            evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            is_first_row: Felt::from_bool(row_idx == 0),
            is_last_row: Felt::from_bool(row_idx + 1 == trace_len),
        }
    }
}

impl AirBuilder for ConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type PreprocessedWindow = RowWindow<'static, Felt>;
    type MainWindow = RowMajorMatrix<Felt>;
    type PublicVar = Felt;
    type PeriodicVar = Felt;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition(&self) -> Self::Expr {
        Felt::ONE - self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "BlakeG 32-row tests use two-row transition windows");
        self.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &[]
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

impl ExtensionBuilder for ConstraintEvalBuilder {
    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    fn assert_zero_ext<I>(&mut self, _x: I)
    where
        I: Into<Self::ExprEF>,
    {
        panic!("BlakeG base-constraint tests must not emit extension-field constraints");
    }
}

impl PermutationAirBuilder for ConstraintEvalBuilder {
    type MP = RowMajorMatrix<QuadFelt>;
    type RandomVar = QuadFelt;
    type PermutationVar = QuadFelt;

    fn permutation(&self) -> Self::MP {
        self.aux.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.permutation_values
    }
}

fn test_block() -> [u32; 16] {
    [
        0x0000_0001,
        0x0000_0002,
        0x0000_0003,
        0x0000_0004,
        0x8000_0005,
        0x0000_0006,
        0x0000_0007,
        0x0000_0008,
        0x0000_0009,
        0x8000_000a,
        0x8000_000b,
        0x0000_000c,
        0x0000_000d,
        0x0000_000e,
        0x0000_000f,
        0x0000_0010,
    ]
}

fn test_h() -> [u32; 8] {
    [
        0x0000_0021,
        0x8000_0001,
        0x8000_0022,
        0x0000_0043,
        0x0000_0023,
        0x0000_0065,
        0x0000_0024,
        0x0000_0087,
    ]
}

fn alternate_test_block() -> [u32; 16] {
    test_block().map(|word| word.wrapping_add(0x0101_0101))
}

fn alternate_test_h() -> [u32; 8] {
    test_h().map(|word| word.wrapping_add(0x0010_0010))
}

fn periodic_row(row_idx: usize) -> Vec<Felt> {
    get_periodic_column_values()
        .iter()
        .map(|column| column[row_idx % column.len()])
        .collect()
}

fn eval_fused_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, BLOCK_PERIOD);
    let selectors = BlakeGSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    builder.evaluations
}

fn eval_footer_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, BLOCK_PERIOD);
    let selectors = BlakeGSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.evaluations
}

fn eval_main_row(trace: &[BlakeGFeltRow], row_idx: usize) -> Vec<Felt> {
    let next_idx = (row_idx + 1).min(trace.len() - 1);
    let local = &trace[row_idx];
    let next = &trace[next_idx];
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, trace.len());
    let selectors = BlakeGSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.evaluations
}

fn two_cycle_trace(second_cycle_id: u64) -> Vec<BlakeGFeltRow> {
    let first =
        generate_felt_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let second = generate_felt_trace_block_with_cycle_id(
        alternate_test_block(),
        alternate_test_h(),
        second_cycle_id,
        TraceMode::Compression,
    );
    first.rows.into_iter().chain(second.rows).collect()
}

fn assert_all_zero(values: &[Felt]) {
    assert!(
        values.iter().all(|value| *value == Felt::ZERO),
        "expected all constraints to vanish"
    );
}

fn assert_any_nonzero(values: &[Felt]) {
    assert!(values.iter().any(|value| *value != Felt::ZERO), "expected a failing constraint");
}

fn footer_xor_word_value(row: &BlakeGFeltRow, slot_base: usize) -> u32 {
    let bytes = core::array::from_fn(|byte| {
        let base = footer_xor_slot_col(slot_base + byte, 0);
        let lhs = row[base].as_canonical_u64() as u8;
        let rhs = row[base + 1].as_canonical_u64() as u8;
        lhs ^ rhs
    });
    u32::from_le_bytes(bytes)
}

fn rewrite_footer_d_prefix(trace: &mut [BlakeGFeltRow], footer: usize) {
    let origin = FOOTER_START + footer;
    let row = &trace[origin];
    let out_even = footer_xor_word_value(row, F_OUTPUT_EVEN_SLOT_BASE);
    let out_odd = footer_xor_word_value(row, F_OUTPUT_ODD_SLOT_BASE);
    let top_bit = row[F_TOP_BIT_SLOT_BASE_COL + 2].as_canonical_u64() as u32;
    let masked_odd = out_odd - (top_bit << 24);
    let packed = Felt::from_u32(out_even) + Felt::from_u64(1 << 32) * Felt::from_u32(masked_odd);

    for row in trace.iter_mut().skip(origin) {
        row[F_D_BASE_COL + footer] = packed;
    }
}

#[test]
fn air_constraint_mutation_matrix_rejects_each_witness_family() {
    let cases = [
        ("message index", 0, g_msg_slot_col(0, 0), 0),
        ("message word", 0, g_msg_slot_col(0, 1), 0),
        ("message cycle id", 0, g_msg_slot_col(1, 2), 0),
        ("input a", 0, G_A_BASE_COL, 0),
        ("input c / IV", 0, G_C_BASE_COL, 0),
        ("k3 bit 0", 0, G_K3_BIT0_BASE_COL, 0),
        ("k3 bit 1", 0, G_K3_BIT1_BASE_COL, 0),
        ("k2", 0, G_K2_BASE_COL, 0),
        ("AC lhs", 0, g_ac_byte_slot_col(0, 0, 0), 0),
        ("AC rhs", 0, g_ac_byte_slot_col(0, 0, 1), 0),
        ("AC and", 0, g_ac_byte_slot_col(0, 0, 2), 0),
        ("BD lhs", 0, g_bd_rot_slot_col(0, 0, 0), 0),
        ("BD rhs", 0, g_bd_rot_slot_col(0, 0, 1), 0),
        ("BD contribution", 0, g_bd_rot_slot_col(0, 0, 2), 0),
        ("fused transition", 1, G_A_BASE_COL, 0),
        ("footer bridge", FOOTER_START, F_FUTURE_W_BASE_COL, FUSED_G_ROWS - 1),
        ("footer xor duplicate", FOOTER_START, footer_xor_slot_col(8, 1), FOOTER_START),
        ("footer top byte", FOOTER_START, F_TOP_BIT_SLOT_BASE_COL, FOOTER_START),
        ("footer HIN tag", FOOTER_START, F_HIN_SLOT_BASE_COL, FOOTER_START),
        ("footer HIN value", FOOTER_START, F_HIN_SLOT_BASE_COL + 1, FOOTER_START),
        (
            "footer message index",
            FOOTER_START,
            footer_msg_word_slot_col(0, 0),
            FOOTER_START,
        ),
        (
            "footer message cycle id",
            FOOTER_START,
            footer_msg_word_slot_col(0, 2),
            FOOTER_START,
        ),
        ("footer range limb", FOOTER_START, footer_range_slot_col(0, 0), FOOTER_START),
        ("footer range padding", FOOTER_START, footer_range_slot_col(0, 1), FOOTER_START),
        ("footer R", FOOTER_START, F_R_BASE_COL, FOOTER_START),
        ("footer C", FOOTER_START, F_C_BASE_COL, FOOTER_START),
        ("footer D", FOOTER_START, F_D_BASE_COL, FOOTER_START),
        ("footer future-W tail", FOOTER_START, F_FUTURE_W_BASE_COL + 11, FOOTER_START),
        ("footer R canonical inverse", FOOTER_START, F_R_CANON_INV_BASE_COL, FOOTER_START),
        ("footer R canonical zero", FOOTER_START, F_R_CANON_Z_BASE_COL, FOOTER_START),
        ("footer C canonical inverse", FOOTER_START, F_C_CANON_INV_COL, FOOTER_START),
        ("footer C canonical zero", FOOTER_START, F_C_CANON_Z_COL, FOOTER_START),
        (
            "footer multiplicity transition",
            FOOTER_START + 1,
            F_COMPRESSION_MULTIPLICITY_COL,
            FOOTER_START,
        ),
        ("footer mode", FOOTER_START, F_MODE_COL, FOOTER_START),
        ("footer clk", FOOTER_START, F_CLK_COL, FOOTER_START),
        (
            "footer cycle id transition",
            FOOTER_START + 1,
            F_COMPRESSION_CYCLE_ID_COL,
            FOOTER_START,
        ),
    ];

    for (name, mutated_row, mutated_col, evaluated_row) in cases {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        trace.rows[mutated_row][mutated_col] += Felt::ONE;
        assert!(
            eval_main_row(&trace.rows, evaluated_row)
                .iter()
                .any(|&value| value != Felt::ZERO),
            "mutation {name:?} was not rejected",
        );
    }
}

#[test]
fn air_constraints_accept_two_consecutive_compression_cycles() {
    let trace = two_cycle_trace(1);

    for row in 0..trace.len() {
        assert_all_zero(&eval_main_row(&trace, row));
    }
}

#[test]
fn air_constraints_pin_first_compression_cycle_id_to_zero() {
    let mut trace = two_cycle_trace(2);
    for row in trace.iter_mut().take(FUSED_G_ROWS) {
        for g in 0..NUM_G {
            row[g_msg_slot_col(g, 2)] = Felt::ONE;
        }
    }
    for row in trace.iter_mut().take(BLOCK_PERIOD).skip(FOOTER_START) {
        row[F_COMPRESSION_CYCLE_ID_COL] = Felt::ONE;
        for word_slot in 0..F_MSG_WORD_SLOTS {
            row[footer_msg_word_slot_col(word_slot, 2)] = Felt::ONE;
        }
    }

    assert_any_nonzero(&eval_main_row(&trace, 0));
}

#[test]
fn air_constraints_reject_inconsistent_fused_cycle_id() {
    let mut trace = two_cycle_trace(1);
    trace[5][g_msg_slot_col(1, 2)] += Felt::ONE;

    assert_any_nonzero(&eval_main_row(&trace, 5));
}

#[test]
fn air_constraints_pin_inner_fused_cycle_id_constancy() {
    let mut trace = two_cycle_trace(1);

    // This is the original two-cycle forgery with every per-row ID equality left intact: most of
    // cycle 0 borrows cycle 1's ID, while row 0, row 27, and the footer retain cycle 0's ID. Only the
    // cross-row cycle-ID constraint can reject the two discontinuities.
    for row in trace.iter_mut().take(FUSED_G_ROWS - 1).skip(1) {
        for g in 0..NUM_G {
            row[g_msg_slot_col(g, 2)] = Felt::ONE;
        }
    }

    for row_idx in 0..trace.len() {
        let rejected = eval_main_row(&trace, row_idx).iter().any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            matches!(row_idx, 0 | 26),
            "unexpected constraint result on forged row {row_idx}",
        );
    }
}

#[test]
fn air_constraints_reject_inconsistent_footer_cycle_id() {
    let mut trace = two_cycle_trace(1);
    trace[FOOTER_START][footer_msg_word_slot_col(1, 2)] += Felt::ONE;

    assert_any_nonzero(&eval_main_row(&trace, FOOTER_START));
}

#[test]
fn air_constraints_bind_fused_and_footer_cycle_ids() {
    let mut trace = two_cycle_trace(1);
    trace[FOOTER_START][F_COMPRESSION_CYCLE_ID_COL] += Felt::ONE;
    for word_slot in 0..F_MSG_WORD_SLOTS {
        trace[FOOTER_START][footer_msg_word_slot_col(word_slot, 2)] += Felt::ONE;
    }

    assert_any_nonzero(&eval_main_row(&trace, FUSED_G_ROWS - 1));
}

#[test]
fn air_constraints_require_consecutive_cycle_ids() {
    let trace = two_cycle_trace(2);

    assert_any_nonzero(&eval_main_row(&trace, BLOCK_PERIOD - 1));
}

#[test]
fn air_fused_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for row in 0..FUSED_G_ROWS {
        assert_all_zero(&eval_fused_row(&trace.rows[row], &trace.rows[row + 1], row));
    }
}

#[test]
fn air_fused_constraints_reject_bad_message_index() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_msg_slot_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_reject_bad_carry() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_K2_BASE_COL] = Felt::new_unchecked(2);

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_pin_k3_low_bit_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let (row_idx, g) = (0..FUSED_G_ROWS)
        .flat_map(|row_idx| (0..NUM_G).map(move |g| (row_idx, g)))
        .find(|&(row_idx, g)| {
            trace.rows[row_idx][G_K3_BIT0_BASE_COL + g] == Felt::ZERO
                && trace.rows[row_idx][G_K3_BIT1_BASE_COL + g] == Felt::ONE
        })
        .expect("test trace must contain a carry of two");

    // Preserve k3 = bit0 + 2 * bit1 while making only bit0 non-boolean.
    trace.rows[row_idx][G_K3_BIT0_BASE_COL + g] = Felt::TWO;
    trace.rows[row_idx][G_K3_BIT1_BASE_COL + g] = Felt::ZERO;

    assert_any_nonzero(&eval_fused_row(&trace.rows[row_idx], &trace.rows[row_idx + 1], row_idx));
}

#[test]
fn air_fused_constraints_pin_k3_high_bit_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let (row_idx, g) = (0..FUSED_G_ROWS)
        .flat_map(|row_idx| (0..NUM_G).map(move |g| (row_idx, g)))
        .find(|&(row_idx, g)| {
            trace.rows[row_idx][G_K3_BIT0_BASE_COL + g] == Felt::ONE
                && trace.rows[row_idx][G_K3_BIT1_BASE_COL + g] == Felt::ZERO
        })
        .expect("test trace must contain a carry of one");

    // Preserve k3 = 1 while making only bit1 non-boolean.
    trace.rows[row_idx][G_K3_BIT0_BASE_COL + g] = Felt::ZERO;
    trace.rows[row_idx][G_K3_BIT1_BASE_COL + g] = Felt::TWO.inverse();

    assert_any_nonzero(&eval_fused_row(&trace.rows[row_idx], &trace.rows[row_idx + 1], row_idx));
}

#[test]
fn air_fused_constraints_exclude_k3_carry_of_three() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let row_idx = FUSED_G_ROWS - 1;
    let g = 0;
    let next = trace.rows[row_idx + 1];
    let row = &mut trace.rows[row_idx];
    let original_k3 = row[G_K3_BIT0_BASE_COL + g] + Felt::TWO * row[G_K3_BIT1_BASE_COL + g];
    let delta = (original_k3 - Felt::from_u32(3)) * Felt::from_u64(1 << 32);

    // Make both carry bits one and adjust the test-only byte witnesses so the addition and XOR
    // equations still vanish. Since the last fused row has no fused-row transition, only the
    // constraint excluding the impossible carry value three can reject this local witness.
    row[G_K3_BIT0_BASE_COL + g] = Felt::ONE;
    row[G_K3_BIT1_BASE_COL + g] = Felt::ONE;
    row[g_ac_byte_slot_col(g, 0, 1)] += delta;
    row[g_ac_byte_slot_col(g, 0, 2)] += delta * Felt::TWO.inverse();

    assert_any_nonzero(&eval_fused_row(row, &next, row_idx));
}

#[test]
fn air_fused_constraints_pin_k2_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let row_idx = FUSED_G_ROWS - 1;
    let g = 0;
    let next = trace.rows[row_idx + 1];
    let row = &mut trace.rows[row_idx];
    let original_k2 = row[G_K2_BASE_COL + g];
    let delta = (original_k2 - Felt::TWO) * Felt::from_u64(1 << 32);

    // Preserve the second addition equation while making k2 non-boolean. The last fused row has
    // no fused-row transition, so no other main-trace constraint sees the adjusted c_new witness.
    row[G_K2_BASE_COL + g] = Felt::TWO;
    row[g_bd_rot_slot_col(g, 0, 1)] += delta;

    assert_any_nonzero(&eval_fused_row(row, &next, row_idx));
}

#[test]
fn air_fused_constraints_reject_bad_rotation_payload() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_bd_rot_slot_col(0, 0, 2)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_reject_bad_initial_iv() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_C_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_pin_both_initial_iv_halves() {
    for iv_idx in [0, 4] {
        let mut initial_v = initial_working_state(test_h());
        initial_v[8 + iv_idx] = BLAKEG_IV[iv_idx] ^ 1;
        let trace = generate_felt_trace_block_with_initial_state_for_test(
            test_block(),
            test_h(),
            initial_v,
            TraceMode::Compression,
        );

        for row_idx in 0..BLOCK_PERIOD {
            let rejected =
                eval_main_row(&trace.rows, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == 0,
                "IV word {iv_idx} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_fused_constraints_reject_bad_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[1][G_A_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_constraints_pin_all_four_fused_transition_families() {
    let original = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let alternate = generate_felt_trace_block(
        alternate_test_block(),
        alternate_test_h(),
        TraceMode::Compression,
    );

    for boundary in 0..FUSED_G_ROWS_PER_ROUND {
        let mut forged = original.rows;

        // Splice four locally valid rows from another compression. The only broken equations are
        // the two boundary transitions, which belong to the same row family four rows apart. A
        // source mutation deleting that transition family therefore makes this case fully valid.
        forged[boundary + 1..boundary + 5]
            .copy_from_slice(&alternate.rows[boundary + 1..boundary + 5]);

        for row_idx in 0..BLOCK_PERIOD {
            let rejected = eval_main_row(&forged, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == boundary || row_idx == boundary + FUSED_G_ROWS_PER_ROUND,
                "transition-family {boundary} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    for row in FUSED_G_ROWS - 1..BLOCK_PERIOD {
        let next = row.saturating_add(1).min(BLOCK_PERIOD - 1);
        assert_all_zero(&eval_footer_row(&trace.rows[row], &trace.rows[next], row));
    }
}

#[test]
fn air_footer_constraints_reject_bad_bridge() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_FUTURE_W_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FUSED_G_ROWS - 1],
        &trace.rows[FOOTER_START],
        FUSED_G_ROWS - 1,
    ));
}

#[test]
fn air_footer_constraints_pin_all_four_direct_output_bridges() {
    for word_idx in [0, 1, 8, 9] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        let mut forged_final_v = trace.final_v;
        forged_final_v[word_idx] ^= 1;
        rewrite_felt_footer_for_test(
            &mut trace.rows,
            test_block(),
            test_h(),
            forged_final_v,
            TraceMode::Compression,
        );

        for row_idx in 0..BLOCK_PERIOD {
            let rejected =
                eval_main_row(&trace.rows, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == FUSED_G_ROWS - 1,
                "final word {word_idx} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_reject_bad_message_limb() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_range_slot_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_reject_bad_hin_binding() {
    for col in F_HIN_SLOT_BASE_COL..F_HIN_SLOT_BASE_COL + 3 {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        trace.rows[FOOTER_START][col] += Felt::ONE;

        assert_any_nonzero(&eval_footer_row(
            &trace.rows[FOOTER_START],
            &trace.rows[FOOTER_START + 1],
            FOOTER_START,
        ));
    }
}

#[test]
fn air_footer_constraints_pin_r_c_and_d_payload_packings() {
    for footer in 0..FOOTER_ROWS {
        let origin = FOOTER_START + footer;
        let columns = [
            F_R_BASE_COL + 2 * footer,
            F_R_BASE_COL + 2 * footer + 1,
            F_C_BASE_COL + footer,
            F_D_BASE_COL + footer,
        ];

        for col in columns {
            let mut trace =
                generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

            // Keep every subsequent copy consistent so that only the local packing equation at
            // the value's introduction row rejects the witness.
            for row in trace.rows.iter_mut().skip(origin) {
                row[col] += Felt::ONE;
            }

            for row_idx in FOOTER_START..BLOCK_PERIOD {
                let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
                let rejected =
                    eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
                        .iter()
                        .any(|&value| value != Felt::ZERO);
                assert_eq!(
                    rejected,
                    row_idx == origin,
                    "column {col} had an unexpected result on footer row {row_idx}",
                );
            }
        }
    }
}

#[test]
fn air_footer_constraints_pin_output_high_word_bindings() {
    for slot_base in [F_OUTPUT_EVEN_SLOT_BASE, F_OUTPUT_ODD_SLOT_BASE] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        let origin = FOOTER_START;
        let byte_base = footer_xor_slot_col(slot_base, 0);
        let lhs = trace.rows[origin][byte_base].as_canonical_u64() as u8;
        let rhs = (trace.rows[origin][byte_base + 1].as_canonical_u64() as u8) ^ 1;
        trace.rows[origin][byte_base + 1] = Felt::from_u8(rhs);
        trace.rows[origin][byte_base + 2] = Felt::from_u8(lhs & rhs);
        rewrite_footer_d_prefix(&mut trace.rows, 0);

        for row_idx in FOOTER_START..BLOCK_PERIOD {
            let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
            let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
                .iter()
                .any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == origin,
                "output slot {slot_base} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_pin_top_bit_mask() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let footer = (0..FOOTER_ROWS)
        .find(|&footer| {
            trace.rows[FOOTER_START + footer][F_TOP_BIT_SLOT_BASE_COL + 2] == Felt::from_u8(128)
        })
        .expect("test vector must exercise an odd output word with its top bit set");
    let origin = FOOTER_START + footer;

    trace.rows[origin][F_TOP_BIT_SLOT_BASE_COL + 1] = Felt::ZERO;
    trace.rows[origin][F_TOP_BIT_SLOT_BASE_COL + 2] = Felt::ZERO;
    rewrite_footer_d_prefix(&mut trace.rows, footer);

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx == origin,
            "top-bit-mask forgery had an unexpected result on row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_future_w_shift() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_FUTURE_W_BASE_COL] += Felt::ONE;

    // Evaluate F0 directly, without the last-fused-to-F0 bridge, to isolate the footer queue shift.
    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_reject_bad_canonicality() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_C_CANON_Z_COL] = Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_pin_noncanonical_pair_rejection() {
    let mut block = test_block();
    block[0] = 7;
    block[1] = u32::MAX;
    let trace = generate_felt_trace_block(block, test_h(), TraceMode::Compression);
    let evaluations =
        eval_footer_row(&trace.rows[FOOTER_START], &trace.rows[FOOTER_START + 1], FOOTER_START);

    // `(7, u32::MAX)` packs to 6 modulo the Goldilocks prime, colliding with `(6, 0)`. All other
    // footer constraints accept this honest BlakeG witness; only `z * lo = 0` rejects the
    // non-canonical representation.
    assert_eq!(evaluations.iter().filter(|&&value| value != Felt::ZERO).count(), 1);
}

#[test]
fn air_footer_constraints_pin_mode_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    for row in trace.rows.iter_mut().skip(FOOTER_START) {
        row[F_MODE_COL] = Felt::from_u8(2);
        row[F_COMPRESSION_MULTIPLICITY_COL] = Felt::ZERO;
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let evaluations = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx);
        assert_eq!(
            evaluations.iter().filter(|&&value| value != Felt::ZERO).count(),
            1,
            "mode booleanity was not isolated on footer row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_pin_mode_persistence() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    for (footer, row) in trace.rows.iter_mut().skip(FOOTER_START).enumerate() {
        row[F_MODE_COL] = Felt::from_bool(footer < FOOTER_ROWS - 1);
        row[F_COMPRESSION_MULTIPLICITY_COL] = Felt::ZERO;
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx == BLOCK_PERIOD - 2,
            "mode-persistence forgery had an unexpected result on row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_footer_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START + 1][F_R_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_pin_c_and_d_persistence() {
    for col in [F_C_BASE_COL, F_D_BASE_COL] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        for row in trace.rows.iter_mut().skip(FOOTER_START + 1) {
            row[col] += Felt::ONE;
        }

        for row_idx in FOOTER_START..BLOCK_PERIOD {
            let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
            let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
                .iter()
                .any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == FOOTER_START,
                "column {col} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_reject_aead_compression_multiplicity() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    for row in trace.rows.iter_mut().skip(FOOTER_START) {
        row[F_COMPRESSION_MULTIPLICITY_COL] = Felt::ONE;
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let evaluations = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx);
        assert_eq!(
            evaluations.iter().filter(|&&value| value != Felt::ZERO).count(),
            1,
            "AEAD multiplicity was not isolated on footer row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_pin_aead_clk_persistence() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    for (footer, row) in trace.rows.iter_mut().skip(FOOTER_START).enumerate() {
        row[F_CLK_COL] = Felt::from_usize(19 + footer);
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx < BLOCK_PERIOD - 1,
            "AEAD clk persistence had an unexpected result on footer row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_multiplicity_transition() {
    let mut trace = generate_felt_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 2 },
    );
    trace.rows[FOOTER_START + 1][F_COMPRESSION_MULTIPLICITY_COL] = Felt::new_unchecked(3);

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}
