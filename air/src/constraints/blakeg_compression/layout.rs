//! Column layout for the 32-row x 128-column BlakeG AIR.

/// Number of main-trace columns in the BlakeG compression AIR.
pub const NUM_COLS: usize = 128;
pub const AUX_COLS: usize = 24;

pub const ROUNDS: usize = 7;
pub const FUSED_G_ROWS_PER_ROUND: usize = 4;
pub const FUSED_G_ROWS: usize = ROUNDS * FUSED_G_ROWS_PER_ROUND;
pub const FOOTER_ROWS: usize = 4;
pub const BLOCK_PERIOD: usize = FUSED_G_ROWS + FOOTER_ROWS;
pub const FOOTER_START: usize = FUSED_G_ROWS;

pub const NUM_G: usize = 4;
pub const BYTES_PER_WORD: usize = 4;
pub const BYTE_SLOT_WIDTH: usize = 3;
#[cfg(test)]
pub const BYTE_SLOTS_PER_STEP: usize = NUM_G * BYTES_PER_WORD;

// --- Fused G-row layout ----------------------------------------------------

pub const G_AC_BYTE_SLOT_BASE_COL: usize = 0;
pub const G_BD_ROT_SLOT_BASE_COL: usize = 48;
pub const G_MSG_SLOT_BASE_COL: usize = 96;
pub const G_A_BASE_COL: usize = 108;
pub const G_C_BASE_COL: usize = 112;
pub const G_K3_BIT0_BASE_COL: usize = 116;
pub const G_K3_BIT1_BASE_COL: usize = 120;
pub const G_K2_BASE_COL: usize = 124;

// --- Footer-overlay layout -------------------------------------------------

pub const F_XOR_SLOT_BASE_COL: usize = 0;
pub const F_HIGH_EVEN_SLOT_BASE: usize = 0;
pub const F_HIGH_ODD_SLOT_BASE: usize = 4;
pub const F_OUTPUT_EVEN_SLOT_BASE: usize = 8;
pub const F_OUTPUT_ODD_SLOT_BASE: usize = 12;
pub const F_TOP_BIT_SLOT_BASE_COL: usize = 48;
pub const F_HIN_SLOT_BASE_COL: usize = 51;
pub const F_MSG_GROUP_BASE_COL: usize = 54;
pub const F_MSG_WORD_SLOTS: usize = 4;
pub const F_RANGE_SLOTS: usize = 8;
#[cfg(test)]
pub const F_MSG_GROUP_SLOTS: usize = F_MSG_WORD_SLOTS + F_RANGE_SLOTS;
pub const F_R_BASE_COL: usize = 90;
pub const F_C_BASE_COL: usize = 98;
pub const F_D_BASE_COL: usize = 102;
pub const F_FUTURE_W_BASE_COL: usize = 106;
pub const F_FUTURE_W_COLS: usize = 12;
pub const F_FUTURE_W_WORD_INDICES: [usize; F_FUTURE_W_COLS] =
    [2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15];
pub const F_R_CANON_INV_BASE_COL: usize = 118;
pub const F_R_CANON_Z_BASE_COL: usize = 120;
pub const F_C_CANON_INV_COL: usize = 122;
pub const F_C_CANON_Z_COL: usize = 123;
/// Number of controller requests represented by this compression cycle.
///
/// This is intentionally a field-valued count rather than a boolean: identical controller requests
/// may be aggregated into one physical compression. Soundness relies on every controller request
/// being emitted with unit multiplicity and locally tied to a real event; the compression provider
/// then contributes the negated aggregate count.
pub const F_COMPRESSION_MULTIPLICITY_COL: usize = 124;
/// Physical compression-cycle identifier on footer rows.
///
/// The same identifier is stored in field 2 of every fused and footer message-word slot. It is
/// constant over a 32-row cycle and increments between cycles, binding the internal CV and message
/// buses to the physical compression which consumes them.
pub const F_COMPRESSION_CYCLE_ID_COL: usize = 125;
pub const F_MODE_COL: usize = 126;
pub const F_CLK_COL: usize = 127;
pub const F_TOP_BIT_MASK: u8 = 128;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RowKind {
    Ab,
    Cd,
    AbDiag,
    CdDiag,
    Footer(usize),
}

pub const fn row_kind(row: usize) -> RowKind {
    if row < FUSED_G_ROWS {
        match row % FUSED_G_ROWS_PER_ROUND {
            0 => RowKind::Ab,
            1 => RowKind::Cd,
            2 => RowKind::AbDiag,
            _ => RowKind::CdDiag,
        }
    } else if row < BLOCK_PERIOD {
        RowKind::Footer(row - FOOTER_START)
    } else {
        panic!("32-row BlakeG row index must be in 0..32")
    }
}

pub const fn byte_slot_base(base_col: usize, slot: usize) -> usize {
    base_col + BYTE_SLOT_WIDTH * slot
}

pub const fn g_ac_byte_slot_col(g: usize, byte: usize, field: usize) -> usize {
    byte_slot_base(G_AC_BYTE_SLOT_BASE_COL, g * BYTES_PER_WORD + byte) + field
}

pub const fn g_bd_rot_slot_col(g: usize, byte: usize, field: usize) -> usize {
    byte_slot_base(G_BD_ROT_SLOT_BASE_COL, g * BYTES_PER_WORD + byte) + field
}

pub const fn g_msg_slot_col(g: usize, field: usize) -> usize {
    G_MSG_SLOT_BASE_COL + BYTE_SLOT_WIDTH * g + field
}

pub const fn footer_xor_slot_col(slot: usize, field: usize) -> usize {
    byte_slot_base(F_XOR_SLOT_BASE_COL, slot) + field
}

pub const fn footer_msg_word_slot_col(word: usize, field: usize) -> usize {
    F_MSG_GROUP_BASE_COL + BYTE_SLOT_WIDTH * word + field
}

pub const fn footer_range_slot_col(limb: usize, field: usize) -> usize {
    F_MSG_GROUP_BASE_COL + BYTE_SLOT_WIDTH * (F_MSG_WORD_SLOTS + limb) + field
}

pub const fn footer_message_word_index(footer_row: usize, word_slot: usize) -> usize {
    if footer_row >= FOOTER_ROWS {
        panic!("footer row must be in 0..4");
    }
    if word_slot >= F_MSG_WORD_SLOTS {
        panic!("footer message word slot must be in 0..4");
    }
    footer_row * F_MSG_WORD_SLOTS + word_slot
}

pub const fn footer_range_limb_word_index(footer_row: usize, limb: usize) -> usize {
    footer_message_word_index(footer_row, limb / 2)
}

pub const fn footer_range_limb_is_high(limb: usize) -> bool {
    if limb >= F_RANGE_SLOTS {
        panic!("footer range limb must be in 0..8");
    }
    limb % 2 == 1
}

pub fn footer_future_w_indices(footer_row: usize) -> &'static [usize] {
    if footer_row >= FOOTER_ROWS {
        panic!("footer row must be in 0..4");
    }
    &F_FUTURE_W_WORD_INDICES[4 * footer_row..]
}

const _: () = assert!(BLOCK_PERIOD == 32);
const _: () = assert!(F_COMPRESSION_CYCLE_ID_COL + 1 == F_MODE_COL);
const _: () = assert!(F_CLK_COL + 1 == NUM_COLS);
