//! Trace generation for the deferred transcript's 32-row BlakeG compression chiplet.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::ops::Range;

use miden_air::trace::and8_lookup::{
    AND8_LOOKUP_TRACE_HEIGHT, BYTE_LOOKUP_COUNT_LEN, BYTE_LOOKUP_KIND_AND8,
    BYTE_LOOKUP_KIND_BLAKEG_ROT7, BYTE_LOOKUP_KIND_BLAKEG_ROT12, BYTE_LOOKUP_KIND_COUNT,
    BYTE_PAIR_ROWS, NUM_AND8_LOOKUP_COLS, RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL,
    byte_lookup_result,
};
use miden_core::{
    Felt, Word,
    deferred::{DEFERRED_CHUNKS_DOMAIN, DEFERRED_NODE_DOMAIN, DEFERRED_ROOT_DOMAIN},
    field::{Field, PrimeCharacteristicRing, PrimeField64},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;

use super::blakeg::{
    layout::{
        BLOCK_PERIOD as BLAKEG_COMPRESSION_CYCLE_LEN, NUM_COLS as NUM_BLAKEG_COMPRESSION_COLS,
    },
    trace::{
        BlakeGByteLookup, ByteLookupRecorder, write_felt_trace_block_into_zeroed_with_lookups,
    },
};
use crate::{
    relations::ProvideMult,
    transcript::eidos::{
        COL_ABSORPTION_ID, COL_CAP_BEGIN, COL_CV_IN_BEGIN, COL_IN_MULTIPLICITY, COL_IS_ABSORB,
        COL_IS_AND, COL_IS_CHUNKS, COL_IS_GENERIC, COL_IS_HEAD, COL_IS_OUTPUT, COL_IS_PAYLOAD,
        COL_OUT_MULTIPLICITY, COL_REMAINING, COL_REMAINING_INV, NUM_MAIN_COLS,
        digest::{EidosCap, EidosDigest},
    },
};

// ABSORPTION OUTPUT
// ================================================================================================

/// Logical input-block identifier used by the surrounding transcript relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsorptionId(u32);

impl AbsorptionId {
    pub fn as_u32(self) -> u32 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn forged(absorption_id: u32) -> Self {
        Self(absorption_id)
    }
}

/// Contiguous logical input-block span occupied by one absorption.
///
/// Generic tagged nodes have one additional physical BlakeG compression for `tag || 0w`; that
/// finalizer reuses the span tail's external id and is not counted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsorptionSpan {
    start: u32,
    len: u32,
}

impl AbsorptionSpan {
    fn new(range: Range<u32>) -> Self {
        Self {
            start: range.start,
            len: range.end - range.start,
        }
    }

    pub fn head(self) -> AbsorptionId {
        AbsorptionId(self.start)
    }

    pub fn tail(self) -> AbsorptionId {
        AbsorptionId(self.start + self.len - 1)
    }

    pub fn n_cycles(self) -> u32 {
        self.len
    }
}

#[derive(Debug, Clone)]
pub struct AbsorptionOutput {
    pub digest: EidosDigest,
    pub span: AbsorptionSpan,
}

impl AbsorptionOutput {
    pub fn head(&self) -> AbsorptionId {
        self.span.head()
    }

    pub fn tail(&self) -> AbsorptionId {
        self.span.tail()
    }
}

// EIDOS ORACLE
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbsorptionKind {
    And,
    Chunks,
    Generic,
}

fn absorption_kind(cap: EidosCap) -> AbsorptionKind {
    if cap == EidosCap::and() {
        AbsorptionKind::And
    } else if cap == EidosCap::chunk() {
        AbsorptionKind::Chunks
    } else {
        AbsorptionKind::Generic
    }
}

fn block_from_chunks(rate0: [Felt; 4], rate1: [Felt; 4]) -> [Felt; 8] {
    let mut block = [Felt::ZERO; 8];
    block[..4].copy_from_slice(&rate0);
    block[4..].copy_from_slice(&rate1);
    block
}

fn initial_cv(kind: AbsorptionKind, num_payload_blocks: usize) -> Word {
    let payload_felts = u32::try_from(num_payload_blocks * 8)
        .expect("deferred absorption felt length must fit in u32");
    match kind {
        AbsorptionKind::And => {
            assert_eq!(num_payload_blocks, 1, "AND must contain one digest pair");
            DEFERRED_ROOT_DOMAIN
        },
        AbsorptionKind::Chunks => Eidos::init_chaining_word(
            DEFERRED_CHUNKS_DOMAIN.as_canonical_u64() as u32,
            payload_felts,
        ),
        AbsorptionKind::Generic => Eidos::init_chaining_word(
            DEFERRED_NODE_DOMAIN.as_canonical_u64() as u32,
            payload_felts.checked_add(4).expect("generic node felt length overflow"),
        ),
    }
}

fn tag_block(cap: EidosCap) -> [Felt; 8] {
    let mut block = [Felt::ZERO; 8];
    block[..4].copy_from_slice(&cap.as_array());
    block
}

fn absorb_oracle(cap: EidosCap, blocks: &[([Felt; 4], [Felt; 4])]) -> EidosDigest {
    let kind = absorption_kind(cap);
    let mut cv = initial_cv(kind, blocks.len());
    for &(rate0, rate1) in blocks {
        cv = Eidos::compress_block(cv, block_from_chunks(rate0, rate1));
    }
    if kind == AbsorptionKind::Generic {
        cv = Eidos::compress_block(cv, tag_block(cap));
    }
    EidosDigest(cv.into_elements())
}

// REQUIRES ACCUMULATOR
// ================================================================================================

#[derive(Debug, Clone)]
struct RecordedAbsorption {
    cap: EidosCap,
    blocks: Vec<([Felt; 4], [Felt; 4])>,
    digest: EidosDigest,
    range: Range<u32>,
    in_mult: ProvideMult,
    out_mult: ProvideMult,
}

#[derive(Debug, Clone, Default)]
pub struct EidosRequires {
    absorptions: Vec<RecordedAbsorption>,
    by_digest: BTreeMap<EidosDigest, usize>,
    next_seq: u32,
}

impl EidosRequires {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest_of(cap: EidosCap, blocks: &[([Felt; 4], [Felt; 4])]) -> EidosDigest {
        assert!(!blocks.is_empty(), "absorption needs at least one block");
        absorb_oracle(cap, blocks)
    }

    pub fn require_absorption(
        &mut self,
        cap: EidosCap,
        blocks: impl IntoIterator<Item = ([Felt; 4], [Felt; 4])>,
    ) -> AbsorptionOutput {
        let blocks: Vec<_> = blocks.into_iter().collect();
        assert!(!blocks.is_empty(), "absorption needs at least one block");
        let digest = absorb_oracle(cap, &blocks);

        if let Some(&idx) = self.by_digest.get(&digest) {
            let rec = &mut self.absorptions[idx];
            debug_assert_eq!(rec.cap, cap, "equal digest must identify the same cap");
            debug_assert_eq!(rec.blocks, blocks, "equal digest must identify the same payload");
            rec.in_mult += 1;
            return AbsorptionOutput {
                digest,
                span: AbsorptionSpan::new(rec.range.clone()),
            };
        }

        let n = u32::try_from(blocks.len()).expect("absorption block count must fit in u32");
        let range = self.next_seq..self.next_seq + n;
        self.next_seq += n;
        let idx = self.absorptions.len();
        self.absorptions.push(RecordedAbsorption {
            cap,
            blocks,
            digest,
            range: range.clone(),
            in_mult: 1,
            out_mult: 0,
        });
        self.by_digest.insert(digest, idx);
        AbsorptionOutput { digest, span: AbsorptionSpan::new(range) }
    }

    pub fn require_one_shot(
        &mut self,
        cap: EidosCap,
        rate0: [Felt; 4],
        rate1: [Felt; 4],
    ) -> AbsorptionOutput {
        self.require_absorption(cap, core::iter::once((rate0, rate1)))
    }

    pub fn require_digest(&mut self, digest: EidosDigest) -> Option<AbsorptionSpan> {
        let &idx = self.by_digest.get(&digest)?;
        let rec = &mut self.absorptions[idx];
        rec.out_mult += 1;
        Some(AbsorptionSpan::new(rec.range.clone()))
    }

    pub fn lookup(&self, digest: EidosDigest) -> Option<AbsorptionSpan> {
        self.by_digest
            .get(&digest)
            .map(|&idx| AbsorptionSpan::new(self.absorptions[idx].range.clone()))
    }

    /// Number of logical payload compressions allocated to surrounding transcript buses.
    pub fn total_cycles(&self) -> u32 {
        self.next_seq
    }
}

// TRACE GENERATION
// ================================================================================================

/// The integrated PVM BlakeG trace and its fixed byte-operation lookup trace.
#[derive(Debug)]
pub struct EidosTraceBundle {
    pub compression: RowMajorMatrix<Felt>,
    pub and8: RowMajorMatrix<Felt>,
}

#[derive(Debug)]
struct CompressionCycle {
    absorption_id: u32,
    in_mult: ProvideMult,
    out_mult: ProvideMult,
    is_head: bool,
    is_payload: bool,
    is_output: bool,
    kind: AbsorptionKind,
    remaining: usize,
    block: [Felt; 8],
    cap: EidosCap,
    cv_in: Word,
}

impl CompressionCycle {
    fn append_metadata(&self, row: &mut Vec<Felt>) {
        let start = row.len();
        row.resize(start + (NUM_MAIN_COLS - NUM_BLAKEG_COMPRESSION_COLS), Felt::ZERO);
        let meta = &mut row[start..];
        let col = |absolute: usize| absolute - NUM_BLAKEG_COMPRESSION_COLS;
        meta[col(COL_ABSORPTION_ID)] = Felt::from(self.absorption_id);
        meta[col(COL_IN_MULTIPLICITY)] = Felt::from(self.in_mult);
        meta[col(COL_OUT_MULTIPLICITY)] = Felt::from(self.out_mult);
        meta[col(COL_IS_HEAD)] = Felt::from_u8(self.is_head as u8);
        meta[col(COL_IS_ABSORB)] = Felt::from_u8((!self.is_head) as u8);
        meta[col(COL_IS_PAYLOAD)] = Felt::from_u8(self.is_payload as u8);
        meta[col(COL_IS_OUTPUT)] = Felt::from_u8(self.is_output as u8);
        meta[col(COL_IS_AND)] = Felt::from_u8((self.kind == AbsorptionKind::And) as u8);
        meta[col(COL_IS_CHUNKS)] = Felt::from_u8((self.kind == AbsorptionKind::Chunks) as u8);
        meta[col(COL_IS_GENERIC)] = Felt::from_u8((self.kind == AbsorptionKind::Generic) as u8);
        let remaining = Felt::from(
            u32::try_from(self.remaining).expect("remaining compression count must fit in u32"),
        );
        meta[col(COL_REMAINING)] = remaining;
        meta[col(COL_REMAINING_INV)] = if self.remaining == 1 {
            Felt::ZERO
        } else {
            (remaining - Felt::ONE).inverse()
        };
        meta[col(COL_CAP_BEGIN)..col(COL_CAP_BEGIN) + 4].copy_from_slice(&self.cap.as_array());
        meta[col(COL_CV_IN_BEGIN)..col(COL_CV_IN_BEGIN) + 4].copy_from_slice(self.cv_in.as_slice());
    }
}

struct BlakeGLookupCounter<'a> {
    counts: &'a mut [u64],
}

impl ByteLookupRecorder for BlakeGLookupCounter<'_> {
    fn record(&mut self, lookup: BlakeGByteLookup, lhs: u8, rhs: u8, result: u32) {
        let kind = match lookup {
            BlakeGByteLookup::And8 => BYTE_LOOKUP_KIND_AND8,
            BlakeGByteLookup::Rot12 { byte } => BYTE_LOOKUP_KIND_BLAKEG_ROT12[byte],
            BlakeGByteLookup::Rot7 { byte } => BYTE_LOOKUP_KIND_BLAKEG_ROT7[byte],
        };
        debug_assert_eq!(byte_lookup_result(kind, lhs, rhs), result);
        let pair = ((lhs as usize) << 8) + rhs as usize;
        self.counts[kind * BYTE_PAIR_ROWS + pair] += 1;
    }
}

fn unpack_felts<const N: usize>(values: &[Felt]) -> [u32; N] {
    assert_eq!(2 * values.len(), N, "packed Felt slice must contain exactly {N} BlakeG words",);

    let mut words = [0; N];
    for (idx, value) in values.iter().enumerate() {
        let packed = value.as_canonical_u64();
        words[2 * idx] = packed as u32;
        words[2 * idx + 1] = (packed >> 32) as u32;
    }
    words
}

fn record_message_range_checks(counts: &mut [u64], block: [u32; 16]) {
    for word in block {
        for limb in [word as u16, (word >> 16) as u16] {
            counts[RANGE_CHECK_COUNT_OFFSET + limb as usize] += 1;
        }
    }
}

fn build_and8_trace(counts: &[u64]) -> RowMajorMatrix<Felt> {
    assert_eq!(counts.len(), BYTE_LOOKUP_COUNT_LEN);
    let mut values = vec![Felt::ZERO; AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_COLS];
    for pair in 0..BYTE_PAIR_ROWS {
        for kind in 0..BYTE_LOOKUP_KIND_COUNT {
            let count = counts[kind * BYTE_PAIR_ROWS + pair];
            assert!(count < Felt::ORDER_U64, "byte lookup multiplicity must be canonical");
            values[pair * NUM_AND8_LOOKUP_COLS + kind] = Felt::new_unchecked(count);
        }
        let count = counts[RANGE_CHECK_COUNT_OFFSET + pair];
        assert!(count < Felt::ORDER_U64, "range lookup multiplicity must be canonical");
        values[pair * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL] = Felt::new_unchecked(count);
    }
    RowMajorMatrix::new(values, NUM_AND8_LOOKUP_COLS)
}

fn build_blakeg_traces(
    cycles: &[CompressionCycle],
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
    let real_cycles = cycles.len();
    let height = (real_cycles * BLAKEG_COMPRESSION_CYCLE_LEN)
        .next_power_of_two()
        .max(BLAKEG_COMPRESSION_CYCLE_LEN);
    let cycle_count = height / BLAKEG_COMPRESSION_CYCLE_LEN;
    let mut values = vec![Felt::ZERO; height * NUM_BLAKEG_COMPRESSION_COLS];
    let (rows, remainder) = values.as_chunks_mut::<NUM_BLAKEG_COMPRESSION_COLS>();
    debug_assert!(remainder.is_empty());
    let mut counts = vec![0u64; BYTE_LOOKUP_COUNT_LEN];

    for (physical_cycle_id, cycle_rows) in
        rows.chunks_exact_mut(BLAKEG_COMPRESSION_CYCLE_LEN).enumerate()
    {
        let (block, cv) = if let Some(cycle) = cycles.get(physical_cycle_id) {
            let block = unpack_felts::<16>(&cycle.block);
            let cv = unpack_felts::<8>(cycle.cv_in.as_slice());
            (block, cv)
        } else {
            ([0; 16], [0; 8])
        };

        record_message_range_checks(&mut counts, block);
        let mut recorder = BlakeGLookupCounter { counts: &mut counts };
        write_felt_trace_block_into_zeroed_with_lookups(
            cycle_rows,
            block,
            cv,
            physical_cycle_id as u64,
            &mut recorder,
        );
    }

    debug_assert_eq!(cycle_count, rows.len() / BLAKEG_COMPRESSION_CYCLE_LEN);
    (
        RowMajorMatrix::new(values, NUM_BLAKEG_COMPRESSION_COLS),
        build_and8_trace(&counts),
    )
}

pub fn generate_traces(requires: EidosRequires) -> EidosTraceBundle {
    let physical_cycles: usize = requires
        .absorptions
        .iter()
        .map(|rec| {
            rec.blocks.len() + usize::from(absorption_kind(rec.cap) == AbsorptionKind::Generic)
        })
        .sum();
    let mut cycles = Vec::with_capacity(physical_cycles);

    for rec in &requires.absorptions {
        let kind = absorption_kind(rec.cap);
        let extra = usize::from(kind == AbsorptionKind::Generic);
        let total = rec.blocks.len() + extra;
        let mut cv = initial_cv(kind, rec.blocks.len());

        for (idx, &(rate0, rate1)) in rec.blocks.iter().enumerate() {
            let block = block_from_chunks(rate0, rate1);
            let cv_out = Eidos::compress_block(cv, block);
            let is_output = kind != AbsorptionKind::Generic && idx + 1 == rec.blocks.len();
            cycles.push(CompressionCycle {
                absorption_id: rec.range.start + idx as u32,
                in_mult: rec.in_mult,
                out_mult: if is_output { rec.out_mult } else { 0 },
                is_head: idx == 0,
                is_payload: true,
                is_output,
                kind,
                remaining: total - idx,
                block,
                cap: rec.cap,
                cv_in: cv,
            });
            cv = cv_out;
        }

        if kind == AbsorptionKind::Generic {
            let block = tag_block(rec.cap);
            let cv_out = Eidos::compress_block(cv, block);
            cycles.push(CompressionCycle {
                absorption_id: rec.range.end - 1,
                in_mult: 0,
                out_mult: rec.out_mult,
                is_head: false,
                is_payload: false,
                is_output: true,
                kind,
                remaining: 1,
                block,
                cap: rec.cap,
                cv_in: cv,
            });
            cv = cv_out;
        }

        debug_assert_eq!(EidosDigest(cv.into_elements()), rec.digest);
    }

    let (blakeg, and8) = build_blakeg_traces(&cycles);
    let height = blakeg.values.len() / blakeg.width;
    debug_assert_eq!(height % BLAKEG_COMPRESSION_CYCLE_LEN, 0);
    debug_assert!(cycles.len() * BLAKEG_COMPRESSION_CYCLE_LEN <= height);

    let mut values = Vec::with_capacity(height * NUM_MAIN_COLS);
    for (row_idx, base_row) in blakeg.values.chunks_exact(blakeg.width).enumerate() {
        values.extend_from_slice(base_row);
        let cycle_idx = row_idx / BLAKEG_COMPRESSION_CYCLE_LEN;
        if let Some(cycle) = cycles.get(cycle_idx) {
            cycle.append_metadata(&mut values);
        } else {
            values.extend([Felt::ZERO; NUM_MAIN_COLS - NUM_BLAKEG_COMPRESSION_COLS]);
        }
    }

    EidosTraceBundle {
        compression: RowMajorMatrix::new(values, NUM_MAIN_COLS),
        and8,
    }
}

pub fn generate_trace(requires: EidosRequires) -> RowMajorMatrix<Felt> {
    generate_traces(requires).compression
}

const _: () = assert!(BLAKEG_COMPRESSION_CYCLE_LEN == 32);
