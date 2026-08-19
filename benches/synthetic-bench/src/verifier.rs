//! Verification helpers for synthetic-trace matching.
//!
//! Hard checks:
//! - `padded_core(actual) == padded_core(target)`
//! - `padded_and8_lookup(actual) == padded_and8_lookup(target)` when the snapshot contains a
//!   per-AIR BlakeG target.
//! - `padded_chiplets(actual) == padded_chiplets(target)` when the snapshot contains a per-AIR
//!   BlakeG target.
//! - `padded_blakeg_compression(actual) == padded_blakeg_compression(target)` when the snapshot
//!   contains a per-AIR BlakeG target.
//! - `padded_total(actual) == padded_total(target)`
//!
//! Soft reporting:
//! - unpadded totals (`core_rows`, `chiplets_rows`, `blakeg_compression_rows`) within
//!   [`PER_COMPONENT_TOLERANCE`]
//! - advisory breakdown deltas (info only)

use std::fmt::{self, Display};

use crate::snapshot::TraceShape;

/// Reporting tolerance for unpadded totals; never used for pass/fail.
pub const PER_COMPONENT_TOLERANCE: f64 = 0.02;

/// Result of comparing an emitted program's measured shape against the snapshot target.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub target: TraceShape,
    pub actual: TraceShape,
    pub total_deltas: Vec<ComponentDelta>,
    pub breakdown_deltas: Vec<ComponentDelta>,
}

/// How a row-count entry participates in the verifier's reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaStatus {
    /// Prints `ok` if within tolerance, `out` otherwise.
    Enforced,
    /// Always prints `info`; used for rows the solver does not target.
    Informational,
}

/// Per-row-count comparison.
#[derive(Debug, Clone, Copy)]
pub struct ComponentDelta {
    pub name: &'static str,
    pub target: u64,
    pub actual: u64,
    pub delta_pct: f64,
    pub within_tolerance: bool,
    pub status: DeltaStatus,
}

impl VerificationReport {
    pub fn new(target: TraceShape, actual: TraceShape) -> Self {
        let has_blakeg_target = target.totals.has_blakeg_compression_target();
        let chiplets_status = if has_blakeg_target {
            DeltaStatus::Enforced
        } else {
            DeltaStatus::Informational
        };
        let blakeg_status = if has_blakeg_target {
            DeltaStatus::Enforced
        } else {
            DeltaStatus::Informational
        };
        let total_rows: &[(&'static str, u64, u64, DeltaStatus)] = &[
            (
                "core_rows",
                target.totals.core_rows,
                actual.totals.core_rows,
                DeltaStatus::Enforced,
            ),
            (
                "chiplets_rows",
                target.totals.chiplets_rows,
                actual.totals.chiplets_rows,
                chiplets_status,
            ),
            (
                "blakeg_rows",
                target.totals.blakeg_compression_rows,
                actual.totals.blakeg_compression_rows,
                blakeg_status,
            ),
            (
                // byte_pair_lookup_rows is derived, not independently driven.
                "byte_pair_lookup_rows",
                target.totals.byte_pair_lookup_rows,
                actual.totals.byte_pair_lookup_rows,
                DeltaStatus::Informational,
            ),
        ];
        let breakdown_rows: &[(&'static str, u64, u64, DeltaStatus)] = &[
            (
                "hasher",
                target.hasher_work_rows(),
                actual.hasher_work_rows(),
                DeltaStatus::Informational,
            ),
            (
                "bitwise",
                target.breakdown.bitwise_rows,
                actual.breakdown.bitwise_rows,
                DeltaStatus::Informational,
            ),
            (
                "memory",
                target.breakdown.memory_target(),
                actual.breakdown.memory_rows,
                DeltaStatus::Informational,
            ),
        ];
        Self {
            target,
            actual,
            total_deltas: total_rows.iter().map(|r| component_delta(*r)).collect(),
            breakdown_deltas: breakdown_rows.iter().map(|r| component_delta(*r)).collect(),
        }
    }

    /// True when all available padded proxies match their targets exactly.
    pub fn brackets_match(&self) -> bool {
        let has_blakeg_target = self.target.totals.has_blakeg_compression_target();
        let chiplets_matches = !has_blakeg_target
            || self.target.totals.padded_chiplets() == self.actual.totals.padded_chiplets();
        let blakeg_matches = !has_blakeg_target
            || self.target.totals.padded_blakeg_compression()
                == self.actual.totals.padded_blakeg_compression();
        let and8_matches = !has_blakeg_target
            || self.target.totals.padded_and8_lookup() == self.actual.totals.padded_and8_lookup();

        self.target.totals.padded_core() == self.actual.totals.padded_core()
            && and8_matches
            && chiplets_matches
            && blakeg_matches
            && self.target.totals.padded_total() == self.actual.totals.padded_total()
    }
}

fn component_delta((name, t, a, status): (&'static str, u64, u64, DeltaStatus)) -> ComponentDelta {
    let delta_pct = if t == 0 {
        if a == 0 { 0.0 } else { f64::INFINITY }
    } else {
        (a as f64 - t as f64) / t as f64
    };
    ComponentDelta {
        name,
        target: t,
        actual: a,
        delta_pct,
        within_tolerance: delta_pct.abs() <= PER_COMPONENT_TOLERANCE,
        status,
    }
}

impl Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-- hard brackets (padded power-of-two) --")?;
        write_bracket_row(
            f,
            "padded_core",
            self.target.totals.padded_core(),
            self.actual.totals.padded_core(),
        )?;
        if self.target.totals.has_blakeg_compression_target() {
            write_bracket_row(
                f,
                "padded_and8",
                self.target.totals.padded_and8_lookup(),
                self.actual.totals.padded_and8_lookup(),
            )?;
            write_bracket_row(
                f,
                "padded_chiplets",
                self.target.totals.padded_chiplets(),
                self.actual.totals.padded_chiplets(),
            )?;
            write_bracket_row(
                f,
                "padded_blakeg",
                self.target.totals.padded_blakeg_compression(),
                self.actual.totals.padded_blakeg_compression(),
            )?;
        }
        write_bracket_row(
            f,
            "padded_total",
            self.target.totals.padded_total(),
            self.actual.totals.padded_total(),
        )?;

        writeln!(f, "\n-- totals (soft: {:.0}% band) --", PER_COMPONENT_TOLERANCE * 100.0)?;
        write_delta_header(f)?;
        for d in &self.total_deltas {
            write_delta_row(f, d)?;
        }

        writeln!(f, "\n-- breakdown (info) --")?;
        write_delta_header(f)?;
        for d in &self.breakdown_deltas {
            write_delta_row(f, d)?;
        }

        writeln!(f)?;
        if self.brackets_match() {
            writeln!(f, "=> BRACKET MATCH")?;
        } else {
            writeln!(f, "=> BRACKET MISS")?;
        }
        Ok(())
    }
}

fn write_delta_header(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(
        f,
        "{:<16} {:>12} {:>12} {:>10}  status",
        "component", "target", "actual", "delta"
    )
}

fn write_delta_row(f: &mut fmt::Formatter<'_>, d: &ComponentDelta) -> fmt::Result {
    let delta_str = if d.delta_pct.is_finite() {
        format!("{:+6.2}%", d.delta_pct * 100.0)
    } else {
        "+∞".to_string()
    };
    let status = match d.status {
        DeltaStatus::Enforced => {
            if d.within_tolerance {
                "ok"
            } else {
                "out"
            }
        },
        DeltaStatus::Informational => "info",
    };
    writeln!(
        f,
        "{:<16} {:>12} {:>12} {:>10}  {}",
        d.name, d.target, d.actual, delta_str, status
    )
}

fn write_bracket_row(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    target: u64,
    actual: u64,
) -> fmt::Result {
    let ok = if target == actual { "==" } else { "MISS" };
    writeln!(f, "{name:<16} {target:>12} {actual:>12} {ok:>10}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{TraceBreakdown, TraceTotals};

    fn shape(core: u64, hasher: u64, memory: u64) -> TraceShape {
        let breakdown = TraceBreakdown {
            hasher_rows: hasher,
            bitwise_rows: 0,
            memory_rows: memory,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let totals = TraceTotals {
            core_rows: core,
            chiplets_rows: breakdown.chiplets_sum(),
            blakeg_compression_rows: hasher,
            byte_pair_lookup_rows: 0,
        };
        TraceShape::new(totals, breakdown)
    }

    #[test]
    fn exact_match_is_bracket_ok_and_all_within_tolerance() {
        let t = shape(68000, 8000, 12000);
        let r = VerificationReport::new(t, t);
        assert!(r.brackets_match());
        assert!(r.total_deltas.iter().all(|d| d.within_tolerance));
        assert!(r.breakdown_deltas.iter().all(|d| d.within_tolerance));
    }

    #[test]
    fn bracket_miss_is_reported_when_core_bracket_differs() {
        // target.core=68000 → 131072; actual.core=30000 → 32768 (different bracket)
        let target = shape(68000, 8000, 12000);
        let actual = shape(30000, 2000, 1000);
        let r = VerificationReport::new(target, actual);
        assert!(!r.brackets_match());
        assert!(r.to_string().contains("BRACKET MISS"));
    }

    #[test]
    fn chiplets_bracket_can_miss_independently_of_core() {
        // core is the same (same padded bracket); chiplets_rows lands in different brackets.
        // target chiplets = 8000 + 12000 + 1 = 20001 → 32768
        // actual chiplets = 20000 + 30000 + 1 = 50001 → 65536
        let target = shape(40000, 8000, 12000);
        let actual = shape(40000, 20000, 30000);
        let r = VerificationReport::new(target, actual);
        // padded_core: both 40000 → 65536 (same)
        assert_eq!(target.totals.padded_core(), actual.totals.padded_core());
        // padded_chiplets differs
        assert_ne!(target.totals.padded_chiplets(), actual.totals.padded_chiplets());
        assert!(!r.brackets_match());
    }

    #[test]
    fn blakeg_bracket_can_miss_independently_of_core_and_chiplets() {
        let target = shape(40000, 8000, 1000);
        let actual = shape(40000, 9000, 1000);
        let r = VerificationReport::new(target, actual);

        assert_eq!(target.totals.padded_core(), actual.totals.padded_core());
        assert_eq!(target.totals.padded_chiplets(), actual.totals.padded_chiplets());
        assert_ne!(
            target.totals.padded_blakeg_compression(),
            actual.totals.padded_blakeg_compression()
        );
        assert!(!r.brackets_match());
    }

    #[test]
    fn and8_bracket_can_miss_independently_of_core() {
        let mut target = shape(40_000, 8_000, 1_000);
        let mut actual = target;
        target.totals.byte_pair_lookup_rows = 65_536;
        actual.totals.byte_pair_lookup_rows = 32_768;
        let r = VerificationReport::new(target, actual);

        assert_eq!(target.totals.padded_core(), actual.totals.padded_core());
        assert_eq!(target.totals.padded_total(), actual.totals.padded_total());
        assert_ne!(target.totals.padded_and8_lookup(), actual.totals.padded_and8_lookup());
        assert!(!r.brackets_match());
    }

    #[test]
    fn missing_blakeg_target_uses_chiplet_hasher_rows() {
        let breakdown = TraceBreakdown {
            hasher_rows: 8000,
            bitwise_rows: 0,
            memory_rows: 1000,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let target = TraceShape::new(
            TraceTotals {
                core_rows: 40000,
                chiplets_rows: breakdown.chiplets_sum(),
                blakeg_compression_rows: 0,
                byte_pair_lookup_rows: 0,
            },
            breakdown,
        );
        let actual = shape(40000, 8000, 1000);
        let r = VerificationReport::new(target, actual);

        assert!(r.brackets_match());
    }

    #[test]
    fn chiplets_bracket_miss_is_info_without_blakeg_target() {
        let target_breakdown = TraceBreakdown {
            hasher_rows: 16_000,
            bitwise_rows: 0,
            memory_rows: 16_000,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let actual_breakdown = TraceBreakdown {
            hasher_rows: 32_000,
            bitwise_rows: 0,
            memory_rows: 32_000,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let target = TraceShape::new(
            TraceTotals {
                core_rows: 100_000,
                chiplets_rows: target_breakdown.chiplets_sum(),
                blakeg_compression_rows: 0,
                byte_pair_lookup_rows: 0,
            },
            target_breakdown,
        );
        let actual = TraceShape::new(
            TraceTotals {
                core_rows: 100_000,
                chiplets_rows: actual_breakdown.chiplets_sum(),
                blakeg_compression_rows: 0,
                byte_pair_lookup_rows: 0,
            },
            actual_breakdown,
        );
        let r = VerificationReport::new(target, actual);

        assert_eq!(target.totals.padded_core(), actual.totals.padded_core());
        assert_eq!(target.totals.padded_total(), actual.totals.padded_total());
        assert_ne!(target.totals.padded_chiplets(), actual.totals.padded_chiplets());
        assert!(r.brackets_match());

        let chiplets_delta = r.total_deltas.iter().find(|d| d.name == "chiplets_rows").unwrap();
        assert_eq!(chiplets_delta.status, DeltaStatus::Informational);
    }

    #[test]
    fn per_component_overshoot_stays_within_bracket() {
        // Hasher overshoots but every padded AIR bracket stays unchanged.
        let target = shape(68000, 8000, 12000);
        let actual = shape(68000, 8191, 12000);
        let r = VerificationReport::new(target, actual);
        assert!(r.brackets_match());
        let hasher_delta = r.breakdown_deltas.iter().find(|d| d.name == "hasher").unwrap();
        assert!(!hasher_delta.within_tolerance);
    }
}
