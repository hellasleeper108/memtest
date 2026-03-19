//! Error forensics: cluster analysis, bit statistics, and diagnosis.
//!
//! All functions are pure (no I/O) so they can be called from either the TUI
//! or the CLI without depending on any rendering code.

use crate::tests::MemError;

// ── DRAM geometry constants (typical DDR5) ────────────────────────────────────

/// Cache-line size (bytes). Errors within one cache line share a single column.
pub const CACHELINE: u64 = 64;

/// Typical DDR5 row size in bytes (8 KiB). Errors within one row indicate a
/// failed DRAM row cell.
pub const ROW_BYTES: u64 = 8_192;

/// Heuristic bank size (8 MiB). Regular clusters spaced at this granularity
/// suggest a bank-level defect.
pub const BANK_BYTES: u64 = 8 * 1024 * 1024;

// ── Types ─────────────────────────────────────────────────────────────────────

/// How tightly grouped the errors in a cluster are.
#[derive(Debug, Clone, PartialEq)]
pub enum ClusterKind {
    /// All within one 64-byte cache line → single column cell failure.
    CacheLine,
    /// All within one 8 KiB DRAM row → row-level failure.
    Row,
    /// Span < 8 MiB → likely confined to one bank.
    Bank,
    /// Errors span more than a bank → bad stick or multiple independent cells.
    Scattered,
}

impl ClusterKind {
    pub fn from_span(span: u64) -> Self {
        if span < CACHELINE  { ClusterKind::CacheLine }
        else if span < ROW_BYTES  { ClusterKind::Row }
        else if span < BANK_BYTES { ClusterKind::Bank }
        else                      { ClusterKind::Scattered }
    }
    pub fn label(&self) -> &'static str {
        match self {
            ClusterKind::CacheLine => "CACHE LINE",
            ClusterKind::Row       => "SAME ROW",
            ClusterKind::Bank      => "SAME BANK",
            ClusterKind::Scattered => "SCATTERED",
        }
    }
    pub fn hint(&self) -> &'static str {
        match self {
            ClusterKind::CacheLine => "single column cell — monitor",
            ClusterKind::Row       => "DRAM row failure — replace DIMM",
            ClusterKind::Bank      => "bank-level failure — replace DIMM",
            ClusterKind::Scattered => "widespread — bad stick or many cells",
        }
    }
}

/// A contiguous group of errors (gap between any two consecutive members ≤ ROW_BYTES).
#[derive(Debug, Clone)]
pub struct Cluster {
    /// Lowest byte offset in the group.
    pub start: u64,
    /// Highest byte offset in the group.
    pub end: u64,
    /// end − start.
    pub span: u64,
    pub kind: ClusterKind,
    /// Indices into the flat error slice passed to `analyze()`.
    pub error_idxs: Vec<usize>,
    /// Bits that flipped in *every* error in this cluster — rock-solid failure.
    pub common_flip: u64,
    /// Bits that flipped in *any* error — worst-case affected bits.
    pub any_flip: u64,
}

/// Diagnosis severity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sev { Info, Warn, Crit }

#[derive(Debug, Clone)]
pub struct DiagLine {
    pub sev:  Sev,
    pub text: String,
}

/// Complete forensics report for one test run.
pub struct Report {
    pub clusters:   Vec<Cluster>,
    /// How many times each bit (index 0..63) flipped across all errors.
    pub bit_flips:  [u32; 64],
    /// Bits where every flip left the cell reading 0 (stuck-at-0: can't hold logic-1).
    pub stuck_at_0: u64,
    /// Bits where every flip left the cell reading 1 (stuck-at-1: can't hold logic-0).
    pub stuck_at_1: u64,
    pub diagnosis:  Vec<DiagLine>,
}

// ── Analysis ──────────────────────────────────────────────────────────────────

/// Analyse a flat slice of errors (collected across all tests) and produce a
/// forensics report.  Errors may arrive in any order.
pub fn analyze(errors: &[MemError]) -> Report {
    if errors.is_empty() {
        return Report {
            clusters:   Vec::new(),
            bit_flips:  [0; 64],
            stuck_at_0: 0,
            stuck_at_1: 0,
            diagnosis:  vec![DiagLine {
                sev:  Sev::Info,
                text: "No errors recorded — memory appears healthy.".into(),
            }],
        };
    }

    // Sort indices by ascending offset.
    let mut sorted: Vec<usize> = (0..errors.len()).collect();
    sorted.sort_by_key(|&i| errors[i].offset);

    // ── Clustering ────────────────────────────────────────────────────────────
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut cur: Vec<usize> = vec![sorted[0]];
    let mut cur_start = errors[sorted[0]].offset as u64;
    let mut cur_end   = cur_start;

    for &i in sorted.iter().skip(1) {
        let off = errors[i].offset as u64;
        if off.saturating_sub(cur_end) > ROW_BYTES {
            clusters.push(mk_cluster(cur, cur_start, cur_end, errors));
            cur = Vec::new();
            cur_start = off;
            cur_end   = off;
        }
        cur.push(i);
        cur_end = cur_end.max(off);
    }
    clusters.push(mk_cluster(cur, cur_start, cur_end, errors));

    // ── Bit statistics ────────────────────────────────────────────────────────
    let mut bit_flips = [0u32; 64];
    // Initialize "stuck" trackers: true = hypothesis still holds.
    let mut stuck_0  = [true; 64]; // hypothesis: this bit is stuck-at-0
    let mut stuck_1  = [true; 64]; // hypothesis: this bit is stuck-at-1
    let mut bit_seen = [false; 64];

    for e in errors {
        let flip = e.expected as u64 ^ e.actual as u64;
        for b in 0..64u64 {
            if flip & (1 << b) != 0 {
                bit_flips[b as usize] += 1;
                bit_seen[b as usize]   = true;
                if (e.actual as u64 >> b) & 1 == 1 {
                    stuck_0[b as usize] = false; // actual read as 1 → not stuck-at-0
                } else {
                    stuck_1[b as usize] = false; // actual read as 0 → not stuck-at-1
                }
            }
        }
    }

    let mut stuck_at_0 = 0u64;
    let mut stuck_at_1 = 0u64;
    for b in 0..64usize {
        if bit_seen[b] {
            if stuck_0[b] { stuck_at_0 |= 1 << b; }
            if stuck_1[b] { stuck_at_1 |= 1 << b; }
        }
    }

    // ── Diagnosis ─────────────────────────────────────────────────────────────
    let mut diag: Vec<DiagLine> = Vec::new();

    // Stuck bits — highest confidence, report first.
    for b in 0..64u64 {
        if stuck_at_0 & (1 << b) != 0 {
            diag.push(DiagLine {
                sev:  Sev::Crit,
                text: format!(
                    "STUCK BIT {b} (stuck-at-0) — {} flip(s), cell cannot hold logic-1",
                    bit_flips[b as usize]
                ),
            });
        }
        if stuck_at_1 & (1 << b) != 0 {
            diag.push(DiagLine {
                sev:  Sev::Crit,
                text: format!(
                    "STUCK BIT {b} (stuck-at-1) — {} flip(s), cell cannot hold logic-0",
                    bit_flips[b as usize]
                ),
            });
        }
    }

    // Per-cluster diagnosis.
    for (ci, c) in clusters.iter().enumerate() {
        let n   = c.error_idxs.len();
        let num = ci + 1;
        diag.push(DiagLine {
            sev:  Sev::Crit,
            text: match c.kind {
                ClusterKind::CacheLine => format!(
                    "Cluster {num} — {n} error(s) in {} B (CACHE LINE) — single column cell",
                    c.span.max(8)
                ),
                ClusterKind::Row => format!(
                    "Cluster {num} — {n} error(s) within {} B (ROW) — failed DRAM row, replace DIMM",
                    c.span.max(8)
                ),
                ClusterKind::Bank => format!(
                    "Cluster {num} — {n} error(s) span {} KiB (BANK) — bank-level defect, replace DIMM",
                    (c.span + 1023) / 1024
                ),
                ClusterKind::Scattered => format!(
                    "Cluster {num} — {n} error(s) span {} MiB (SCATTERED) — bad stick",
                    (c.span + 1_048_575) / 1_048_576
                ),
            },
        });
    }

    // Regular cluster spacing → bank pattern.
    if clusters.len() >= 3 {
        let gaps: Vec<u64> = clusters
            .windows(2)
            .map(|w| w[1].start.saturating_sub(w[0].start))
            .collect();
        let g0 = gaps[0];
        if g0 > 0 && gaps.iter().all(|&g| {
            let hi = g0.max(g);
            let lo = g0.min(g);
            lo > 0 && hi / lo < 2 // within 2× of each other
        }) {
            diag.push(DiagLine {
                sev:  Sev::Crit,
                text: format!(
                    "REGULAR SPACING — clusters every ~{} KiB — likely failed DRAM bank",
                    (g0 + 1023) / 1024
                ),
            });
        }
    }

    // Low confidence advisory.
    if errors.len() == 1 {
        diag.push(DiagLine {
            sev:  Sev::Warn,
            text: "Only 1 error — may be transient. Re-run with more passes to confirm.".into(),
        });
    } else if errors.len() < 5 && (stuck_at_0 | stuck_at_1) == 0 {
        diag.push(DiagLine {
            sev:  Sev::Warn,
            text: "Few errors, no stuck bits — possible thermal or transient upset. Re-test.".into(),
        });
    }

    Report { clusters, bit_flips, stuck_at_0, stuck_at_1, diagnosis: diag }
}

fn mk_cluster(idxs: Vec<usize>, start: u64, end: u64, errors: &[MemError]) -> Cluster {
    let span = end.saturating_sub(start);
    let kind = ClusterKind::from_span(span);
    let mut common_flip = !0u64;
    let mut any_flip    = 0u64;
    for &i in &idxs {
        let flip = errors[i].expected as u64 ^ errors[i].actual as u64;
        common_flip &= flip;
        any_flip    |= flip;
    }
    Cluster { start, end, span, kind, error_idxs: idxs, common_flip, any_flip }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/// `0xHHHH_HHHH_HHHH_HHHH` — grouped hex offset.
pub fn fmt_addr(v: u64) -> String {
    let h = format!("{v:016X}");
    format!("0x{}_{}_{}_{}",  &h[0..4], &h[4..8], &h[8..12], &h[12..16])
}

/// Human-readable list of set bits in a mask, e.g. `"bits 2, 7"`.
/// Falls back to hex if more than 6 bits are set.
pub fn fmt_bits(mask: u64) -> String {
    let bits: Vec<u8> = (0..64).filter(|&b| mask & (1u64 << b) != 0).collect();
    if bits.is_empty() {
        return String::from("none");
    }
    if bits.len() > 6 {
        return format!("{} bits (0x{mask:016X})", bits.len());
    }
    let list = bits.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
    if bits.len() == 1 { format!("bit {list}") } else { format!("bits {list}") }
}

/// Byte span formatted with appropriate unit.
pub fn fmt_span(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{} KiB", (bytes + 1023) / 1024)
    } else {
        format!("{} MiB", (bytes + 1_048_575) / 1_048_576)
    }
}
