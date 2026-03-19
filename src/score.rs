//! Memory Stability Score — a single 0-100 quality metric derived from all
//! test results, heatmap latency data, and forensic analysis.
//!
//! The score has four weighted components that sum to 100:
//!   Error accuracy   60 pts  — correctness (errors, stuck bits, cluster type)
//!   Latency health   20 pts  — timing stability (spike/slow fractions)
//!   Row disturbance  10 pts  — row-hammer / row-level cluster risk
//!   Test coverage    10 pts  — confidence (how many tests, how many passes)

use crate::forensics::{ClusterKind, Report as ForensicsReport};
use crate::heatmap::{LAT_SLOW, LAT_SPIKE};

// ── Input ─────────────────────────────────────────────────────────────────────

pub struct ScoreInput<'a> {
    /// Total error count across all tests in the run.
    pub total_errors: usize,
    /// Number of u64 words in the tested region.
    pub region_words: u64,
    /// Number of full passes that were completed.
    pub passes: usize,
    /// Number of distinct test functions that ran (1-7).
    pub tests_run: usize,
    /// Heatmap latency counts [LAT_NONE, LAT_FAST, LAT_NORMAL, LAT_SLOW, LAT_SPIKE].
    pub lat_counts: [u32; 5],
    /// Completed forensic analysis.
    pub forensics: &'a ForensicsReport,
}

// ── Output types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum LatVariance {
    Low,      // < 0.5% spikes, < 5% slow
    Moderate, // < 2% spikes, < 15% slow
    High,     // < 5% spikes, < 30% slow
    Critical, // ≥ 5% spikes or ≥ 30% slow
}

impl LatVariance {
    pub fn label(&self) -> &'static str {
        match self {
            LatVariance::Low      => "low",
            LatVariance::Moderate => "moderate",
            LatVariance::High     => "high",
            LatVariance::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RowRisk {
    None,     // no row-level clusters, rowhammer clean
    Low,      // scattered errors only
    Elevated, // row-level cluster or rowhammer errors present
    High,     // multiple row/bank clusters
}

impl RowRisk {
    pub fn label(&self) -> &'static str {
        match self {
            RowRisk::None     => "none",
            RowRisk::Low      => "low",
            RowRisk::Elevated => "elevated",
            RowRisk::High     => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Safe,      // 90-100
    Stable,    // 75-89
    Marginal,  // 60-74
    Unstable,  // 40-59
    Critical,  // 0-39
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Safe     => "SAFE FOR HEAVY WORKLOADS",
            Verdict::Stable   => "STABLE — minor anomalies detected",
            Verdict::Marginal => "MARGINAL — monitor closely",
            Verdict::Unstable => "UNSTABLE — replacement recommended",
            Verdict::Critical => "CRITICAL FAILURE — do not use",
        }
    }
}

/// Complete stability score with all sub-metrics.
#[derive(Debug, Clone)]
pub struct StabilityScore {
    /// Overall score 0-100.
    pub total: u32,

    // Sub-component scores (for breakdown display)
    pub score_errors:    u32, // 0-60
    pub score_latency:   u32, // 0-20
    pub score_rowhammer: u32, // 0-10
    pub score_coverage:  u32, // 0-10

    // Qualitative metrics
    pub lat_variance:    LatVariance,
    pub row_risk:        RowRisk,
    pub stuck_bits:      u32,
    pub pattern_fail_pct: f64, // errors / region_words * 100

    pub verdict: Verdict,
}

// ── Computation ───────────────────────────────────────────────────────────────

pub fn compute(inp: &ScoreInput) -> StabilityScore {
    // ── Error component (0-60) ────────────────────────────────────────────────
    let stuck_bits = (inp.forensics.stuck_at_0 | inp.forensics.stuck_at_1).count_ones();

    let row_bank_clusters = inp
        .forensics
        .clusters
        .iter()
        .filter(|c| c.kind == ClusterKind::Row || c.kind == ClusterKind::Bank)
        .count();

    let score_errors: u32 = if inp.total_errors == 0 {
        60
    } else {
        let base: i32 = match inp.total_errors {
            1..=3   => 45,
            4..=10  => 35,
            11..=50 => 20,
            _       => 8,
        };
        let stuck_pen   = (stuck_bits as i32 * 10).min(30);
        let cluster_pen = (row_bank_clusters as i32 * 10).min(20);
        (base - stuck_pen - cluster_pen).max(0) as u32
    };

    // ── Latency component (0-20) ──────────────────────────────────────────────
    let tested: u32 = inp.lat_counts[1..].iter().sum(); // exclude LAT_NONE
    let tested_f = tested.max(1) as f64;

    let spike_frac = inp.lat_counts[LAT_SPIKE as usize] as f64 / tested_f;
    let slow_frac  = inp.lat_counts[LAT_SLOW  as usize] as f64 / tested_f;

    let lat_variance = if spike_frac >= 0.05 || (spike_frac + slow_frac) >= 0.30 {
        LatVariance::Critical
    } else if spike_frac >= 0.02 || (spike_frac + slow_frac) >= 0.15 {
        LatVariance::High
    } else if spike_frac >= 0.005 || slow_frac >= 0.05 {
        LatVariance::Moderate
    } else {
        LatVariance::Low
    };

    let score_latency: u32 = match lat_variance {
        LatVariance::Low      => 20,
        LatVariance::Moderate => 15,
        LatVariance::High     => 8,
        LatVariance::Critical => 2,
    };

    // ── Row disturbance component (0-10) ──────────────────────────────────────
    let row_risk = if row_bank_clusters >= 2 {
        RowRisk::High
    } else if row_bank_clusters >= 1 {
        RowRisk::Elevated
    } else if inp.total_errors > 0 {
        RowRisk::Low
    } else {
        RowRisk::None
    };

    let score_rowhammer: u32 = match row_risk {
        RowRisk::None     => 10,
        RowRisk::Low      => 7,
        RowRisk::Elevated => 3,
        RowRisk::High     => 0,
    };

    // ── Coverage component (0-10) ─────────────────────────────────────────────
    // Up to 5 pts for test breadth (7 possible), up to 5 pts for extra passes.
    let test_pts  = (inp.tests_run as u32 * 5 / 7).min(5);
    let pass_pts  = (inp.passes as u32).saturating_sub(1).min(5);
    let score_coverage = (test_pts + pass_pts).min(10);

    // ── Total & verdict ───────────────────────────────────────────────────────
    let total = (score_errors + score_latency + score_rowhammer + score_coverage).min(100);

    let verdict = match total {
        90..=100 => Verdict::Safe,
        75..=89  => Verdict::Stable,
        60..=74  => Verdict::Marginal,
        40..=59  => Verdict::Unstable,
        _        => Verdict::Critical,
    };

    let pattern_fail_pct = if inp.region_words > 0 {
        inp.total_errors as f64 / inp.region_words as f64 * 100.0
    } else {
        0.0
    };

    StabilityScore {
        total,
        score_errors,
        score_latency,
        score_rowhammer,
        score_coverage,
        lat_variance,
        row_risk,
        stuck_bits,
        pattern_fail_pct,
        verdict,
    }
}
