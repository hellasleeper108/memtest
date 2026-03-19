use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Internal heatmap resolution.
/// 256 columns × 16 rows = 4096 cells.
/// For a 256 MiB region this is 64 KiB per cell, matching TIMING_STRIDE.
pub const HMAP_COLS: usize = 256;
pub const HMAP_ROWS: usize = 16;

/// Number of u64 words per timed chunk (8192 × 8 bytes = 64 KiB).
/// Must match the stride used in tests.rs timing loops.
pub const TIMING_STRIDE: usize = 8192;
const TOTAL: usize = HMAP_COLS * HMAP_ROWS;

/// Per-cell state packed into a single u32 for lock-free updates.
///
/// Layout:
///   bits  0– 1  phase        0=untested 1=writing 2=reading 3=verified
///   bits  2– 5  error_count  saturating at 15
///   bits  6– 8  latency      0=none 1=fast 2=normal 3=slow 4=spike
///   bits  9–31  reserved
#[derive(Clone, Copy, Default)]
pub struct CellState {
    pub phase:   u8,
    pub errors:  u8,
    pub latency: u8,
}

impl CellState {
    pub fn from_u32(v: u32) -> Self {
        CellState {
            phase:   (v & 0x3) as u8,
            errors:  ((v >> 2) & 0xF) as u8,
            latency: ((v >> 6) & 0x7) as u8,
        }
    }
    pub fn to_u32(self) -> u32 {
        (self.phase as u32) | ((self.errors as u32) << 2) | ((self.latency as u32) << 6)
    }
    pub fn has_error(self) -> bool {
        self.errors > 0
    }
}

/// Latency class constants.
pub const LAT_NONE:   u8 = 0;
pub const LAT_FAST:   u8 = 1;
pub const LAT_NORMAL: u8 = 2;
pub const LAT_SLOW:   u8 = 3;
pub const LAT_SPIKE:  u8 = 4;

/// Shared heatmap state updated by the worker thread and read by the UI thread.
/// All writes use Relaxed ordering — the UI is only displaying approximate state.
pub struct HeatmapData {
    cells:       Vec<AtomicU32>,
    /// Set to the region size (bytes) before each test run.
    pub region_size: AtomicU64,
}

impl HeatmapData {
    pub fn new() -> Self {
        HeatmapData {
            cells:       (0..TOTAL).map(|_| AtomicU32::new(0)).collect(),
            region_size: AtomicU64::new(1),
        }
    }

    pub fn reset(&self) {
        for c in &self.cells {
            c.store(0, Ordering::Relaxed);
        }
    }

    fn cell_idx_for_byte(&self, byte: u64) -> usize {
        let sz = self.region_size.load(Ordering::Relaxed).max(1);
        let idx = (byte.saturating_mul(TOTAL as u64) / sz) as usize;
        idx.min(TOTAL - 1)
    }

    /// Record phase + latency for the byte range `[byte_start, byte_start + byte_len)`.
    /// Errors accumulate (saturating); latency class only increases (spikes persist).
    pub fn record(&self, byte_start: u64, byte_len: u64, phase: u8, latency: u8, error: bool) {
        let i0 = self.cell_idx_for_byte(byte_start);
        let i1 = self.cell_idx_for_byte(byte_start + byte_len.saturating_sub(1));

        for idx in i0..=i1 {
            let old = CellState::from_u32(self.cells[idx].load(Ordering::Relaxed));
            let new = CellState {
                phase,
                errors:  if error { old.errors.saturating_add(1).min(15) } else { old.errors },
                latency: old.latency.max(latency).min(4),
            };
            self.cells[idx].store(new.to_u32(), Ordering::Relaxed);
        }
    }

    /// Count cells at each latency level [LAT_NONE..LAT_SPIKE].
    /// Only cells with latency > LAT_NONE were actually timed; index 0 is untested.
    pub fn latency_counts(&self) -> [u32; 5] {
        let mut counts = [0u32; 5];
        for c in &self.cells {
            let lat = ((c.load(Ordering::Relaxed) >> 6) & 0x7).min(4) as usize;
            counts[lat] += 1;
        }
        counts
    }

    /// Bulk-set the phase for every cell (used for fast fill operations).
    pub fn set_all_phase(&self, phase: u8) {
        for c in &self.cells {
            let old = c.load(Ordering::Relaxed);
            let new = (old & !0x3) | (phase as u32 & 0x3);
            c.store(new, Ordering::Relaxed);
        }
    }

    /// Read the cell at internal grid position (col, row).
    pub fn get(&self, col: usize, row: usize) -> CellState {
        let idx = row.min(HMAP_ROWS - 1) * HMAP_COLS + col.min(HMAP_COLS - 1);
        CellState::from_u32(self.cells[idx].load(Ordering::Relaxed))
    }

    /// Return the "worst" cell state in the rectangle covering internal cells
    /// mapped to display cell (dcol, drow_virtual) for a display of size (dw, dh_virtual).
    pub fn sample(&self, dcol: usize, dvrow: usize, dw: usize, dvh: usize) -> CellState {
        let c0 = dcol * HMAP_COLS / dw.max(1);
        let c1 = ((dcol + 1) * HMAP_COLS / dw.max(1)).min(HMAP_COLS).max(c0 + 1);
        let r0 = dvrow * HMAP_ROWS / dvh.max(1);
        let r1 = ((dvrow + 1) * HMAP_ROWS / dvh.max(1)).min(HMAP_ROWS).max(r0 + 1);

        let mut worst = CellState::default();
        for r in r0..r1 {
            for c in c0..c1 {
                let s = self.get(c, r);
                // Priority: error > spike latency > slow > phase > untested
                if s.errors > worst.errors
                    || (s.errors == worst.errors && s.latency > worst.latency)
                    || (s.errors == 0 && worst.errors == 0 && s.phase > worst.phase)
                {
                    worst = s;
                }
            }
        }
        worst
    }
}

// ── Latency baseline tracker ──────────────────────────────────────────────────

/// Adaptive baseline for latency classification.
/// Calibrates on the first `BASELINE_N` measurements, then classifies relative to that.
pub struct LatencyBaseline {
    baseline_ns: u64,
    count:       u32,
}

const BASELINE_N: u32 = 16;

impl LatencyBaseline {
    pub fn new() -> Self {
        LatencyBaseline { baseline_ns: 0, count: 0 }
    }

    /// Feed a new timing sample (nanoseconds for `TIMING_STRIDE` words = 64 KiB).
    /// Returns the latency class for this sample.
    pub fn classify(&mut self, elapsed_ns: u64) -> u8 {
        // Build baseline from first N samples
        if self.count < BASELINE_N {
            self.baseline_ns = if self.count == 0 {
                elapsed_ns
            } else {
                (self.baseline_ns * self.count as u64 + elapsed_ns)
                    / (self.count as u64 + 1)
            };
            self.count += 1;
            return LAT_FAST; // assume fast during warmup
        }

        let base = self.baseline_ns.max(1);
        // ratio_x10 = elapsed * 10 / baseline
        let ratio_x10 = elapsed_ns.saturating_mul(10) / base;
        match ratio_x10 {
            0..=13  => LAT_FAST,   // ≤ 1.3× baseline
            14..=20 => LAT_NORMAL, // 1.3–2× baseline
            21..=40 => LAT_SLOW,   // 2–4× baseline
            _       => LAT_SPIKE,  // > 4× baseline
        }
    }
}
