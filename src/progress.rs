use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::heatmap::HeatmapData;

/// Current phase of the active test.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Phase {
    Idle    = 0,
    Writing = 1,
    Reading = 2,
}

impl Phase {
    pub fn from_u64(v: u64) -> Self {
        match v {
            1 => Phase::Writing,
            2 => Phase::Reading,
            _ => Phase::Idle,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Phase::Idle    => "Idle",
            Phase::Writing => "Writing",
            Phase::Reading => "Reading",
        }
    }
    pub fn arrow(self) -> &'static str {
        match self {
            Phase::Writing => "↓ ",
            Phase::Reading => "↑ ",
            Phase::Idle    => "  ",
        }
    }
}

/// All live diagnostic state shared between the worker thread and the UI thread.
/// All fields are atomics so the UI can read them at any time without locking.
pub struct DiagState {
    /// 0-1000 progress within the current test step.
    pub permille: AtomicU64,
    /// Byte offset in the region currently being processed.
    pub byte_pos: AtomicU64,
    /// Current Phase, encoded as u64.
    pub phase: AtomicU64,
    /// The 64-bit pattern currently being written / verified.
    pub pattern: AtomicU64,
    /// Cumulative bytes written across all tests this run (for bandwidth).
    pub bytes_written: AtomicU64,
    /// Cumulative bytes read across all tests this run (for bandwidth).
    pub bytes_read: AtomicU64,
    /// Set true by the UI to request graceful abort.
    pub cancel: AtomicBool,
    /// Live 2-D heatmap updated by the worker as it scans memory.
    pub heatmap: HeatmapData,
}

impl DiagState {
    pub fn new() -> Self {
        Self {
            permille:      AtomicU64::new(0),
            byte_pos:      AtomicU64::new(0),
            phase:         AtomicU64::new(0),
            pattern:       AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            bytes_read:    AtomicU64::new(0),
            cancel:        AtomicBool::new(false),
            heatmap:       HeatmapData::new(),
        }
    }

    /// Reset per-test fields. Cumulative bytes counters are NOT reset between tests.
    pub fn reset_for_test(&self) {
        self.permille.store(0, Ordering::Relaxed);
        self.byte_pos.store(0, Ordering::Relaxed);
        self.set_phase(Phase::Idle);
        self.pattern.store(0, Ordering::Relaxed);
        // Do NOT reset heatmap here — it accumulates across all tests in a run.
    }

    /// Reset everything for a brand-new test run (called by App::start_tests).
    pub fn reset_for_run(&self, region_size: u64) {
        self.reset_for_test();
        self.bytes_written.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
        self.cancel.store(false, Ordering::Relaxed);
        self.heatmap.reset();
        self.heatmap.region_size.store(region_size, Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn phase(&self) -> Phase {
        Phase::from_u64(self.phase.load(Ordering::Relaxed))
    }

    pub fn set_phase(&self, p: Phase) {
        self.phase.store(p as u64, Ordering::Relaxed);
    }

    pub fn set_pattern(&self, p: u64) {
        self.pattern.store(p, Ordering::Relaxed);
    }

    pub fn set_progress(&self, permille: u64) {
        self.permille.store(permille, Ordering::Relaxed);
    }

    /// Call at the start of a write sweep to set phase and position.
    pub fn writing_at(&self, byte_offset: u64) {
        self.byte_pos.store(byte_offset, Ordering::Relaxed);
        self.set_phase(Phase::Writing);
    }

    /// Call at the start of a read sweep to set phase and position.
    pub fn reading_at(&self, byte_offset: u64) {
        self.byte_pos.store(byte_offset, Ordering::Relaxed);
        self.set_phase(Phase::Reading);
    }

    /// Notify that a full write pass of `n_bytes` completed.
    pub fn wrote(&self, n_bytes: u64) {
        self.bytes_written.fetch_add(n_bytes, Ordering::Relaxed);
    }

    /// Notify that a full read pass of `n_bytes` completed.
    pub fn read_done(&self, n_bytes: u64) {
        self.bytes_read.fetch_add(n_bytes, Ordering::Relaxed);
    }
}
