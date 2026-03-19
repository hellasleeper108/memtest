use crate::heatmap::{LAT_FAST, LatencyBaseline, TIMING_STRIDE};
use crate::memory::MemRegion;
use crate::progress::DiagState;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A single detected memory error.
#[derive(Debug, Clone)]
pub struct MemError {
    pub offset: usize,
    pub expected: u64,
    pub actual: u64,
}

impl MemError {
    fn new(offset: usize, expected: u64, actual: u64) -> Self {
        MemError { offset, expected, actual }
    }
}

/// Result returned by every test function.
pub struct TestResult {
    pub name:       &'static str,
    pub errors:     Vec<MemError>,
    pub elapsed_ms: u64,
}

// Words between byte_pos updates (8 KiB).
const POS_STRIDE: usize = 1024;

// ── Heatmap stride ────────────────────────────────────────────────────────────
// Re-export from heatmap so tests can use it without importing heatmap directly.
// TIMING_STRIDE is defined in heatmap.rs and imported above.

// ── helper: parallel pattern verify ─────────────────────────────────────────

fn verify_pattern(region: &MemRegion, pattern: u64) -> Vec<MemError> {
    let words = region.as_u64_slice();
    let base  = region.ptr as usize;
    let count = AtomicU64::new(0);
    let mut v: Vec<MemError> = words
        .par_iter()
        .enumerate()
        .filter_map(|(i, &val)| {
            if val != pattern && count.fetch_add(1, Ordering::Relaxed) < 64 {
                Some(MemError::new(base + i * 8, pattern, val))
            } else {
                None
            }
        })
        .collect();
    v.truncate(64);
    v
}

// ── helper: timed sequential read with heatmap recording ────────────────────
//
// Reads `words_len` words from `base`, checking against `expected`.
// Updates `diag` with byte_pos, phase, and heatmap data every TIMING_STRIDE words.
// Appends up to 64 errors to `errors`.
// `phase_byte` is 1=writing or 2=reading for heatmap cell encoding.
unsafe fn timed_read_sequential(
    base:       *const u64,
    words_len:  usize,
    expected:   u64,
    ascending:  bool,
    diag:       &DiagState,
    errors:     &mut Vec<MemError>,
) {
    let mut lat = LatencyBaseline::new();
    let mut chunk_start = 0usize;
    let mut chunk_has_error = false;
    let mut t = Instant::now();

    let indices: Box<dyn Iterator<Item = usize>> = if ascending {
        Box::new(0..words_len)
    } else {
        Box::new((0..words_len).rev())
    };

    for i in indices {
        if i % POS_STRIDE == 0 {
            diag.reading_at((i * 8) as u64);
        }

        let got = base.add(i).read_volatile();
        if got != expected {
            chunk_has_error = true;
            if errors.len() < 64 {
                errors.push(MemError::new(i * 8, expected, got));
            }
        }

        let words_since_chunk_start = if ascending {
            i - chunk_start + 1
        } else {
            chunk_start - i + 1
        };

        if words_since_chunk_start >= TIMING_STRIDE || i + 1 == words_len || i == 0 && !ascending
        {
            let elapsed_ns = t.elapsed().as_nanos() as u64;
            let latency_class = lat.classify(elapsed_ns);
            let byte_start = chunk_start.min(i) as u64 * 8;
            let byte_len   = words_since_chunk_start as u64 * 8;
            diag.heatmap.record(byte_start, byte_len, 2, latency_class, chunk_has_error);
            chunk_start = if ascending { i + 1 } else { i.saturating_sub(1) };
            chunk_has_error = false;
            t = Instant::now();
        }
    }
}

// ── helper: timed sequential write with heatmap recording ────────────────────
unsafe fn timed_write_sequential(
    base:      *mut u64,
    words_len: usize,
    value:     u64,
    ascending: bool,
    diag:      &DiagState,
) {
    let mut chunk_start = 0usize;
    let mut t = Instant::now();
    let mut lat = LatencyBaseline::new();

    let indices: Box<dyn Iterator<Item = usize>> = if ascending {
        Box::new(0..words_len)
    } else {
        Box::new((0..words_len).rev())
    };

    for i in indices {
        if i % POS_STRIDE == 0 {
            diag.writing_at((i * 8) as u64);
        }
        base.add(i).write_volatile(value);

        let words_since = if ascending { i - chunk_start + 1 } else { chunk_start - i + 1 };
        if words_since >= TIMING_STRIDE || i + 1 == words_len || i == 0 && !ascending {
            let elapsed_ns = t.elapsed().as_nanos() as u64;
            let latency_class = lat.classify(elapsed_ns);
            let byte_start = chunk_start.min(i) as u64 * 8;
            let byte_len   = words_since as u64 * 8;
            diag.heatmap.record(byte_start, byte_len, 1, latency_class, false);
            chunk_start = if ascending { i + 1 } else { i.saturating_sub(1) };
            t = Instant::now();
        }
    }
}

// ── 1. Solid bits ─────────────────────────────────────────────────────────────
pub fn test_solid_bits(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();
    let mut errors = Vec::new();
    let sz = region.size as u64;

    for (step, &pat) in [0u64, u64::MAX].iter().enumerate() {
        if diag.cancelled() { break; }
        diag.set_pattern(pat);

        // Bulk fill (non-temporal) — mark whole region as writing
        diag.writing_at(0);
        diag.heatmap.set_all_phase(1);
        region.nt_fill_u64(pat);
        region.flush_all();
        diag.wrote(sz);

        // Parallel verify
        diag.reading_at(0);
        diag.heatmap.set_all_phase(2);
        let new_errs = verify_pattern(region, pat);
        // Mark error cells on heatmap
        for e in &new_errs {
            diag.heatmap.record(e.offset as u64, 8, 3, LAT_FAST, true);
        }
        diag.heatmap.set_all_phase(3);
        diag.read_done(sz);
        errors.extend(new_errs);
        diag.set_progress((step as u64 + 1) * 500);

        if errors.len() >= 64 { break; }
    }

    TestResult { name: "Solid Bits", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 2. Checkerboard ───────────────────────────────────────────────────────────
pub fn test_checkerboard(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();
    let mut errors = Vec::new();
    let sz = region.size as u64;

    for (step, &pat) in
        [0x5555_5555_5555_5555u64, 0xAAAA_AAAA_AAAA_AAAAu64].iter().enumerate()
    {
        if diag.cancelled() { break; }
        diag.set_pattern(pat);

        diag.writing_at(0);
        diag.heatmap.set_all_phase(1);
        region.nt_fill_u64(pat);
        region.flush_all();
        diag.wrote(sz);

        diag.reading_at(0);
        diag.heatmap.set_all_phase(2);
        let new_errs = verify_pattern(region, pat);
        for e in &new_errs {
            diag.heatmap.record(e.offset as u64, 8, 3, LAT_FAST, true);
        }
        diag.heatmap.set_all_phase(3);
        diag.read_done(sz);
        errors.extend(new_errs);
        diag.set_progress((step as u64 + 1) * 500);

        if errors.len() >= 64 { break; }
    }

    TestResult { name: "Checkerboard", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 3. Walking 1s / 0s ────────────────────────────────────────────────────────
pub fn test_walking_bits(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();
    let mut errors = Vec::new();
    let sz = region.size as u64;
    let mut step = 0u64;
    const TOTAL: u64 = 128;

    for bit in 0..64u32 {
        if diag.cancelled() { break; }
        let pat = 1u64 << bit;
        diag.set_pattern(pat);

        diag.writing_at(0);
        diag.heatmap.set_all_phase(1);
        region.nt_fill_u64(pat);
        region.flush_all();
        diag.wrote(sz);

        diag.reading_at(0);
        diag.heatmap.set_all_phase(2);
        let new_errs = verify_pattern(region, pat);
        for e in &new_errs { diag.heatmap.record(e.offset as u64, 8, 3, LAT_FAST, true); }
        diag.heatmap.set_all_phase(3);
        diag.read_done(sz);
        errors.extend(new_errs);
        step += 1;
        diag.set_progress(step * 1000 / TOTAL);

        if errors.len() >= 64 {
            return TestResult {
                name: "Walking 1s/0s",
                errors,
                elapsed_ms: t0.elapsed().as_millis() as u64,
            };
        }
    }

    for bit in 0..64u32 {
        if diag.cancelled() { break; }
        let pat = !(1u64 << bit);
        diag.set_pattern(pat);

        diag.writing_at(0);
        diag.heatmap.set_all_phase(1);
        region.nt_fill_u64(pat);
        region.flush_all();
        diag.wrote(sz);

        diag.reading_at(0);
        diag.heatmap.set_all_phase(2);
        let new_errs = verify_pattern(region, pat);
        for e in &new_errs { diag.heatmap.record(e.offset as u64, 8, 3, LAT_FAST, true); }
        diag.heatmap.set_all_phase(3);
        diag.read_done(sz);
        errors.extend(new_errs);
        step += 1;
        diag.set_progress(step * 1000 / TOTAL);

        if errors.len() >= 64 { break; }
    }

    TestResult { name: "Walking 1s/0s", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 4. March C- ───────────────────────────────────────────────────────────────
pub fn test_march_c(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();
    let mut errors = Vec::new();
    let words_len = region.size / 8;
    let sz = region.size as u64;
    let base = region.ptr as *mut u64;

    macro_rules! step {
        ($n:expr) => {
            diag.set_progress($n * 1000 / 6);
            if diag.cancelled() {
                return TestResult {
                    name: "March C-",
                    errors,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                };
            }
        };
    }

    unsafe {
        // M0: ascending write 0 — fully timed
        diag.set_pattern(0);
        timed_write_sequential(base, words_len, 0, true, diag);
        region.flush_all();
        diag.wrote(sz);
        step!(1);

        // M1: ascending read 0 → write 1 — read phase timed, write inline
        diag.set_pattern(0);
        {
            let mut lat = LatencyBaseline::new();
            let mut chunk_start = 0usize;
            let mut chunk_has_error = false;
            let mut t = Instant::now();

            for i in 0..words_len {
                if i % POS_STRIDE == 0 { diag.reading_at((i * 8) as u64); }

                let got = base.add(i).read_volatile();
                if got != 0 {
                    chunk_has_error = true;
                    if errors.len() < 64 { errors.push(MemError::new(i * 8, 0, got)); }
                }
                base.add(i).write_volatile(u64::MAX);

                let words_since = i - chunk_start + 1;
                if words_since >= TIMING_STRIDE || i + 1 == words_len {
                    let class = lat.classify(t.elapsed().as_nanos() as u64);
                    let bs = chunk_start as u64 * 8;
                    let bl = words_since as u64 * 8;
                    diag.heatmap.record(bs, bl, 2, class, chunk_has_error);
                    chunk_start = i + 1;
                    chunk_has_error = false;
                    t = Instant::now();
                }
            }
        }
        region.flush_all();
        diag.read_done(sz);
        diag.wrote(sz);
        step!(2);

        // M2: ascending read 1 → write 0 — timed
        diag.set_pattern(u64::MAX);
        {
            let mut lat = LatencyBaseline::new();
            let mut chunk_start = 0usize;
            let mut chunk_has_error = false;
            let mut t = Instant::now();

            for i in 0..words_len {
                if i % POS_STRIDE == 0 { diag.reading_at((i * 8) as u64); }
                let got = base.add(i).read_volatile();
                if got != u64::MAX {
                    chunk_has_error = true;
                    if errors.len() < 64 { errors.push(MemError::new(i * 8, u64::MAX, got)); }
                }
                base.add(i).write_volatile(0);
                let words_since = i - chunk_start + 1;
                if words_since >= TIMING_STRIDE || i + 1 == words_len {
                    let class = lat.classify(t.elapsed().as_nanos() as u64);
                    diag.heatmap.record(chunk_start as u64 * 8, words_since as u64 * 8, 2, class, chunk_has_error);
                    chunk_start = i + 1;
                    chunk_has_error = false;
                    t = Instant::now();
                }
            }
        }
        region.flush_all();
        diag.read_done(sz);
        diag.wrote(sz);
        step!(3);

        // M3: descending read 0 → write 1 — timed
        diag.set_pattern(0);
        {
            let mut lat = LatencyBaseline::new();
            let mut chunk_end = words_len;
            let mut chunk_has_error = false;
            let mut t = Instant::now();

            for i in (0..words_len).rev() {
                if i % POS_STRIDE == 0 { diag.reading_at((i * 8) as u64); }
                let got = base.add(i).read_volatile();
                if got != 0 {
                    chunk_has_error = true;
                    if errors.len() < 64 { errors.push(MemError::new(i * 8, 0, got)); }
                }
                base.add(i).write_volatile(u64::MAX);
                let words_since = chunk_end - i;
                if words_since >= TIMING_STRIDE || i == 0 {
                    let class = lat.classify(t.elapsed().as_nanos() as u64);
                    diag.heatmap.record(i as u64 * 8, words_since as u64 * 8, 2, class, chunk_has_error);
                    chunk_end = i;
                    chunk_has_error = false;
                    t = Instant::now();
                }
            }
        }
        region.flush_all();
        diag.read_done(sz);
        diag.wrote(sz);
        step!(4);

        // M4: descending read 1 → write 0 — timed
        diag.set_pattern(u64::MAX);
        {
            let mut lat = LatencyBaseline::new();
            let mut chunk_end = words_len;
            let mut chunk_has_error = false;
            let mut t = Instant::now();

            for i in (0..words_len).rev() {
                if i % POS_STRIDE == 0 { diag.reading_at((i * 8) as u64); }
                let got = base.add(i).read_volatile();
                if got != u64::MAX {
                    chunk_has_error = true;
                    if errors.len() < 64 { errors.push(MemError::new(i * 8, u64::MAX, got)); }
                }
                base.add(i).write_volatile(0);
                let words_since = chunk_end - i;
                if words_since >= TIMING_STRIDE || i == 0 {
                    let class = lat.classify(t.elapsed().as_nanos() as u64);
                    diag.heatmap.record(i as u64 * 8, words_since as u64 * 8, 2, class, chunk_has_error);
                    chunk_end = i;
                    chunk_has_error = false;
                    t = Instant::now();
                }
            }
        }
        region.flush_all();
        diag.read_done(sz);
        diag.wrote(sz);
        step!(5);

        // M5: ascending read 0 — timed
        diag.set_pattern(0);
        timed_read_sequential(base as *const u64, words_len, 0, true, diag, &mut errors);
        diag.heatmap.set_all_phase(3); // mark all verified
        diag.read_done(sz);
        step!(6);
    }

    TestResult { name: "March C-", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 5. Address pattern ────────────────────────────────────────────────────────
pub fn test_address_pattern(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();
    let words_len = region.size / 8;
    let sz = region.size as u64;
    let base = region.ptr as *mut u64;

    diag.set_pattern(0xADD0_0000_0000_0000);
    diag.heatmap.set_all_phase(1);
    unsafe {
        for i in 0..words_len {
            if i % POS_STRIDE == 0 { diag.writing_at((i * 8) as u64); }
            base.add(i).write_volatile(i as u64);
        }
        region.flush_all();
    }
    diag.wrote(sz);
    diag.set_progress(500);

    let mut errors = Vec::new();
    if !diag.cancelled() {
        diag.heatmap.set_all_phase(2);
        let words = region.as_u64_slice();
        let mut v: Vec<MemError> = words
            .par_iter()
            .enumerate()
            .filter_map(|(i, &val)| {
                if val != i as u64 { Some(MemError::new(i * 8, i as u64, val)) } else { None }
            })
            .collect();
        v.truncate(64);
        for e in &v { diag.heatmap.record(e.offset as u64, 8, 3, LAT_FAST, true); }
        diag.heatmap.set_all_phase(3);
        errors = v;
    }
    diag.read_done(sz);
    diag.set_progress(1000);

    TestResult { name: "Address Pattern", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 6. LFSR random pattern ────────────────────────────────────────────────────
pub fn test_random_pattern(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    let t0 = std::time::Instant::now();

    fn lfsr(s: u64) -> u64 {
        if s & 1 != 0 { (s >> 1) ^ 0xD800_0000_0000_0000 } else { s >> 1 }
    }

    let words_len = region.size / 8;
    let sz = region.size as u64;
    let base = region.ptr as *mut u64;
    const SEED: u64 = 0xDEAD_BEEF_CAFE_BABE;

    // Write with timing
    diag.heatmap.set_all_phase(1);
    unsafe {
        let mut state = SEED;
        let mut lat = LatencyBaseline::new();
        let mut chunk_start = 0usize;
        let mut t = Instant::now();

        for i in 0..words_len {
            if i % POS_STRIDE == 0 {
                diag.set_pattern(state);
                diag.writing_at((i * 8) as u64);
            }
            state = lfsr(state);
            base.add(i).write_volatile(state);

            let words_since = i - chunk_start + 1;
            if words_since >= TIMING_STRIDE || i + 1 == words_len {
                let class = lat.classify(t.elapsed().as_nanos() as u64);
                diag.heatmap.record(chunk_start as u64 * 8, words_since as u64 * 8, 1, class, false);
                chunk_start = i + 1;
                t = Instant::now();
            }
        }
        region.flush_all();
    }
    diag.wrote(sz);
    diag.set_progress(500);

    // Read with timing
    let mut errors = Vec::new();
    if !diag.cancelled() {
        diag.heatmap.set_all_phase(2);
        unsafe {
            let mut state = SEED;
            let mut lat = LatencyBaseline::new();
            let mut chunk_start = 0usize;
            let mut chunk_has_error = false;
            let mut t = Instant::now();

            for i in 0..words_len {
                if i % POS_STRIDE == 0 {
                    diag.set_pattern(state);
                    diag.reading_at((i * 8) as u64);
                }
                state = lfsr(state);
                let got = base.add(i).read_volatile();
                if got != state {
                    chunk_has_error = true;
                    if errors.len() < 64 { errors.push(MemError::new(i * 8, state, got)); }
                }
                let words_since = i - chunk_start + 1;
                if words_since >= TIMING_STRIDE || i + 1 == words_len {
                    let class = lat.classify(t.elapsed().as_nanos() as u64);
                    diag.heatmap.record(chunk_start as u64 * 8, words_since as u64 * 8, 2, class, chunk_has_error);
                    chunk_start = i + 1;
                    chunk_has_error = false;
                    t = Instant::now();
                }
            }
        }
        diag.heatmap.set_all_phase(3);
    }
    diag.read_done(sz);
    diag.set_progress(1000);

    TestResult { name: "LFSR Random", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}

// ── 7. Row Hammer ─────────────────────────────────────────────────────────────
pub fn test_rowhammer(region: &mut MemRegion, diag: &DiagState) -> TestResult {
    const ROW_SIZE:    usize = 8 * 1024;
    const HAMMER_ITERS: usize = 500_000;

    let t0 = std::time::Instant::now();
    let sz = region.size as u64;

    if region.size < ROW_SIZE * 3 {
        diag.set_progress(1000);
        return TestResult { name: "Row Hammer", errors: vec![], elapsed_ms: 0 };
    }

    diag.set_pattern(0xAAAA_AAAA_AAAA_AAAA);
    diag.writing_at(0);
    diag.heatmap.set_all_phase(1);
    region.nt_fill_u64(0xAAAA_AAAA_AAAA_AAAA);
    region.flush_all();
    diag.wrote(sz);
    diag.heatmap.set_all_phase(3);
    diag.set_progress(333);

    if !diag.cancelled() {
        let base = region.ptr;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use std::arch::x86_64::_mm_clflush;
            let a = base;
            let b = base.add(ROW_SIZE * 2);
            // Mark aggressors as "active write" on heatmap
            diag.heatmap.record(0, ROW_SIZE as u64, 1, 0, false);
            diag.heatmap.record(ROW_SIZE as u64 * 2, ROW_SIZE as u64, 1, 0, false);
            for _ in 0..HAMMER_ITERS {
                let _: u8 = a.read_volatile();
                _mm_clflush(a);
                let _: u8 = b.read_volatile();
                _mm_clflush(b);
            }
        }
        region.flush_all();
    }
    diag.set_progress(667);

    let mut errors = Vec::new();
    if !diag.cancelled() {
        let expected = 0xAAAA_AAAA_AAAA_AAAAu64;
        let num_rows = region.size / ROW_SIZE;
        let base = region.ptr;

        for row in 1..num_rows.saturating_sub(1) {
            let byte_off = (row * ROW_SIZE) as u64;
            diag.reading_at(byte_off);
            let row_ptr = unsafe { base.add(row * ROW_SIZE) as *const u64 };
            let mut row_has_error = false;
            for w in 0..ROW_SIZE / 8 {
                let val = unsafe { row_ptr.add(w).read_volatile() };
                if val != expected {
                    row_has_error = true;
                    if errors.len() < 64 {
                        errors.push(MemError::new(row * ROW_SIZE + w * 8, expected, val));
                    }
                }
            }
            diag.heatmap.record(byte_off, ROW_SIZE as u64, 3, LAT_FAST, row_has_error);
            if errors.len() >= 64 { break; }
        }
        diag.read_done(sz);
    }
    diag.set_progress(1000);

    TestResult { name: "Row Hammer", errors, elapsed_ms: t0.elapsed().as_millis() as u64 }
}
