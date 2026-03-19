use std::io::{self, Write as IoWrite};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, Paragraph, Row, Table},
};

use crate::dimm::{self, DimmInfo, DimmStats};
use crate::forensics::{self, Report as ForensicsReport, Sev};
use crate::recover::{self, RecoveryAction};
use crate::score::{self, StabilityScore};
use crate::syscheck::{EccStatus, KernelSev, SystemHealth};
use crate::heatmap::{CellState, LAT_SLOW, LAT_SPIKE};
use crate::memory::MemRegion;
use crate::progress::{DiagState, Phase};
use crate::sysinfo::{SysInfo, format_timestamp, format_timestamp_file};
use crate::tests::{
    MemError, TestResult, test_address_pattern, test_checkerboard, test_march_c,
    test_random_pattern, test_rowhammer, test_solid_bits, test_walking_bits,
};

// ── Catppuccin Mocha ─────────────────────────────────────────────────────────
const MAUVE:    Color = Color::Rgb(203, 166, 247);
const BLUE:     Color = Color::Rgb(137, 180, 250);
const SAPPHIRE: Color = Color::Rgb(116, 199, 236);
const GREEN:    Color = Color::Rgb(166, 227, 161);
const RED:      Color = Color::Rgb(243, 139, 168);
const YELLOW:   Color = Color::Rgb(249, 226, 175);
const PEACH:    Color = Color::Rgb(250, 179, 135);
const TEXT:     Color = Color::Rgb(205, 214, 244);
const SUBTEXT:  Color = Color::Rgb(147, 153, 178);
const SURFACE1: Color = Color::Rgb(69, 71, 90);
const SURFACE0: Color = Color::Rgb(49, 50, 68);
const BASE:     Color = Color::Rgb(30, 30, 46);

// ── Test registry ─────────────────────────────────────────────────────────────
type RunFn = fn(&mut MemRegion, &DiagState) -> TestResult;

const TESTS: &[(&str, RunFn)] = &[
    ("Solid Bits",      test_solid_bits),
    ("Checkerboard",    test_checkerboard),
    ("Walking 1s/0s",   test_walking_bits),
    ("March C-",        test_march_c),
    ("Address Pattern", test_address_pattern),
    ("LFSR Random",     test_random_pattern),
    ("Row Hammer",      test_rowhammer),
];

// ── Preset sizes ──────────────────────────────────────────────────────────────
const PRESETS: &[(&str, usize)] = &[
    ("256M", 256),
    ("512M", 512),
    (" 1 G", 1024),
    (" 4 G", 4096),
    (" MAX", 0), // 0 = use SysInfo::max_test_mib()
];

// ── Config field index layout ─────────────────────────────────────────────────
// F_MIB=0  F_PASSES=1  F_PRESET 2-6  F_TEST 7-13  F_START=14
const F_MIB:    usize = 0;
const F_PASSES: usize = 1;
const F_PRESET: usize = 2; // 2..2+5
const F_TEST:   usize = 7; // 7..7+7
const F_START:  usize = 14;
const F_MAX:    usize = 14;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen { Config, Running, Done, Forensics, Health, Recover }

struct CompletedTest {
    name:       &'static str,
    passed:     bool,
    elapsed_ms: u64,
    errors:     Vec<MemError>,
}

enum WorkerMsg {
    Started { idx: usize, total: usize, name: &'static str },
    Done(TestResult),
    AllDone,
}

/// Clickable regions tracked per frame.
#[derive(Clone, Copy)]
enum HitTarget {
    MibField,
    PassesField,
    Preset(usize),
    TestToggle(usize),
    StartBtn,
    DoneRow(usize),
}

// ── Heatmap color mapping ─────────────────────────────────────────────────────

fn cell_color(cell: CellState) -> Color {
    if cell.errors > 0 {
        RED
    } else if cell.latency >= LAT_SPIKE {
        PEACH
    } else if cell.latency >= LAT_SLOW {
        YELLOW
    } else {
        match cell.phase {
            3 => GREEN,    // verified
            2 => SAPPHIRE, // reading
            1 => BLUE,     // writing
            _ => SURFACE0, // untested
        }
    }
}

// ── Forensics renderer ────────────────────────────────────────────────────────

fn build_forensics_lines<'a>(
    errors: &[crate::tests::MemError],
    report: &forensics::Report,
) -> Vec<Line<'a>> {
    let mut lines: Vec<Line<'a>> = Vec::new();

    // ── Summary ──────────────────────────────────────────────────────────────
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{} error(s)", errors.len()),
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  across {} cluster(s)", report.clusters.len()),
            Style::default().fg(SUBTEXT),
        ),
    ]));
    lines.push(Line::raw(""));

    // ── Clusters ─────────────────────────────────────────────────────────────
    for (ci, cluster) in report.clusters.iter().enumerate() {
        let kind_col = match cluster.kind {
            forensics::ClusterKind::CacheLine => YELLOW,
            forensics::ClusterKind::Row       => RED,
            forensics::ClusterKind::Bank      => RED,
            forensics::ClusterKind::Scattered => PEACH,
        };

        // Cluster header line
        let header_label = format!(
            "  ▸ Cluster {}  —  {} error(s)  —  {} ─ {}",
            ci + 1,
            cluster.error_idxs.len(),
            cluster.kind.label(),
            cluster.kind.hint(),
        );
        lines.push(Line::from(vec![
            Span::styled(header_label, Style::default().fg(kind_col).add_modifier(Modifier::BOLD)),
        ]));

        // Individual errors (cap at 16 to avoid wall-of-text)
        let show_n = cluster.error_idxs.len().min(16);
        for &ei in cluster.error_idxs.iter().take(show_n) {
            let e = &errors[ei];
            let flip = e.expected as u64 ^ e.actual as u64;
            lines.push(Line::from(vec![
                Span::styled("    ", Style::default()),
                Span::styled(
                    forensics::fmt_addr(e.offset as u64),
                    Style::default().fg(MAUVE).add_modifier(Modifier::BOLD),
                ),
                Span::styled("  exp ", Style::default().fg(SUBTEXT)),
                Span::styled(
                    forensics::fmt_addr(e.expected as u64),
                    Style::default().fg(GREEN),
                ),
                Span::styled("  got ", Style::default().fg(SUBTEXT)),
                Span::styled(
                    forensics::fmt_addr(e.actual as u64),
                    Style::default().fg(RED),
                ),
                Span::styled("  diff ", Style::default().fg(SUBTEXT)),
                Span::styled(
                    forensics::fmt_addr(flip),
                    Style::default().fg(PEACH),
                ),
                Span::styled(
                    format!("  ({})", forensics::fmt_bits(flip)),
                    Style::default().fg(SUBTEXT),
                ),
            ]));
        }
        if cluster.error_idxs.len() > show_n {
            lines.push(Line::from(Span::styled(
                format!("    … and {} more", cluster.error_idxs.len() - show_n),
                Style::default().fg(SUBTEXT),
            )));
        }

        // Cluster summary line
        let common_str = if cluster.common_flip != 0 {
            format!("  consistent flip: {}", forensics::fmt_bits(cluster.common_flip))
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("    span {}{}",
                    forensics::fmt_span(cluster.span.max(8)),
                    common_str),
                Style::default().fg(SUBTEXT),
            ),
        ]));
        lines.push(Line::raw(""));
    }

    // ── Bit failure map ───────────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  Bit Failure Map",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));

    // Label row
    lines.push(Line::from(vec![
        Span::styled(
            "  63                             32  31                               0",
            Style::default().fg(SUBTEXT),
        ),
    ]));

    // Two rows of 32 bits each, grouped into nibbles of 8
    for row in 0..2usize {
        // row 0 = bits 63..32, row 1 = bits 31..0
        let bit_start = if row == 0 { 63i32 } else { 31 };
        let mut spans: Vec<Span<'a>> = vec![Span::raw("  ")];
        for i in 0..32usize {
            if i > 0 && i % 8 == 0 { spans.push(Span::raw(" ")); }
            let b = (bit_start - i as i32) as u64;
            let flips = report.bit_flips[b as usize];
            let (ch, col) = if flips == 0 {
                ("□", SURFACE1)
            } else if report.stuck_at_0 & (1 << b) != 0 {
                ("■", RED)
            } else if report.stuck_at_1 & (1 << b) != 0 {
                ("■", PEACH)
            } else {
                ("▪", YELLOW) // intermittent
            };
            spans.push(Span::styled(ch, Style::default().fg(col)));
        }
        lines.push(Line::from(spans));
    }

    // Legend for the bit map
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("■", Style::default().fg(RED)),
        Span::styled(" stuck-at-0  ", Style::default().fg(SUBTEXT)),
        Span::styled("■", Style::default().fg(PEACH)),
        Span::styled(" stuck-at-1  ", Style::default().fg(SUBTEXT)),
        Span::styled("▪", Style::default().fg(YELLOW)),
        Span::styled(" intermittent  ", Style::default().fg(SUBTEXT)),
        Span::styled("□", Style::default().fg(SURFACE1)),
        Span::styled(" clean", Style::default().fg(SUBTEXT)),
    ]));

    // Failing bit summary
    let any_stuck = report.stuck_at_0 | report.stuck_at_1;
    let any_flip_mask: u64 = report.bit_flips.iter().enumerate()
        .filter(|(_, n)| **n > 0)
        .fold(0u64, |acc, (b, _)| acc | (1u64 << b));
    if any_flip_mask != 0 {
        let mut parts: Vec<String> = Vec::new();
        for b in 0..64u64 {
            let f = report.bit_flips[b as usize];
            if f == 0 { continue; }
            let tag = if report.stuck_at_0 & (1 << b) != 0 { " stuck-0" }
                      else if report.stuck_at_1 & (1 << b) != 0 { " stuck-1" }
                      else { "" };
            parts.push(format!("bit {b} ({f}×{tag})"));
        }
        lines.push(Line::from(vec![
            Span::styled("  Failing: ", Style::default().fg(SUBTEXT)),
            Span::styled(parts.join("  "), Style::default().fg(
                if any_stuck != 0 { RED } else { YELLOW }
            )),
        ]));
    }
    lines.push(Line::raw(""));

    // ── Diagnosis ─────────────────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  Diagnosis",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));
    for dl in &report.diagnosis {
        let (icon, col) = match dl.sev {
            Sev::Crit => ("✗", RED),
            Sev::Warn => ("!", YELLOW),
            Sev::Info => ("·", SUBTEXT),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {icon}  "), Style::default().fg(col).add_modifier(Modifier::BOLD)),
            Span::styled(dl.text.clone(), Style::default().fg(
                match dl.sev { Sev::Crit => TEXT, Sev::Warn => YELLOW, Sev::Info => SUBTEXT }
            )),
        ]));
    }
    lines.push(Line::raw(""));

    lines
}

// ── App ───────────────────────────────────────────────────────────────────────

struct App {
    screen:  Screen,
    sysinfo: SysInfo,
    tick:    u64, // frame counter (for animation)

    // Config
    focused:    usize,
    mib_str:    String,
    passes_str: String,
    tests_on:   [bool; 7],

    // Running
    rx:           Option<mpsc::Receiver<WorkerMsg>>,
    diag:         Arc<DiagState>,
    current_name: &'static str,
    current_idx:  usize,
    total_tests:  usize,
    completed:    Vec<CompletedTest>,
    run_start:    Instant,
    test_start:   Instant,
    // 256-bucket error map: bucket i covers [i/256 .. (i+1)/256] of the region
    error_map:    [bool; 256],

    // Done
    total_errors:   usize,
    elapsed_s:      u64,
    summary_mib:    usize,
    summary_passes: usize,
    done_selected:  usize,
    done_expanded:  Option<usize>,
    done_scroll:    usize, // scroll offset in the results table
    log_path:       Option<String>,

    // Mouse
    hits: Vec<(Rect, HitTarget)>,

    // DIMM topology (empty when DMI unavailable)
    dimms:      Vec<DimmInfo>,
    dimm_stats: Vec<DimmStats>,

    // Forensics (populated when AllDone arrives)
    forensics_errors: Vec<crate::tests::MemError>,
    forensics_report: Option<ForensicsReport>,
    forensics_scroll: usize,

    // Stability score (populated when AllDone arrives)
    stability_score: Option<StabilityScore>,

    // System health (collected at startup)
    health:        SystemHealth,
    health_scroll: usize,

    // Recovery actions (generated after test completes)
    recovery:        Vec<RecoveryAction>,
    recover_scroll:  usize,
}

impl App {
    fn new() -> Self {
        let sysinfo = SysInfo::read();
        let dimms = dimm::read_dimms();
        let dimm_count = dimms.len();
        let health = SystemHealth::collect();
        App {
            screen:  Screen::Config,
            tick:    0,
            sysinfo,
            focused:    F_MIB,
            mib_str:    String::from("256"),
            passes_str: String::from("1"),
            tests_on:   [true; 7],
            rx:           None,
            diag:         Arc::new(DiagState::new()),
            current_name: "",
            current_idx:  0,
            total_tests:  0,
            completed:    Vec::new(),
            run_start:    Instant::now(),
            test_start:   Instant::now(),
            error_map:    [false; 256],
            total_errors:   0,
            elapsed_s:      0,
            summary_mib:    256,
            summary_passes: 1,
            done_selected:  0,
            done_expanded:  None,
            done_scroll:    0,
            log_path:       None,
            hits:           Vec::new(),
            dimms,
            dimm_stats:     vec![DimmStats::default(); dimm_count],
            forensics_errors: Vec::new(),
            forensics_report: None,
            forensics_scroll: 0,
            stability_score:  None,
            health,
            health_scroll:   0,
            recovery:        Vec::new(),
            recover_scroll:  0,
        }
    }

    fn mib(&self) -> usize {
        self.mib_str.parse::<usize>().unwrap_or(256).max(1).min(32768)
    }

    fn passes(&self) -> usize {
        self.passes_str.parse::<usize>().unwrap_or(1).max(1).min(999)
    }

    fn set_preset(&mut self, idx: usize) {
        let mib = if PRESETS[idx].1 == 0 {
            self.sysinfo.max_test_mib()
        } else {
            PRESETS[idx].1
        };
        self.mib_str = mib.to_string();
    }

    // ── Worker ───────────────────────────────────────────────────────────────

    fn start_tests(&mut self) {
        let mib = self.mib();
        let passes = self.passes();
        self.summary_mib = mib;
        self.summary_passes = passes;
        self.completed.clear();
        self.total_errors = 0;
        self.error_map = [false; 256];
        self.log_path = None;
        self.done_selected = 0;
        self.done_expanded = None;
        self.done_scroll = 0;

        let fns: Vec<(&'static str, RunFn)> = TESTS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.tests_on[*i])
            .map(|(_, &t)| t)
            .collect();

        if fns.is_empty() {
            return;
        }

        let total = fns.len() * passes;
        self.total_tests = total;
        self.current_idx = 0;
        self.current_name = fns[0].0;

        // Reset and reuse the DiagState for a fresh run
        self.diag.reset_for_run(mib as u64 * 1024 * 1024);
        self.dimm_stats = vec![DimmStats::default(); self.dimms.len()];

        let diag = Arc::clone(&self.diag);
        let (tx, rx) = mpsc::channel::<WorkerMsg>();
        self.rx = Some(rx);
        self.run_start = Instant::now();
        self.test_start = Instant::now();

        thread::spawn(move || {
            let size = mib * 1024 * 1024;
            let mut region = match MemRegion::allocate(size) {
                Ok(r) => r,
                Err(_) => {
                    let _ = tx.send(WorkerMsg::AllDone);
                    return;
                }
            };
            let mut idx = 0;
            'outer: for _ in 0..passes {
                for &(name, run) in &fns {
                    if diag.cancelled() {
                        break 'outer;
                    }
                    diag.reset_for_test();
                    let _ = tx.send(WorkerMsg::Started { idx, total, name });
                    let result = run(&mut region, &diag);
                    let _ = tx.send(WorkerMsg::Done(result));
                    idx += 1;
                }
            }
            let _ = tx.send(WorkerMsg::AllDone);
        });

        self.screen = Screen::Running;
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.rx else { return };
        loop {
            match rx.try_recv() {
                Ok(WorkerMsg::Started { idx, total, name }) => {
                    self.current_idx = idx;
                    self.total_tests = total;
                    self.current_name = name;
                    self.test_start = Instant::now();
                }
                Ok(WorkerMsg::Done(r)) => {
                    // Update error map and per-DIMM stats
                    let region_bytes = self.summary_mib as u64 * 1024 * 1024;
                    for e in &r.errors {
                        let b = ((e.offset as u64 * 256) / region_bytes.max(1)).min(255) as usize;
                        self.error_map[b] = true;
                        // Attribute error to a DIMM slot (proportional estimate)
                        if let Some(di) = dimm::attr_offset(&self.dimms, e.offset as u64, region_bytes) {
                            if di < self.dimm_stats.len() {
                                self.dimm_stats[di].errors += 1;
                            }
                        }
                    }
                    let ec = r.errors.len();
                    self.total_errors += ec;
                    self.completed.push(CompletedTest {
                        name: r.name,
                        passed: ec == 0,
                        elapsed_ms: r.elapsed_ms,
                        errors: r.errors,
                    });
                }
                Ok(WorkerMsg::AllDone) => {
                    self.elapsed_s = self.run_start.elapsed().as_secs();
                    self.screen = Screen::Done;
                    self.auto_save_log();
                    // Build forensics report from all collected errors
                    self.forensics_errors = self.completed
                        .iter()
                        .flat_map(|ct| ct.errors.iter().cloned())
                        .collect();
                    self.forensics_report = Some(forensics::analyze(&self.forensics_errors));
                    self.forensics_scroll = 0;

                    // Compute stability score from all available data.
                    let lat_counts = self.diag.heatmap.latency_counts();
                    let tests_per_pass = if self.summary_passes > 0 {
                        (self.completed.len() / self.summary_passes).min(7)
                    } else {
                        self.completed.len().min(7)
                    };
                    if let Some(fr) = &self.forensics_report {
                        self.stability_score = Some(score::compute(&score::ScoreInput {
                            total_errors: self.total_errors,
                            region_words: self.summary_mib as u64 * 1024 * 1024 / 8,
                            passes:       self.summary_passes,
                            tests_run:    tests_per_pass,
                            lat_counts,
                            forensics:    fr,
                        }));
                    }
                    // Generate recovery recommendations
                    self.recovery = recover::generate(
                        self.forensics_report.as_ref(),
                        &self.health,
                        self.total_errors,
                        self.summary_mib,
                    );
                    self.recover_scroll = 0;
                    // Ring the terminal bell
                    print!("\x07");
                    let _ = io::stdout().flush();
                    return;
                }
                Err(_) => break,
            }
        }
    }

    // ── Log saving ───────────────────────────────────────────────────────────

    fn auto_save_log(&mut self) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let filename = format!("ddr5-memtest-{}.log", format_timestamp_file(ts));
        let path = match home_dir() {
            Some(h) => h.join(&filename),
            None => PathBuf::from(&filename),
        };
        if let Ok(mut f) = std::fs::File::create(&path) {
            let _ = write_log(&mut f, self, &format_timestamp(ts));
            self.log_path = Some(path.display().to_string());
        }
    }

    // ── Key handling ─────────────────────────────────────────────────────────

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        match self.screen {
            Screen::Config    => self.handle_config_key(code, mods),
            Screen::Running   => self.handle_running_key(code, mods),
            Screen::Done      => self.handle_done_key(code),
            Screen::Forensics => self.handle_forensics_key(code),
            Screen::Health    => self.handle_health_key(code),
            Screen::Recover   => self.handle_recover_key(code),
        }
    }

    fn handle_config_key(&mut self, code: KeyCode, _mods: KeyModifiers) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.health_scroll = 0;
                self.screen = Screen::Health;
            }

            KeyCode::Tab | KeyCode::Down => {
                self.focused = (self.focused + 1) % (F_MAX + 1);
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focused = if self.focused == 0 { F_MAX } else { self.focused - 1 };
            }
            KeyCode::Left => {
                if (F_PRESET..F_PRESET + 5).contains(&self.focused) && self.focused > F_PRESET {
                    self.focused -= 1;
                }
            }
            KeyCode::Right => {
                if (F_PRESET..F_PRESET + 5).contains(&self.focused)
                    && self.focused < F_PRESET + 4
                {
                    self.focused += 1;
                }
            }

            KeyCode::Char(c) if c.is_ascii_digit() => match self.focused {
                F_MIB    if self.mib_str.len() < 5    => self.mib_str.push(c),
                F_PASSES if self.passes_str.len() < 3 => self.passes_str.push(c),
                _ => {}
            },
            KeyCode::Backspace => match self.focused {
                F_MIB    => { self.mib_str.pop(); }
                F_PASSES => { self.passes_str.pop(); }
                _ => {}
            },

            KeyCode::Char(' ') | KeyCode::Enter => {
                if (F_TEST..F_START).contains(&self.focused) {
                    let i = self.focused - F_TEST;
                    self.tests_on[i] = !self.tests_on[i];
                } else if (F_PRESET..F_PRESET + 5).contains(&self.focused) {
                    self.set_preset(self.focused - F_PRESET);
                } else if self.focused == F_START {
                    self.start_tests();
                } else if code == KeyCode::Enter {
                    self.focused = (self.focused + 1) % (F_MAX + 1);
                }
            }

            _ => {}
        }
        false
    }

    fn handle_forensics_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.screen = Screen::Done;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.forensics_scroll = self.forensics_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.forensics_scroll += 1;
            }
            KeyCode::PageUp => {
                self.forensics_scroll = self.forensics_scroll.saturating_sub(20);
            }
            KeyCode::PageDown => {
                self.forensics_scroll += 20;
            }
            _ => {}
        }
        false
    }

    fn handle_health_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.screen = Screen::Config;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.health_scroll = self.health_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.health_scroll += 1;
            }
            KeyCode::PageUp => {
                self.health_scroll = self.health_scroll.saturating_sub(20);
            }
            KeyCode::PageDown => {
                self.health_scroll += 20;
            }
            _ => {}
        }
        false
    }

    fn handle_recover_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.screen = Screen::Done;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.recover_scroll = self.recover_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.recover_scroll += 1;
            }
            KeyCode::PageUp => {
                self.recover_scroll = self.recover_scroll.saturating_sub(20);
            }
            KeyCode::PageDown => {
                self.recover_scroll += 20;
            }
            _ => {}
        }
        false
    }

    fn handle_running_key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.diag.cancel.store(true, Ordering::Relaxed);
            }
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
                self.diag.cancel.store(true, Ordering::Relaxed);
            }
            _ => {}
        }
        false
    }

    fn handle_done_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Char('f') | KeyCode::Char('F') => {
                if self.total_errors > 0 {
                    self.screen = Screen::Forensics;
                }
            }
            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.health_scroll = 0;
                self.screen = Screen::Health;
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.recover_scroll = 0;
                self.screen = Screen::Recover;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.screen = Screen::Config;
                self.completed.clear();
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.auto_save_log();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.done_selected > 0 {
                    self.done_selected -= 1;
                    self.done_expanded = None;
                }
                if self.done_selected < self.done_scroll {
                    self.done_scroll = self.done_selected;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.done_selected + 1 < self.completed.len() {
                    self.done_selected += 1;
                    self.done_expanded = None;
                }
            }
            KeyCode::Enter => {
                if self.done_expanded == Some(self.done_selected) {
                    self.done_expanded = None;
                } else if self.done_selected < self.completed.len()
                    && !self.completed[self.done_selected].errors.is_empty()
                {
                    self.done_expanded = Some(self.done_selected);
                }
            }
            _ => {}
        }
        false
    }

    // ── Mouse ────────────────────────────────────────────────────────────────

    fn handle_click(&mut self, col: u16, row: u16) {
        let hits = std::mem::take(&mut self.hits);
        for (rect, target) in &hits {
            if col >= rect.x
                && col < rect.x + rect.width
                && row >= rect.y
                && row < rect.y + rect.height
            {
                match *target {
                    HitTarget::MibField    => { self.focused = F_MIB; }
                    HitTarget::PassesField => { self.focused = F_PASSES; }
                    HitTarget::Preset(i)  => {
                        self.focused = F_PRESET + i;
                        self.set_preset(i);
                    }
                    HitTarget::TestToggle(i) => {
                        self.focused = F_TEST + i;
                        self.tests_on[i] = !self.tests_on[i];
                    }
                    HitTarget::StartBtn => {
                        if self.screen == Screen::Config {
                            self.start_tests();
                        }
                    }
                    HitTarget::DoneRow(i) => {
                        self.done_selected = i;
                        if self.done_expanded == Some(i) {
                            self.done_expanded = None;
                        } else if !self.completed[i].errors.is_empty() {
                            self.done_expanded = Some(i);
                        }
                    }
                }
                break;
            }
        }
        self.hits = hits;
    }

    // ── Drawing ──────────────────────────────────────────────────────────────

    fn draw(&mut self, f: &mut Frame) {
        self.tick = self.tick.wrapping_add(1);
        self.hits.clear();

        let area = f.area();
        f.render_widget(Block::default().style(Style::default().bg(BASE)), area);

        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Min(0),    // content
                Constraint::Length(1), // footer
            ])
            .split(area);

        self.draw_header(f, outer[0]);
        self.draw_footer(f, outer[2]);

        match self.screen {
            Screen::Config    => self.draw_config(f, outer[1]),
            Screen::Running   => self.draw_running(f, outer[1]),
            Screen::Done      => self.draw_done(f, outer[1]),
            Screen::Forensics => self.draw_forensics(f, outer[1]),
            Screen::Health    => self.draw_health(f, outer[1]),
            Screen::Recover   => self.draw_recover(f, outer[1]),
        }
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let title = Paragraph::new(Line::from(vec![
            Span::styled(" DDR5 ", Style::default().fg(MAUVE).add_modifier(Modifier::BOLD)),
            Span::styled("Memory Tester", Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(" v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(SUBTEXT),
            ),
        ]))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(MAUVE))
                .style(Style::default().bg(BASE)),
        );
        f.render_widget(title, area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let hints = match self.screen {
            Screen::Config =>
                "  Tab/↑↓ navigate   ←→ preset   Space/Enter toggle   H health   Q quit",
            Screen::Running => "  Q abort",
            Screen::Done => if self.total_errors > 0 {
                "  ↑↓/jk navigate   Enter expand   F forensics   X recover   H health   S save   R rerun   Q quit"
            } else {
                "  ↑↓/jk navigate   X recover   H health   S save log   R run again   Q quit"
            },
            Screen::Forensics =>
                "  ↑↓/jk scroll   PgUp/PgDn fast scroll   Q / Esc back",
            Screen::Health =>
                "  ↑↓/jk scroll   PgUp/PgDn fast scroll   Q / Esc back to config",
            Screen::Recover =>
                "  ↑↓/jk scroll   PgUp/PgDn fast scroll   Q / Esc back to results",
        };
        f.render_widget(
            Paragraph::new(hints).style(Style::default().fg(SUBTEXT).bg(BASE)),
            area,
        );
    }

    // ── Config ────────────────────────────────────────────────────────────────

    fn draw_config(&mut self, f: &mut Frame, area: Rect) {
        // DIMM panel height: 2 border rows + 1 row per slot (up to 8 shown).
        // Zero when DMI is unavailable so the panel is hidden.
        let dimm_h = if self.dimms.is_empty() {
            0u16
        } else {
            self.dimms.len().min(8) as u16 + 2
        };
        let dimm_sp = if self.dimms.is_empty() { 0u16 } else { 1u16 };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1),       // [0] sysinfo bar
                Constraint::Length(1),       // [1] spacer
                Constraint::Length(dimm_h),  // [2] DIMM panel   (0 = hidden)
                Constraint::Length(dimm_sp), // [3] spacer        (0 = hidden)
                Constraint::Length(6),       // [4] settings block
                Constraint::Length(1),       // [5] spacer
                Constraint::Min(9),          // [6] tests block
                Constraint::Length(1),       // [7] spacer
                Constraint::Length(3),       // [8] start button
            ])
            .split(area);

        // ── Sysinfo bar ──
        let cpu_str = if self.sysinfo.cpu_model.len() > 40 {
            format!("{}…", &self.sysinfo.cpu_model[..40])
        } else {
            self.sysinfo.cpu_model.clone()
        };
        let total_gb = self.sysinfo.total_ram_mib as f64 / 1024.0;
        let avail_gb = self.sysinfo.avail_ram_mib as f64 / 1024.0;
        let info_line = Line::from(vec![
            Span::styled("  CPU: ", Style::default().fg(SUBTEXT)),
            Span::styled(
                format!("{cpu_str}  ({} cores)", self.sysinfo.cpu_cores),
                Style::default().fg(TEXT),
            ),
            Span::styled("   RAM: ", Style::default().fg(SUBTEXT)),
            Span::styled(
                format!("{total_gb:.1} GiB total / {avail_gb:.1} GiB free"),
                Style::default().fg(TEXT),
            ),
        ]);
        f.render_widget(Paragraph::new(info_line), chunks[0]);

        // ── DIMM topology panel ──
        if dimm_h > 0 {
            self.draw_dimm_config_panel(f, chunks[2]);
        }

        // ── Settings block ──
        let settings_block = Block::default()
            .title(" Settings ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BLUE))
            .style(Style::default().bg(BASE));
        let sinner = settings_block.inner(chunks[4]);
        f.render_widget(settings_block, chunks[4]);

        let srows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // MiB row
                Constraint::Length(1), // Passes row
                Constraint::Length(1), // spacer
                Constraint::Length(1), // presets
            ])
            .split(sinner);

        // MiB input
        {
            let focused = self.focused == F_MIB;
            let r = srows[0];
            self.hits.push((r, HitTarget::MibField));
            let style = if focused {
                Style::default().fg(YELLOW).add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default().fg(BLUE)
            };
            let lbl = Style::default().fg(if focused { YELLOW } else { TEXT });
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("  Memory (MiB):  ", lbl),
                    Span::styled(format!(" {:>5} ", &self.mib_str), style),
                ])),
                r,
            );
        }

        // Passes input
        {
            let focused = self.focused == F_PASSES;
            let r = srows[1];
            self.hits.push((r, HitTarget::PassesField));
            let style = if focused {
                Style::default().fg(YELLOW).add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else {
                Style::default().fg(BLUE)
            };
            let lbl = Style::default().fg(if focused { YELLOW } else { TEXT });
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("  Passes:        ", lbl),
                    Span::styled(format!(" {:>5} ", &self.passes_str), style),
                ])),
                r,
            );
        }

        // Preset buttons
        {
            let r = srows[3];

            let btn_w = r.width.saturating_sub(11) / 5;
            let col_constraints: Vec<Constraint> =
                std::iter::once(Constraint::Length(11))
                    .chain((0..5).map(|_| Constraint::Length(btn_w.max(6))))
                    .collect();
            let preset_cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(col_constraints)
                .split(r);

            // render label in first col
            f.render_widget(
                Paragraph::new(Span::styled("  Quick: ", Style::default().fg(SUBTEXT))),
                preset_cols[0],
            );
            for (i, &(label, _)) in PRESETS.iter().enumerate() {
                let focused = self.focused == F_PRESET + i;
                let style = if focused {
                    Style::default().fg(BASE).bg(YELLOW).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(YELLOW).bg(SURFACE0)
                };
                let btn_rect = preset_cols[i + 1];
                self.hits.push((btn_rect, HitTarget::Preset(i)));
                f.render_widget(
                    Paragraph::new(Span::styled(format!(" {label} "), style))
                        .alignment(Alignment::Center)
                        .block(
                            Block::default()
                                .borders(Borders::LEFT | Borders::RIGHT)
                                .border_style(Style::default().fg(SURFACE1)),
                        ),
                    btn_rect,
                );
            }
        }

        // ── Tests block ──
        let tests_block = Block::default()
            .title(" Tests ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BLUE))
            .style(Style::default().bg(BASE));
        let tinner = tests_block.inner(chunks[6]);
        f.render_widget(tests_block, chunks[6]);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(tinner);

        let left:  Vec<usize> = (0..TESTS.len()).filter(|i| i % 2 == 0).collect();
        let right: Vec<usize> = (0..TESTS.len()).filter(|i| i % 2 == 1).collect();

        for (col_area, indices) in [(cols[0], &left), (cols[1], &right)] {
            let row_h = col_area.height / indices.len().max(1) as u16;
            for (row_i, &i) in indices.iter().enumerate() {
                let row_rect = Rect {
                    x:      col_area.x,
                    y:      col_area.y + row_i as u16 * row_h,
                    width:  col_area.width,
                    height: row_h.max(1),
                };
                self.hits.push((row_rect, HitTarget::TestToggle(i)));

                let focused = self.focused == F_TEST + i;
                let checked = self.tests_on[i];
                let check   = if checked { "✓" } else { " " };
                let fg = if focused { YELLOW } else if checked { GREEN } else { SUBTEXT };
                let line = Line::from(vec![
                    Span::styled(
                        if focused { "▶ " } else { "  " },
                        Style::default().fg(YELLOW),
                    ),
                    Span::styled(format!("[{check}] "), Style::default().fg(fg)),
                    Span::styled(
                        TESTS[i].0,
                        Style::default().fg(if focused { YELLOW } else { TEXT }),
                    ),
                ]);
                f.render_widget(Paragraph::new(line), row_rect);
            }
        }

        // ── Start button ──
        let focused = self.focused == F_START;
        let btn_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(40),
                Constraint::Percentage(30),
            ])
            .split(chunks[8])[1];
        self.hits.push((btn_area, HitTarget::StartBtn));

        f.render_widget(
            Paragraph::new(" ▶  START ")
                .alignment(Alignment::Center)
                .style(if focused {
                    Style::default().fg(BASE).bg(GREEN).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(GREEN).bg(SURFACE0).add_modifier(Modifier::BOLD)
                })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(if focused { GREEN } else { SURFACE1 }))
                        .style(Style::default().bg(BASE)),
                ),
            btn_area,
        );
    }

    // ── Stability Score panel (done screen) ───────────────────────────────────

    fn draw_score_panel(&self, f: &mut Frame, area: Rect) {
        let Some(sc) = &self.stability_score else {
            // Score not computed yet — show placeholder
            f.render_widget(
                Block::default()
                    .title(" Memory Stability Score ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(SURFACE1))
                    .style(Style::default().bg(BASE)),
                area,
            );
            return;
        };

        let score_col = match sc.total {
            90..=100 => GREEN,
            75..=89  => SAPPHIRE,
            60..=74  => YELLOW,
            40..=59  => PEACH,
            _        => RED,
        };

        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(" Memory Stability Score ", Style::default().fg(score_col).add_modifier(Modifier::BOLD)),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(score_col))
            .style(Style::default().bg(BASE));
        let inner = block.inner(area);
        f.render_widget(block, area);

        if inner.height == 0 { return; }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // score + bar
                Constraint::Length(1), // sub-metrics
                Constraint::Length(1), // verdict
            ])
            .split(inner);

        // ── Row 1: score number + progress bar ──
        let bar_w = inner.width.saturating_sub(14) as usize; // leave room for "  NN / 100  "
        let filled = (sc.total as usize * bar_w / 100).min(bar_w);
        let empty   = bar_w - filled;
        let bar: String = "█".repeat(filled) + &"░".repeat(empty);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!("  {:>3} / 100  ", sc.total),
                    Style::default().fg(score_col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(bar, Style::default().fg(score_col)),
            ])),
            rows[0],
        );

        // ── Row 2: sub-metrics ──
        let fail_str = if sc.pattern_fail_pct == 0.0 {
            "0%".to_string()
        } else {
            format!("{:.5}%", sc.pattern_fail_pct)
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  Latency variance: ", Style::default().fg(SUBTEXT)),
                Span::styled(sc.lat_variance.label(), Style::default().fg(
                    match sc.lat_variance {
                        score::LatVariance::Low      => GREEN,
                        score::LatVariance::Moderate => YELLOW,
                        score::LatVariance::High     => PEACH,
                        score::LatVariance::Critical => RED,
                    }
                )),
                Span::styled("  ·  Row disturbance risk: ", Style::default().fg(SUBTEXT)),
                Span::styled(sc.row_risk.label(), Style::default().fg(
                    match sc.row_risk {
                        score::RowRisk::None     => GREEN,
                        score::RowRisk::Low      => YELLOW,
                        score::RowRisk::Elevated => PEACH,
                        score::RowRisk::High     => RED,
                    }
                )),
                Span::styled("  ·  Pattern failure rate: ", Style::default().fg(SUBTEXT)),
                Span::styled(fail_str, Style::default().fg(
                    if self.total_errors == 0 { GREEN } else { RED }
                )),
                if sc.stuck_bits > 0 {
                    Span::styled(
                        format!("  ·  Stuck bits: {}", sc.stuck_bits),
                        Style::default().fg(RED).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw("")
                },
            ])),
            rows[1],
        );

        // ── Row 3: verdict ──
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  Verdict:  ", Style::default().fg(SUBTEXT)),
                Span::styled(
                    sc.verdict.label(),
                    Style::default().fg(score_col).add_modifier(Modifier::BOLD),
                ),
            ])),
            rows[2],
        );
    }

    // ── DIMM config panel (config screen) ─────────────────────────────────────

    fn draw_dimm_config_panel(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" DIMM Slots ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SAPPHIRE))
            .style(Style::default().bg(BASE));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let items: Vec<ListItem> = self
            .dimms
            .iter()
            .take(inner.height as usize)
            .map(|d| {
                if d.populated() {
                    let speed_str = if d.speed_mt > 0 {
                        format!("  {:>5} MT/s", d.speed_mt)
                    } else {
                        String::new()
                    };
                    let mfr_str = if d.manufacturer.is_empty() {
                        String::new()
                    } else {
                        format!("  {}", d.manufacturer)
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled("  ● ", Style::default().fg(GREEN)),
                        Span::styled(
                            format!("{:<18}", d.label()),
                            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:>6.1} GiB", d.size_gib()),
                            Style::default().fg(SAPPHIRE),
                        ),
                        Span::styled(
                            format!("  {:<6}", d.mem_type),
                            Style::default().fg(BLUE),
                        ),
                        Span::styled(speed_str, Style::default().fg(SUBTEXT)),
                        Span::styled(mfr_str, Style::default().fg(SUBTEXT)),
                    ]))
                } else {
                    ListItem::new(Line::from(vec![
                        Span::styled("  ○ ", Style::default().fg(SURFACE1)),
                        Span::styled(
                            format!("{:<18}", d.label()),
                            Style::default().fg(SUBTEXT),
                        ),
                        Span::styled("  [empty]", Style::default().fg(SURFACE1)),
                    ]))
                }
            })
            .collect();

        f.render_widget(List::new(items).style(Style::default().bg(BASE)), inner);
    }

    // ── DIMM done panel (done screen) ─────────────────────────────────────────

    fn draw_dimm_done_panel(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" DIMM Results  ~estimated ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SAPPHIRE))
            .style(Style::default().bg(BASE));
        let inner = block.inner(area);
        f.render_widget(block, area);

        // Total populated DIMM MB for proportional error-rate denominator.
        let total_mb: u64 = self.dimms.iter().filter(|d| d.populated()).map(|d| d.size_mb).sum();
        let region_words = self.summary_mib as u64 * 1024 * 1024 / 8;

        let items: Vec<ListItem> = self
            .dimms
            .iter()
            .zip(self.dimm_stats.iter())
            .filter(|(d, _)| d.populated())
            .take(inner.height as usize)
            .map(|(d, stats)| {
                let (icon, icon_col, status_spans) = if stats.errors == 0 {
                    (
                        "✓",
                        GREEN,
                        vec![Span::styled("  OK", Style::default().fg(GREEN))],
                    )
                } else {
                    // Error rate relative to the fraction of the region this DIMM covers.
                    let dimm_frac = if total_mb > 0 {
                        d.size_mb as f64 / total_mb as f64
                    } else {
                        1.0
                    };
                    let dimm_words = (region_words as f64 * dimm_frac) as u64;
                    let rate_pct = if dimm_words > 0 {
                        stats.errors as f64 / dimm_words as f64 * 100.0
                    } else {
                        0.0
                    };
                    (
                        "✗",
                        RED,
                        vec![
                            Span::styled(
                                format!("  ERROR RATE {rate_pct:.4}%"),
                                Style::default().fg(RED).add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(
                                format!("  ({} errors)", stats.errors),
                                Style::default().fg(PEACH),
                            ),
                        ],
                    )
                };

                let speed_str = if d.speed_mt > 0 {
                    format!("  {:>5} MT/s", d.speed_mt)
                } else {
                    String::new()
                };

                let mut spans = vec![
                    Span::styled(
                        format!("  {icon}  "),
                        Style::default().fg(icon_col).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<18}", d.label()),
                        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:>6.1} GiB", d.size_gib()),
                        Style::default().fg(SAPPHIRE),
                    ),
                    Span::styled(
                        format!("  {:<6}", d.mem_type),
                        Style::default().fg(BLUE),
                    ),
                    Span::styled(speed_str, Style::default().fg(SUBTEXT)),
                ];
                spans.extend(status_spans);
                ListItem::new(Line::from(spans))
            })
            .collect();

        f.render_widget(List::new(items).style(Style::default().bg(BASE)), inner);
    }

    // ── Running ───────────────────────────────────────────────────────────────

    fn draw_running(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // status bar
                Constraint::Length(11), // heatmap block (8 data rows + 1 legend + 2 border)
                Constraint::Length(5),  // live diagnostics block
                Constraint::Min(4),     // results list
            ])
            .split(area);

        let elapsed  = self.run_start.elapsed();
        let h = elapsed.as_secs() / 3600;
        let m = (elapsed.as_secs() % 3600) / 60;
        let s = elapsed.as_secs() % 60;
        let perm = self.diag.permille.load(Ordering::Relaxed).min(1000);

        // ── Status bar (plain, no block) ──
        let is_aborting = self.diag.cancelled();
        let status_line = Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                self.current_name,
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  ({}/{})", self.current_idx + 1, self.total_tests),
                Style::default().fg(SUBTEXT),
            ),
            Span::styled(
                format!("   {} MiB", self.summary_mib),
                Style::default().fg(TEXT),
            ),
            Span::styled(
                format!("   Pass {}/{}",
                    self.completed.len() / TESTS.len().max(1) + 1,
                    self.summary_passes),
                Style::default().fg(SUBTEXT),
            ),
            Span::styled(
                format!("   {:02}:{:02}:{:02}", h, m, s),
                Style::default().fg(SAPPHIRE),
            ),
            if is_aborting {
                Span::styled("   ⚠ aborting…", Style::default().fg(YELLOW))
            } else {
                Span::raw("")
            },
        ]);
        f.render_widget(
            Paragraph::new(status_line)
                .block(Block::default().style(Style::default().bg(BASE))),
            chunks[0],
        );

        // ── Heatmap block ──
        let hmap_block = Block::default()
            .title(" Memory Heatmap ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SURFACE1))
            .style(Style::default().bg(BASE));
        let hmap_inner = hmap_block.inner(chunks[1]);
        f.render_widget(hmap_block, chunks[1]);

        let hmap_w = hmap_inner.width as usize;
        // Reserve last inner row for legend; remaining rows are data (half-block = 2 virtual rows each)
        let hmap_data_h = hmap_inner.height.saturating_sub(1) as usize;
        let dvh = (hmap_data_h * 2).max(1);

        // Shared diagnostics state used by heatmap and live panels
        let phase       = self.diag.phase();
        let byte_pos    = self.diag.byte_pos.load(Ordering::Relaxed);
        let region_size = self.summary_mib as u64 * 1024 * 1024;
        let head_col = if region_size > 0 && hmap_w > 0 {
            Some(((byte_pos * hmap_w as u64) / region_size.max(1)) as usize)
        } else {
            None
        };
        let anim_bright = self.tick % 6 < 3;

        for ty in 0..hmap_data_h {
            let vr_top = ty * 2;
            let vr_bot = ty * 2 + 1;
            let spans: Vec<Span> = (0..hmap_w)
                .map(|col| {
                    let top = self.diag.heatmap.sample(col, vr_top, hmap_w, dvh);
                    let bot = self.diag.heatmap.sample(col, vr_bot, hmap_w, dvh);
                    let mut fg = cell_color(top);
                    let mut bg = cell_color(bot);
                    // Animated sweep head
                    if head_col == Some(col) {
                        let head_c = if anim_bright { YELLOW } else { PEACH };
                        fg = head_c;
                        bg = head_c;
                    }
                    Span::styled("▀", Style::default().fg(fg).bg(bg))
                })
                .collect();
            let row_rect = Rect {
                x:      hmap_inner.x,
                y:      hmap_inner.y + ty as u16,
                width:  hmap_inner.width,
                height: 1,
            };
            f.render_widget(Paragraph::new(Line::from(spans)), row_rect);
        }

        // Legend row
        if hmap_inner.height > 0 {
            let legend_rect = Rect {
                x:      hmap_inner.x,
                y:      hmap_inner.y + hmap_data_h as u16,
                width:  hmap_inner.width,
                height: 1,
            };
            let legend = Line::from(vec![
                Span::styled("▀", Style::default().fg(SURFACE0).bg(BASE)),
                Span::styled(" Untested ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(BLUE).bg(BASE)),
                Span::styled(" Write ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(SAPPHIRE).bg(BASE)),
                Span::styled(" Read ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(GREEN).bg(BASE)),
                Span::styled(" OK ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(YELLOW).bg(BASE)),
                Span::styled(" Slow ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(PEACH).bg(BASE)),
                Span::styled(" Spike ", Style::default().fg(SUBTEXT)),
                Span::styled("▀", Style::default().fg(RED).bg(BASE)),
                Span::styled(" Error", Style::default().fg(SUBTEXT)),
            ]);
            f.render_widget(Paragraph::new(legend), legend_rect);
        }

        // ── Live diagnostics block ──
        let diag_block = Block::default()
            .title(" Live ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SURFACE1))
            .style(Style::default().bg(BASE));
        let diag_inner = diag_block.inner(chunks[2]);
        f.render_widget(diag_block, chunks[2]);

        let diag_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // phase + pattern hex
                Constraint::Length(1), // 64-bit pattern visualizer
                Constraint::Length(1), // bandwidth + ETA
            ])
            .split(diag_inner);

        // Row 1: phase + pattern
        let pattern = self.diag.pattern.load(Ordering::Relaxed);
        let phase_col = match phase {
            Phase::Writing => BLUE,
            Phase::Reading => GREEN,
            Phase::Idle    => SUBTEXT,
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  Phase: ", Style::default().fg(SUBTEXT)),
                Span::styled(phase.arrow(), Style::default().fg(phase_col)),
                Span::styled(
                    format!("{:<9}", phase.label()),
                    Style::default().fg(phase_col).add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Pattern: ", Style::default().fg(SUBTEXT)),
                Span::styled(
                    format!("{:#018x}", pattern),
                    Style::default().fg(MAUVE).add_modifier(Modifier::BOLD),
                ),
            ])),
            diag_rows[0],
        );

        // Row 2: bit visualizer
        let available_w = diag_rows[1].width.saturating_sub(4) as usize; // 2 indent + 2 pad
        let bits_to_show = 64.min(available_w);
        let bit_spans: Vec<Span> = (0..bits_to_show)
            .map(|b| {
                // map display bit b to actual bit (MSB first)
                let actual_bit = 63 - (b * 63 / bits_to_show.max(1));
                let set = (pattern >> actual_bit) & 1 == 1;
                let (ch, fg) = if set { ('■', phase_col) } else { ('□', SURFACE1) };
                Span::styled(ch.to_string(), Style::default().fg(fg))
            })
            .collect();
        let mut bit_line = vec![Span::raw("  ")];
        bit_line.extend(bit_spans);
        f.render_widget(Paragraph::new(Line::from(bit_line)), diag_rows[1]);

        // Row 3: bandwidth + ETA + progress gauge
        let total_elapsed = self.run_start.elapsed().as_secs_f64();
        let bw_written = self.diag.bytes_written.load(Ordering::Relaxed) as f64;
        let bw_read    = self.diag.bytes_read.load(Ordering::Relaxed) as f64;
        let write_gbs  = if total_elapsed > 0.1 { bw_written / total_elapsed / 1e9 } else { 0.0 };
        let read_gbs   = if total_elapsed > 0.1 { bw_read / total_elapsed / 1e9 } else { 0.0 };

        // ETA: based on overall fraction done
        let done_frac = if self.total_tests > 0 {
            (self.completed.len() as f64 + perm as f64 / 1000.0) / self.total_tests as f64
        } else {
            0.0
        };
        let eta_str = if done_frac > 0.005 && done_frac < 0.999 {
            let eta_s = (total_elapsed / done_frac * (1.0 - done_frac)) as u64;
            if eta_s < 60 {
                format!("ETA: ~{eta_s}s")
            } else {
                format!("ETA: ~{}m{:02}s", eta_s / 60, eta_s % 60)
            }
        } else {
            String::from("ETA: --")
        };

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  Write: ", Style::default().fg(SUBTEXT)),
                Span::styled(format!("{write_gbs:>5.1} GB/s"), Style::default().fg(BLUE)),
                Span::styled("   Read: ", Style::default().fg(SUBTEXT)),
                Span::styled(format!("{read_gbs:>5.1} GB/s"), Style::default().fg(GREEN)),
                Span::styled(format!("   {eta_str}"), Style::default().fg(PEACH)),
                Span::styled(
                    format!("   {:.1}%", perm as f64 / 10.0),
                    Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
                ),
            ])),
            diag_rows[2],
        );

        // ── Results list ──
        let results_block = Block::default()
            .title(" Results ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SURFACE1))
            .style(Style::default().bg(BASE));
        let results_inner = results_block.inner(chunks[3]);
        f.render_widget(results_block, chunks[3]);

        let tests_per_pass = TESTS.iter().filter(|_| true).count(); // enabled count
        let enabled: Vec<usize> = (0..TESTS.len()).filter(|i| self.tests_on[*i]).collect();
        let completed_in_pass = self.completed.len() % enabled.len().max(1);

        let mut items: Vec<ListItem> = Vec::new();

        for ct in &self.completed {
            let (icon, fg) =
                if ct.passed { ("✓", GREEN) } else { ("✗", RED) };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  {icon}  "),
                    Style::default().fg(fg).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{:<20}", ct.name), Style::default().fg(TEXT)),
                Span::styled(
                    format!("{:>7} ms", ct.elapsed_ms),
                    Style::default().fg(SUBTEXT),
                ),
                if !ct.errors.is_empty() {
                    Span::styled(
                        format!("  {} err", ct.errors.len()),
                        Style::default().fg(RED),
                    )
                } else {
                    Span::raw("")
                },
            ])));
        }

        // Running test marker
        if completed_in_pass < enabled.len() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "  ⟳  ",
                    Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<20}", self.current_name),
                    Style::default().fg(YELLOW),
                ),
                Span::styled("     …", Style::default().fg(SUBTEXT)),
            ])));
        }

        // Pending tests
        let _ = tests_per_pass; // suppress warning
        for &ei in enabled.iter().skip(completed_in_pass + 1) {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("  ·  ", Style::default().fg(SURFACE1)),
                Span::styled(TESTS[ei].0, Style::default().fg(SUBTEXT)),
            ])));
        }

        f.render_widget(List::new(items).style(Style::default().bg(BASE)), results_inner);
    }

    // ── Forensics ─────────────────────────────────────────────────────────────

    fn draw_forensics(&mut self, f: &mut Frame, area: Rect) {
        let outer_block = Block::default()
            .title(Line::from(vec![
                Span::styled(" Error Forensics ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!("— {} error(s) ", self.forensics_errors.len()),
                    Style::default().fg(SUBTEXT),
                ),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(RED))
            .style(Style::default().bg(BASE));
        let inner = outer_block.inner(area);
        f.render_widget(outer_block, area);

        let Some(report) = &self.forensics_report else { return };

        // Build all lines for the scrollable view.
        let lines = build_forensics_lines(&self.forensics_errors, report);

        // Clamp scroll
        let max_scroll = lines.len().saturating_sub(inner.height as usize);
        self.forensics_scroll = self.forensics_scroll.min(max_scroll);

        use ratatui::text::Text;
        let text = Text::from(lines);
        f.render_widget(
            Paragraph::new(text)
                .scroll((self.forensics_scroll as u16, 0))
                .style(Style::default().bg(BASE)),
            inner,
        );
    }

    // ── Done ──────────────────────────────────────────────────────────────────

    fn draw_done(&mut self, f: &mut Frame, area: Rect) {
        let all_pass = self.total_errors == 0;
        let (res_str, res_col) = if all_pass {
            ("✓  ALL TESTS PASSED", GREEN)
        } else {
            ("✗  FAILURES DETECTED", RED)
        };

        let outer_block = Block::default()
            .title(Line::from(vec![
                Span::styled(
                    format!(" {res_str} "),
                    Style::default().fg(res_col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "── {} MiB ── {} pass{} ── {}s ",
                        self.summary_mib,
                        self.summary_passes,
                        if self.summary_passes == 1 { "" } else { "es" },
                        self.elapsed_s
                    ),
                    Style::default().fg(SUBTEXT),
                ),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(res_col))
            .style(Style::default().bg(BASE));

        let outer_inner = outer_block.inner(area);
        f.render_widget(outer_block, area);

        // ── Stability Score panel ──
        let (score_area, below_score) = {
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(0)])
                .split(outer_inner);
            (split[0], split[1])
        };
        self.draw_score_panel(f, score_area);

        // ── Per-DIMM summary (only when DIMM data available) ──
        let populated_dimm_count = self.dimms.iter().filter(|d| d.populated()).count();
        let (content_area, dimm_area) = if populated_dimm_count > 0 {
            let dimm_h = populated_dimm_count.min(6) as u16 + 2; // border + rows
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(dimm_h), Constraint::Min(0)])
                .split(below_score);
            (split[1], Some(split[0]))
        } else {
            (below_score, None)
        };

        if let Some(da) = dimm_area {
            self.draw_dimm_done_panel(f, da);
        }

        // Reserve bottom row for log path
        let (table_area, log_area) = if self.log_path.is_some() {
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(1)])
                .split(content_area);
            (split[0], Some(split[1]))
        } else {
            (content_area, None)
        };

        // Split table_area if we need an error expansion panel
        let (results_area, errors_area) = if self.done_expanded.is_some() {
            let h = (table_area.height / 2).max(3);
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(h)])
                .split(table_area);
            (split[0], Some(split[1]))
        } else {
            (table_area, None)
        };

        // ── Results table ──
        let header = Row::new(vec![
            Cell::from("  Test")
                .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Cell::from("Result")
                .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Cell::from("Time")
                .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
            Cell::from("Errors")
                .style(Style::default().fg(BLUE).add_modifier(Modifier::BOLD)),
        ])
        .height(1)
        .bottom_margin(1);

        // Scroll so selected row is visible
        let visible = results_area.height.saturating_sub(3) as usize; // approx
        if self.done_selected >= self.done_scroll + visible {
            self.done_scroll = self.done_selected + 1 - visible;
        }
        if self.done_selected < self.done_scroll {
            self.done_scroll = self.done_selected;
        }

        let row_y_base = results_area.y + 2; // after border + header
        let rows: Vec<Row> = self
            .completed
            .iter()
            .enumerate()
            .skip(self.done_scroll)
            .take(visible)
            .map(|(i, ct)| {
                let (icon, col) = if ct.passed { ("PASS", GREEN) } else { ("FAIL", RED) };
                let selected = i == self.done_selected;
                let expandable = !ct.errors.is_empty();
                let base_style = if selected {
                    Style::default().bg(SURFACE0)
                } else {
                    Style::default().bg(BASE)
                };

                let expand_hint = if selected && expandable { " ↵" } else { "" };

                Row::new(vec![
                    Cell::from(format!(
                        "  {}{}{}",
                        if selected { "▶ " } else { "  " },
                        ct.name,
                        expand_hint
                    ))
                    .style(base_style.fg(if selected { YELLOW } else { TEXT })),
                    Cell::from(icon)
                        .style(base_style.fg(col).add_modifier(Modifier::BOLD)),
                    Cell::from(format!("{} ms", ct.elapsed_ms))
                        .style(base_style.fg(SUBTEXT)),
                    Cell::from(if ct.errors.is_empty() {
                        "0".to_string()
                    } else {
                        ct.errors.len().to_string()
                    })
                    .style(base_style.fg(if ct.errors.is_empty() { SUBTEXT } else { RED })),
                ])
                .style(base_style)
            })
            .collect();

        // Register click zones
        for (i, _) in self.completed.iter().enumerate().skip(self.done_scroll).take(visible) {
            let row_rect = Rect {
                x:      results_area.x + 1,
                y:      row_y_base + (i - self.done_scroll) as u16,
                width:  results_area.width.saturating_sub(2),
                height: 1,
            };
            self.hits.push((row_rect, HitTarget::DoneRow(i)));
        }

        let table = Table::new(
            rows,
            [
                Constraint::Fill(1),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .header(header)
        .style(Style::default().bg(BASE));

        f.render_widget(table, results_area);

        // ── Error expansion panel ──
        if let (Some(exp_i), Some(ea)) = (self.done_expanded, errors_area) {
            if exp_i < self.completed.len() {
                let ct = &self.completed[exp_i];
                let err_block = Block::default()
                    .title(format!(" Errors: {} ", ct.name))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(RED))
                    .style(Style::default().bg(BASE));
                let err_inner = err_block.inner(ea);
                f.render_widget(err_block, ea);

                let items: Vec<ListItem> = ct
                    .errors
                    .iter()
                    .map(|e| {
                        ListItem::new(Line::from(vec![
                            Span::styled(
                                format!("  offset {:#012x}", e.offset),
                                Style::default().fg(SUBTEXT),
                            ),
                            Span::styled(
                                format!("  exp {:#018x}", e.expected),
                                Style::default().fg(GREEN),
                            ),
                            Span::styled(
                                format!("  got {:#018x}", e.actual),
                                Style::default().fg(RED),
                            ),
                            Span::styled(
                                format!("  diff {:#018x}", e.expected ^ e.actual),
                                Style::default().fg(PEACH),
                            ),
                        ]))
                    })
                    .collect();
                f.render_widget(
                    List::new(items).style(Style::default().bg(BASE)),
                    err_inner,
                );
            }
        }

        // ── Log path ──
        if let (Some(path), Some(la)) = (&self.log_path, log_area) {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("  Saved: ", Style::default().fg(SUBTEXT)),
                    Span::styled(path.as_str(), Style::default().fg(SAPPHIRE)),
                ])),
                la,
            );
        }
    }

    // ── System Health ──────────────────────────────────────────────────────────

    fn draw_health(&mut self, f: &mut Frame, area: Rect) {
        let outer_block = Block::default()
            .title(Line::from(vec![
                Span::styled(" System Health ", Style::default().fg(SAPPHIRE).add_modifier(Modifier::BOLD)),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SAPPHIRE))
            .style(Style::default().bg(BASE));
        let inner = outer_block.inner(area);
        f.render_widget(outer_block, area);

        let lines = build_health_lines(&self.health);
        let max_scroll = lines.len().saturating_sub(inner.height as usize);
        self.health_scroll = self.health_scroll.min(max_scroll);

        use ratatui::text::Text;
        f.render_widget(
            Paragraph::new(Text::from(lines))
                .scroll((self.health_scroll as u16, 0))
                .style(Style::default().bg(BASE)),
            inner,
        );
    }

    // ── Recovery Recommendations ───────────────────────────────────────────────

    fn draw_recover(&mut self, f: &mut Frame, area: Rect) {
        let outer_block = Block::default()
            .title(Line::from(vec![
                Span::styled(" Recovery Recommendations ", Style::default().fg(PEACH).add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!("— {} action(s) ", self.recovery.len()),
                    Style::default().fg(SUBTEXT),
                ),
            ]))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(PEACH))
            .style(Style::default().bg(BASE));
        let inner = outer_block.inner(area);
        f.render_widget(outer_block, area);

        let lines = build_recover_lines(&self.recovery);
        let max_scroll = lines.len().saturating_sub(inner.height as usize);
        self.recover_scroll = self.recover_scroll.min(max_scroll);

        use ratatui::text::Text;
        f.render_widget(
            Paragraph::new(Text::from(lines))
                .scroll((self.recover_scroll as u16, 0))
                .style(Style::default().bg(BASE)),
            inner,
        );
    }
}

// ── Health screen builder ─────────────────────────────────────────────────────

fn build_health_lines(h: &SystemHealth) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    // ── ECC status ────────────────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  ECC Status",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));
    let (ecc_text, ecc_col) = match &h.ecc {
        EccStatus::Enabled(mode) => (format!("Enabled ({mode})"), GREEN),
        EccStatus::Disabled      => ("Disabled".to_string(), YELLOW),
        EccStatus::Unknown       => ("Unknown — EDAC not available".to_string(), SUBTEXT),
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(ecc_text, Style::default().fg(ecc_col).add_modifier(Modifier::BOLD)),
    ]));

    // EDAC controllers
    if h.edac_mcs.is_empty() {
        lines.push(Line::from(Span::styled(
            "    No EDAC memory controllers found",
            Style::default().fg(SUBTEXT),
        )));
    } else {
        for mc in &h.edac_mcs {
            let ce_col = if mc.ce_count > 0 { YELLOW } else { SUBTEXT };
            let ue_col = if mc.ue_count > 0 { RED } else { SUBTEXT };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    mc{}  {}  mode={}",
                        mc.idx,
                        if mc.name.is_empty() { "(unnamed)" } else { &mc.name },
                        mc.edac_mode
                    ),
                    Style::default().fg(TEXT),
                ),
                Span::styled("   CE: ", Style::default().fg(SUBTEXT)),
                Span::styled(mc.ce_count.to_string(), Style::default().fg(ce_col).add_modifier(Modifier::BOLD)),
                Span::styled("   UE: ", Style::default().fg(SUBTEXT)),
                Span::styled(mc.ue_count.to_string(), Style::default().fg(ue_col).add_modifier(Modifier::BOLD)),
            ]));
        }
    }
    lines.push(Line::raw(""));

    // ── NUMA topology ─────────────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  NUMA Topology",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));
    if h.numa_nodes.is_empty() {
        lines.push(Line::from(Span::styled(
            "    NUMA info unavailable",
            Style::default().fg(SUBTEXT),
        )));
    } else {
        for node in &h.numa_nodes {
            let used_mib = node.total_mib.saturating_sub(node.free_mib);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    Node {}  total: {:>6} MiB  free: {:>6} MiB  used: {:>6} MiB",
                        node.idx, node.total_mib, node.free_mib, used_mib),
                    Style::default().fg(TEXT),
                ),
            ]));
        }
    }
    lines.push(Line::raw(""));

    // ── Huge pages ────────────────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  Huge Pages",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));
    let hp = &h.hugepages;
    if hp.total == 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("    Not configured  (page size: {} KiB)", hp.size_kib),
                Style::default().fg(SUBTEXT),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(
                format!("    {} KiB pages  total: {}  free: {}  in-use: {}",
                    hp.size_kib, hp.total, hp.free, hp.total.saturating_sub(hp.free)),
                Style::default().fg(TEXT),
            ),
        ]));
    }
    lines.push(Line::raw(""));

    // ── Kernel memory events ──────────────────────────────────────────────────
    lines.push(Line::from(Span::styled(
        "  Kernel Memory Events (dmesg)",
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    )));
    if h.dmesg_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "    No relevant kernel events found",
            Style::default().fg(SUBTEXT),
        )));
    } else {
        for ev in &h.dmesg_events {
            let (icon, col) = match ev.severity {
                KernelSev::Critical => ("!", RED),
                KernelSev::Warning  => ("~", YELLOW),
                KernelSev::Info     => ("·", SUBTEXT),
            };
            let ts_part = if ev.timestamp.is_empty() {
                String::new()
            } else {
                format!("{}  ", ev.timestamp)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {icon}  "), Style::default().fg(col).add_modifier(Modifier::BOLD)),
                Span::styled(ts_part, Style::default().fg(SUBTEXT)),
                Span::styled(
                    ev.message.clone(),
                    Style::default().fg(match ev.severity {
                        KernelSev::Critical => TEXT,
                        KernelSev::Warning  => YELLOW,
                        KernelSev::Info     => SUBTEXT,
                    }),
                ),
            ]));
        }
    }
    lines.push(Line::raw(""));

    lines
}

// ── Recovery screen builder ───────────────────────────────────────────────────

fn build_recover_lines(actions: &[RecoveryAction]) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    if actions.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No recovery data — run a test first.",
            Style::default().fg(SUBTEXT),
        )));
        return lines;
    }

    for (i, action) in actions.iter().enumerate() {
        let (pri_col, pri_icon) = match action.priority {
            recover::Priority::Critical => (RED,     "✗"),
            recover::Priority::High     => (PEACH,   "!"),
            recover::Priority::Medium   => (YELLOW,  "~"),
            recover::Priority::Low      => (SUBTEXT, "·"),
        };

        // Action header
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {pri_icon}  [{:>8}]  ", action.priority.label()),
                Style::default().fg(pri_col).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{}]", action.category),
                Style::default().fg(SAPPHIRE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  Action {}", i + 1),
                Style::default().fg(SUBTEXT),
            ),
        ]));

        // Wrap description text (approx 78 chars per line)
        let desc = &action.description;
        let mut start = 0;
        while start < desc.len() {
            let end = (start + 76).min(desc.len());
            // Try to break at a word boundary
            let end = if end < desc.len() {
                desc[start..end].rfind(' ').map(|p| start + p).unwrap_or(end)
            } else {
                end
            };
            lines.push(Line::from(vec![
                Span::raw("       "),
                Span::styled(
                    desc[start..end].trim().to_string(),
                    Style::default().fg(TEXT),
                ),
            ]));
            start = end + 1;
            if start >= desc.len() { break; }
        }

        // Optional command
        if let Some(cmd) = &action.command {
            lines.push(Line::from(vec![
                Span::styled("       $ ", Style::default().fg(GREEN)),
                Span::styled(cmd.clone(), Style::default().fg(GREEN).add_modifier(Modifier::DIM)),
            ]));
        }

        lines.push(Line::raw(""));
    }

    lines
}

// ── Log writer ────────────────────────────────────────────────────────────────

fn write_log(f: &mut std::fs::File, app: &App, timestamp: &str) -> io::Result<()> {
    writeln!(f, "DDR5 Memory Tester — Results")?;
    writeln!(f, "{}", "─".repeat(50))?;
    writeln!(f, "Date:    {timestamp} UTC")?;
    writeln!(f, "Memory:  {} MiB", app.summary_mib)?;
    writeln!(f, "Passes:  {}", app.summary_passes)?;
    writeln!(f, "Total:   {}s", app.elapsed_s)?;
    writeln!(f)?;
    writeln!(f, "CPU:  {} ({} cores)", app.sysinfo.cpu_model, app.sysinfo.cpu_cores)?;
    writeln!(
        f,
        "RAM:  {:.1} GiB total / {:.1} GiB free",
        app.sysinfo.total_ram_mib as f64 / 1024.0,
        app.sysinfo.avail_ram_mib as f64 / 1024.0
    )?;
    writeln!(f)?;
    writeln!(f, "{:<22} {:<6} {:>10} {:>8}", "Test", "Result", "Time (ms)", "Errors")?;
    writeln!(f, "{}", "─".repeat(50))?;
    for ct in &app.completed {
        let result = if ct.passed { "PASS" } else { "FAIL" };
        writeln!(
            f,
            "{:<22} {:<6} {:>10} {:>8}",
            ct.name, result, ct.elapsed_ms, ct.errors.len()
        )?;
        for e in &ct.errors {
            writeln!(
                f,
                "  offset {:#012x}  expected {:#018x}  got {:#018x}  diff {:#018x}",
                e.offset, e.expected, e.actual, e.expected ^ e.actual
            )?;
        }
    }
    writeln!(f)?;
    writeln!(
        f,
        "Summary: {}",
        if app.total_errors == 0 {
            "ALL TESTS PASSED".to_string()
        } else {
            format!("FAILED ({} errors)", app.total_errors)
        }
    )?;
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run_tui() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    let mut app = App::new();

    loop {
        app.poll_worker();
        terminal.draw(|f| app.draw(f))?;

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        if app.screen == Screen::Running {
                            app.diag.cancel.store(true, Ordering::Relaxed);
                        } else {
                            break;
                        }
                    } else if app.handle_key(key.code, key.modifiers) {
                        break;
                    }
                }
                Event::Mouse(me) => {
                    if me.kind == MouseEventKind::Down(MouseButton::Left) {
                        app.handle_click(me.column, me.row);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
