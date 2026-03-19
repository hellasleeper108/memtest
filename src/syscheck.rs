//! System health check — reads EDAC error counters, NUMA topology,
//! huge-page status, and recent kernel memory events.
//!
//! Everything is read lazily at startup / on demand.  No writes, no root
//! required (EDAC counters are world-readable on most distros).

use std::fs;
use std::path::Path;
use std::process::Command;

// ── EDAC ──────────────────────────────────────────────────────────────────────

/// Hardware ECC error counters from one EDAC memory controller.
#[derive(Debug, Clone, Default)]
pub struct EdacMc {
    /// Controller index (0, 1, …)
    pub idx: usize,
    /// Corrected errors (recoverable, but may indicate declining DIMM health)
    pub ce_count: u64,
    /// Uncorrected errors (data corruption — critical)
    pub ue_count: u64,
    /// Controller name string (e.g. "i7core#0")
    pub name: String,
    /// EDAC mode reported by the kernel ("SECDED", "S8ECD8ED", "Unknown", …)
    pub edac_mode: String,
}

/// Read all available EDAC memory controllers from sysfs.
/// Returns an empty Vec on WSL2 / VMs / kernels built without CONFIG_EDAC.
pub fn read_edac() -> Vec<EdacMc> {
    let base = Path::new("/sys/devices/system/edac/mc");
    if !base.exists() {
        return Vec::new();
    }

    let mut result = Vec::new();
    for idx in 0..8usize {
        let mc = base.join(format!("mc{idx}"));
        if !mc.exists() {
            break;
        }
        let ce    = read_u64(mc.join("ce_count"));
        let ue    = read_u64(mc.join("ue_count"));
        let name  = read_str(mc.join("mc_name")).unwrap_or_default();
        let mode  = read_str(mc.join("edac_mode")).unwrap_or_else(|| "Unknown".into());
        result.push(EdacMc { idx, ce_count: ce, ue_count: ue, name, edac_mode: mode });
    }
    result
}

// ── NUMA ──────────────────────────────────────────────────────────────────────

/// Memory stats for one NUMA node (from /sys/devices/system/node/nodeN/meminfo).
#[derive(Debug, Clone)]
pub struct NumaNode {
    pub idx:       usize,
    pub total_mib: u64,
    pub free_mib:  u64,
}

pub fn read_numa() -> Vec<NumaNode> {
    let base = Path::new("/sys/devices/system/node");
    if !base.exists() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for idx in 0..8usize {
        let node = base.join(format!("node{idx}"));
        if !node.exists() {
            break;
        }
        // /sys/devices/system/node/node0/meminfo fields are in kB
        let meminfo_path = node.join("meminfo");
        let (mut total_kb, mut free_kb) = (0u64, 0u64);
        if let Ok(s) = fs::read_to_string(&meminfo_path) {
            for line in s.lines() {
                // Format: "Node 0 MemTotal:      XXXXX kB"
                if line.contains("MemTotal:") {
                    total_kb = parse_kb(line);
                } else if line.contains("MemFree:") {
                    free_kb = parse_kb(line);
                }
            }
        }
        result.push(NumaNode {
            idx,
            total_mib: total_kb / 1024,
            free_mib:  free_kb / 1024,
        });
    }
    result
}

// ── Huge pages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct HugePageInfo {
    /// Configured huge page size in KiB (usually 2048 or 1048576)
    pub size_kib:  u64,
    /// Total configured huge pages (0 = not configured)
    pub total:     u64,
    /// Free (unused) huge pages
    pub free:      u64,
}

pub fn read_hugepages() -> HugePageInfo {
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut info = HugePageInfo::default();
    for line in meminfo.lines() {
        if line.starts_with("HugePages_Total:") {
            info.total = parse_last_u64(line);
        } else if line.starts_with("HugePages_Free:") {
            info.free = parse_last_u64(line);
        } else if line.starts_with("Hugepagesize:") {
            info.size_kib = parse_last_u64(line);
        }
    }
    info
}

// ── Kernel memory events (dmesg) ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct KernelEvent {
    pub timestamp: String, // "[   0.123456]"
    pub message:   String,
    pub severity:  KernelSev,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KernelSev {
    Critical, // MCE / UE
    Warning,  // CE / EDAC CE
    Info,     // driver init, ECC version
}

/// Read recent kernel memory-related events via `dmesg`.
/// Returns up to `limit` events, newest first.
/// Returns an empty Vec if dmesg is unavailable (some container envs).
pub fn read_dmesg_events(limit: usize) -> Vec<KernelEvent> {
    let output = Command::new("dmesg")
        .arg("--kernel")
        .arg("--nopager")
        .output();

    let out = match output {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&out);

    let keywords = [
        "mce", "MCE", "edac", "EDAC", "ecc", "ECC",
        "hardware error", "Hardware Error",
        "corrected", "uncorrected",
        "dimm", "DIMM", "dram", "DRAM",
        "memory", "Memory",
    ];

    let mut events: Vec<KernelEvent> = text
        .lines()
        .filter(|l| keywords.iter().any(|kw| l.contains(kw)))
        .map(|l| {
            // Extract timestamp bracket if present
            let (ts, msg) = if l.starts_with('[') {
                if let Some(end) = l.find(']') {
                    (l[..=end].trim().to_string(), l[end + 1..].trim().to_string())
                } else {
                    (String::new(), l.to_string())
                }
            } else {
                (String::new(), l.to_string())
            };

            let lower = msg.to_lowercase();
            let severity = if lower.contains("uncorrected")
                || lower.contains("mce")
                || lower.contains("hardware error")
            {
                KernelSev::Critical
            } else if lower.contains("corrected") || lower.contains(" ce ") || lower.contains("edac") {
                KernelSev::Warning
            } else {
                KernelSev::Info
            };

            KernelEvent { timestamp: ts, message: msg, severity }
        })
        .collect();

    // Newest first, limited
    events.reverse();
    events.truncate(limit);
    events
}

// ── ECC mode summary ─────────────────────────────────────────────────────────

/// High-level ECC summary derived from EDAC data.
#[derive(Debug, Clone, PartialEq)]
pub enum EccStatus {
    /// EDAC found and reports ECC enabled (SECDED or better)
    Enabled(String),
    /// EDAC found but reports no ECC
    Disabled,
    /// EDAC sysfs not present — cannot determine ECC status
    Unknown,
}

pub fn ecc_status(mcs: &[EdacMc]) -> EccStatus {
    if mcs.is_empty() {
        return EccStatus::Unknown;
    }
    // If any MC has a recognised ECC mode, report it
    for mc in mcs {
        let m = mc.edac_mode.as_str();
        if !m.is_empty() && m != "None" && m != "Unknown" {
            return EccStatus::Enabled(m.to_string());
        }
    }
    EccStatus::Disabled
}

// ── Full system health snapshot ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub edac_mcs:    Vec<EdacMc>,
    pub numa_nodes:  Vec<NumaNode>,
    pub hugepages:   HugePageInfo,
    pub ecc:         EccStatus,
    pub dmesg_events: Vec<KernelEvent>,
}

impl SystemHealth {
    /// Collect a full system health snapshot. Blocking (file reads + dmesg).
    pub fn collect() -> Self {
        let edac_mcs = read_edac();
        let ecc = ecc_status(&edac_mcs);
        SystemHealth {
            numa_nodes:   read_numa(),
            hugepages:    read_hugepages(),
            dmesg_events: read_dmesg_events(30),
            ecc,
            edac_mcs,
        }
    }

    /// Total corrected errors across all EDAC controllers.
    pub fn total_ce(&self) -> u64 {
        self.edac_mcs.iter().map(|m| m.ce_count).sum()
    }

    /// Total uncorrected errors across all EDAC controllers.
    pub fn total_ue(&self) -> u64 {
        self.edac_mcs.iter().map(|m| m.ue_count).sum()
    }

    /// True if any critical kernel memory events are present.
    pub fn has_critical_events(&self) -> bool {
        self.dmesg_events.iter().any(|e| e.severity == KernelSev::Critical)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u64(path: impl AsRef<Path>) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn read_str(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn parse_kb(line: &str) -> u64 {
    // "Node 0 MemTotal:   123456 kB"  → last numeric token
    line.split_whitespace()
        .rev()
        .skip(1) // skip "kB"
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn parse_last_u64(line: &str) -> u64 {
    line.split_whitespace()
        .last()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
