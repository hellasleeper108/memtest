//! DIMM slot detection via SMBIOS/DMI.
//!
//! Reads Type 17 (Memory Device) and Type 20 (Memory Device Mapped Address)
//! from `/sys/firmware/dmi/entries/` to discover installed DIMMs, their
//! physical address ranges, and basic specs.
//!
//! When DMI is unavailable (WSL, some VMs) the module returns an empty list
//! and all callers degrade gracefully.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── Public types ──────────────────────────────────────────────────────────────

/// Information about a single DIMM slot (populated or empty).
#[derive(Debug, Clone)]
pub struct DimmInfo {
    /// SMBIOS handle — used to correlate with Type 20 records.
    pub handle: u16,
    /// Device locator string from BIOS, e.g. "DIMM_A1", "ChannelA-DIMM0".
    pub locator: String,
    /// Bank locator string from BIOS, e.g. "BANK 0".
    pub bank_locator: String,
    /// Installed size in MiB. 0 = slot is empty / not populated.
    pub size_mb: u64,
    /// Configured speed in MT/s. 0 = unknown.
    pub speed_mt: u32,
    /// Memory technology string: "DDR5", "DDR4", etc.
    pub mem_type: &'static str,
    /// Manufacturer name (may be empty if BIOS doesn't populate it).
    pub manufacturer: String,
    /// Physical byte address range from SMBIOS Type 20, if available.
    /// `(start_inclusive, end_inclusive)` in bytes.
    pub phys_range: Option<(u64, u64)>,
}

impl DimmInfo {
    pub fn populated(&self) -> bool {
        self.size_mb > 0
    }
    pub fn size_gib(&self) -> f64 {
        self.size_mb as f64 / 1024.0
    }
    /// Short display label: truncate + clean up BIOS noise.
    pub fn label(&self) -> &str {
        let s = self.locator.trim();
        // Truncate to 16 chars for column alignment
        if s.len() > 16 { &s[..16] } else { s }
    }
}

/// Per-DIMM error accumulator, updated as test results arrive.
#[derive(Debug, Clone, Default)]
pub struct DimmStats {
    pub errors: u64,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read all DIMM slots from SMBIOS. Returns empty vec if DMI is unavailable.
///
/// The returned list is sorted: populated slots first, then by locator name.
pub fn read_dimms() -> Vec<DimmInfo> {
    let mut dimms = parse_type17();
    if dimms.is_empty() {
        return dimms;
    }
    let addr_map = parse_type20();
    for d in &mut dimms {
        if let Some(&range) = addr_map.get(&d.handle) {
            d.phys_range = Some(range);
        }
    }
    // Populated slots first, then sort by locator for stable display.
    dimms.sort_by(|a, b| {
        b.populated()
            .cmp(&a.populated())
            .then(a.locator.cmp(&b.locator))
    });
    dimms
}

/// Map a byte offset within the test region to a populated DIMM index using
/// proportional estimation (fraction of offset / region maps to fraction of
/// total DIMM capacity).
///
/// Returns `None` if no DIMM info is available.
/// The mapping is always an estimate — interleaved systems distribute pages
/// across channels so the true mapping requires root + pagemap access.
pub fn attr_offset(dimms: &[DimmInfo], offset: u64, region_size: u64) -> Option<usize> {
    let pop: Vec<usize> = dimms
        .iter()
        .enumerate()
        .filter(|(_, d)| d.populated())
        .map(|(i, _)| i)
        .collect();
    if pop.is_empty() {
        return None;
    }
    let total_mb: u64 = pop.iter().map(|&i| dimms[i].size_mb).sum();
    if total_mb == 0 {
        return None;
    }
    let frac = offset as f64 / region_size.max(1) as f64;
    let mut cum = 0u64;
    for (pos, &di) in pop.iter().enumerate() {
        cum += dimms[di].size_mb;
        if frac < cum as f64 / total_mb as f64 || pos == pop.len() - 1 {
            return Some(di);
        }
    }
    None
}

// ── SMBIOS Type 17 — Memory Device ───────────────────────────────────────────

fn parse_type17() -> Vec<DimmInfo> {
    let base = Path::new("/sys/firmware/dmi/entries");
    if !base.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for n in 0.. {
        let path = base.join(format!("17-{n}/raw"));
        if !path.exists() {
            break;
        }
        let Ok(data) = fs::read(&path) else { break };
        if data.len() >= 21 && data[0] == 17 {
            if let Some(d) = decode_type17(&data) {
                out.push(d);
            }
        }
    }
    out
}

fn decode_type17(data: &[u8]) -> Option<DimmInfo> {
    let slen = data[1] as usize;
    if slen < 21 || data.len() < slen {
        return None;
    }

    let handle = u16::from_le_bytes([data[2], data[3]]);

    // Size (offset 12, 2 bytes). 0=empty, 0x7FFF=use Extended Size field.
    let raw_size = u16::from_le_bytes([data[12], data[13]]);
    let size_mb: u64 = match raw_size {
        0 => 0,
        0x7FFF => {
            if slen >= 32 && data.len() >= 32 {
                u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64
            } else {
                0
            }
        }
        // Bit 15 set → size is in KB, not MB
        s if s & 0x8000 != 0 => (s & 0x7FFF) as u64 / 1024,
        s => s as u64,
    };

    // Memory type (offset 18). SMBIOS 3.6 Table 75.
    let mem_type: &'static str = if slen > 18 {
        match data[18] {
            0x12 => "DDR",
            0x13 => "DDR2",
            0x14 => "DDR2 FB",
            0x18 => "DDR3",
            0x1A => "DDR4",
            0x1B => "LPDDR",
            0x1C => "LPDDR2",
            0x1D => "LPDDR3",
            0x1E => "LPDDR4",
            0x1F => "NVM",
            0x20 => "HBM",
            0x21 => "HBM2",
            0x22 => "DDR5",
            0x23 => "LPDDR5",
            0x24 => "HBM3",
            0x25 => "LPDDR5X",
            _ => "RAM",
        }
    } else {
        "RAM"
    };

    // Configured speed (offset 21, 2 bytes) in MT/s.
    let speed_mt = if slen > 22 {
        u16::from_le_bytes([data[21], data[22]]) as u32
    } else {
        0
    };

    // String table follows the formatted section.
    let strings = dmi_strings(&data[slen..]);
    let si = |idx: u8| dmi_str(&strings, idx);

    let raw_loc = si(data.get(16).copied().unwrap_or(0))
        .unwrap_or_else(|| format!("Slot {handle}"));
    let locator = normalize_locator(&raw_loc, handle);

    let bank_locator = si(data.get(17).copied().unwrap_or(0))
        .unwrap_or_default();
    let manufacturer = si(data.get(23).copied().unwrap_or(0))
        .unwrap_or_default();

    Some(DimmInfo {
        handle,
        locator,
        bank_locator,
        size_mb,
        speed_mt,
        mem_type,
        manufacturer,
        phys_range: None,
    })
}

// ── SMBIOS Type 20 — Memory Device Mapped Address ────────────────────────────

/// Returns: device_handle → (phys_start, phys_end_inclusive) in bytes.
fn parse_type20() -> HashMap<u16, (u64, u64)> {
    let base = Path::new("/sys/firmware/dmi/entries");
    let mut map = HashMap::new();
    for n in 0.. {
        let path = base.join(format!("20-{n}/raw"));
        if !path.exists() {
            break;
        }
        let Ok(data) = fs::read(&path) else { break };
        if data.len() < 15 || data[0] != 20 {
            continue;
        }
        if let Some((handle, start, end)) = decode_type20(&data) {
            map.insert(handle, (start, end));
        }
    }
    map
}

fn decode_type20(data: &[u8]) -> Option<(u16, u64, u64)> {
    let slen = data[1] as usize;
    if slen < 19 || data.len() < slen {
        return None;
    }
    let device_handle = u16::from_le_bytes([data[12], data[13]]);
    let raw_start = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let raw_end   = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let (start, end) = if raw_start == 0xFFFF_FFFF && slen >= 35 && data.len() >= 35 {
        // Extended 64-bit byte addresses (for systems > 4 TB)
        let s = u64::from_le_bytes(data[19..27].try_into().ok()?);
        let e = u64::from_le_bytes(data[27..35].try_into().ok()?);
        (s, e)
    } else {
        // 32-bit KB addresses
        (raw_start as u64 * 1024, raw_end as u64 * 1024 + 1023)
    };
    Some((device_handle, start, end))
}

// ── String table helpers ──────────────────────────────────────────────────────

fn dmi_strings(tail: &[u8]) -> Vec<String> {
    let mut v   = Vec::new();
    let mut cur = Vec::new();
    for &b in tail {
        if b == 0 {
            if cur.is_empty() {
                break; // double-null = end of string table
            }
            v.push(String::from_utf8_lossy(&cur).into_owned());
            cur.clear();
        } else {
            cur.push(b);
        }
    }
    v
}

fn dmi_str(strings: &[String], idx: u8) -> Option<String> {
    if idx == 0 {
        return None;
    }
    Some(strings.get(idx as usize - 1)?.trim().to_string())
}

fn normalize_locator(raw: &str, handle: u16) -> String {
    let s = raw.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("not specified") || s.eq_ignore_ascii_case("unknown") {
        format!("Slot {handle}")
    } else {
        s.to_string()
    }
}
