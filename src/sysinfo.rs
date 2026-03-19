/// Basic system information read from /proc at startup.
pub struct SysInfo {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub total_ram_mib: usize,
    pub avail_ram_mib: usize,
}

impl SysInfo {
    pub fn read() -> Self {
        SysInfo {
            cpu_model:     cpu_model(),
            cpu_cores:     cpu_cores(),
            total_ram_mib: meminfo_mib("MemTotal"),
            avail_ram_mib: meminfo_mib("MemAvailable"),
        }
    }

    /// Conservative "max safe" test size: 90% of available, capped at 32 GiB.
    pub fn max_test_mib(&self) -> usize {
        let headroom = self.avail_ram_mib.saturating_sub(512);
        (headroom * 9 / 10).clamp(256, 32768)
    }
}

fn cpu_model() -> String {
    let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") else {
        return "Unknown CPU".into();
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some(val) = rest.splitn(2, ':').nth(1) {
                return val.trim().to_string();
            }
        }
    }
    "Unknown CPU".into()
}

fn cpu_cores() -> usize {
    let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") else {
        return 1;
    };
    s.lines().filter(|l| l.starts_with("processor")).count().max(1)
}

fn meminfo_mib(key: &str) -> usize {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in s.lines() {
        if line.starts_with(key) {
            let mut parts = line.split_whitespace();
            parts.next(); // key:
            if let Some(kb) = parts.next().and_then(|v| v.parse::<usize>().ok()) {
                return kb / 1024;
            }
        }
    }
    0
}

// ── Timestamp helper ─────────────────────────────────────────────────────────

/// Format a UNIX timestamp as "YYYY-MM-DD HH:MM:SS" (UTC).
pub fn format_timestamp(ts: u64) -> String {
    let s = ts % 60;
    let m = (ts / 60) % 60;
    let h = (ts / 3600) % 24;
    let (y, mo, d) = days_to_ymd(ts / 86400);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

/// Format a UNIX timestamp as "YYYYMMDD-HHMMSS" suitable for a filename.
pub fn format_timestamp_file(ts: u64) -> String {
    let s = ts % 60;
    let m = (ts / 60) % 60;
    let h = (ts / 3600) % 24;
    let (y, mo, d) = days_to_ymd(ts / 86400);
    format!("{y:04}{mo:02}{d:02}-{h:02}{m:02}{s:02}")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let months = if is_leap(y) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    for &md in &months {
        if days < md {
            break;
        }
        days -= md;
        mo += 1;
    }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
