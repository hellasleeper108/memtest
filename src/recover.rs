//! Recovery action recommendations.
//!
//! Analyses the forensics report + system health snapshot and produces a
//! prioritised list of concrete actions the user should take.

use crate::forensics::{ClusterKind, Report as ForensicsReport};
use crate::syscheck::{EccStatus, SystemHealth};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Critical, // act immediately
    High,     // strongly recommended
    Medium,   // investigate
    Low,      // advisory
}

impl Priority {
    pub fn label(&self) -> &'static str {
        match self {
            Priority::Critical => "CRITICAL",
            Priority::High     => "HIGH",
            Priority::Medium   => "MEDIUM",
            Priority::Low      => "LOW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryAction {
    pub priority:    Priority,
    pub category:    &'static str,
    pub description: String,
    /// Optional shell command / OS action the user can run (informational).
    pub command:     Option<String>,
}

// ── Generator ─────────────────────────────────────────────────────────────────

/// Generate a prioritised recovery action list.
///
/// `forensics` may be `None` when the test was run in CLI mode or has not
/// completed yet.  `health` is always collected at startup.
pub fn generate(
    forensics: Option<&ForensicsReport>,
    health:    &SystemHealth,
    total_errors: usize,
    total_tested_mib: usize,
) -> Vec<RecoveryAction> {
    let mut actions: Vec<RecoveryAction> = Vec::new();

    // ── EDAC uncorrected errors ───────────────────────────────────────────────
    let total_ue = health.total_ue();
    let total_ce = health.total_ce();

    if total_ue > 0 {
        actions.push(RecoveryAction {
            priority:    Priority::Critical,
            category:    "ECC",
            description: format!(
                "{total_ue} uncorrected ECC error(s) logged by kernel EDAC. \
                 Data corruption may have already occurred — replace DIMM(s) immediately."
            ),
            command: Some("cat /sys/devices/system/edac/mc/mc*/ue_count".into()),
        });
    }

    if total_ce > 0 {
        actions.push(RecoveryAction {
            priority:    Priority::High,
            category:    "ECC",
            description: format!(
                "{total_ce} corrected ECC error(s) logged by kernel EDAC. \
                 Errors were recovered, but this indicates declining DIMM health. \
                 Monitor closely and plan replacement."
            ),
            command: Some("cat /sys/devices/system/edac/mc/mc*/ce_count".into()),
        });
    }

    // ── ECC not enabled ───────────────────────────────────────────────────────
    if health.ecc == EccStatus::Disabled {
        actions.push(RecoveryAction {
            priority:    Priority::Medium,
            category:    "ECC",
            description: "EDAC reports ECC is disabled on this system. \
                          Enable ECC in BIOS/UEFI for data integrity protection \
                          (requires ECC-capable DIMMs and CPU/platform support).".into(),
            command:     None,
        });
    }

    // ── Kernel critical events ────────────────────────────────────────────────
    if health.has_critical_events() {
        actions.push(RecoveryAction {
            priority:    Priority::Critical,
            category:    "Kernel",
            description: "Critical kernel memory events (MCE / hardware error) detected in dmesg. \
                          Review the Health screen for details. The system may have already \
                          experienced data corruption.".into(),
            command:     Some("dmesg --kernel | grep -iE 'mce|hardware error|uncorrected'".into()),
        });
    }

    // ── Test errors ───────────────────────────────────────────────────────────
    if total_errors > 0 {
        if let Some(fr) = forensics {
            let row_bank_clusters: Vec<_> = fr.clusters.iter()
                .filter(|c| c.kind == ClusterKind::Row || c.kind == ClusterKind::Bank)
                .collect();

            let scattered_clusters: Vec<_> = fr.clusters.iter()
                .filter(|c| c.kind == ClusterKind::Scattered)
                .collect();

            let stuck_bits = (fr.stuck_at_0 | fr.stuck_at_1).count_ones();

            // Stuck bits → definite hardware failure
            if stuck_bits > 0 {
                actions.push(RecoveryAction {
                    priority:    Priority::Critical,
                    category:    "Memory",
                    description: format!(
                        "{stuck_bits} stuck bit(s) detected. These are permanent DRAM cell \
                         failures — the DIMM must be replaced."
                    ),
                    command:     None,
                });
            }

            // Row/bank cluster → single DIMM failure
            if !row_bank_clusters.is_empty() {
                actions.push(RecoveryAction {
                    priority:    Priority::Critical,
                    category:    "Memory",
                    description: format!(
                        "{} row/bank-level error cluster(s) found. This strongly indicates \
                         a failed DRAM row or bank. Replace the affected DIMM.",
                        row_bank_clusters.len()
                    ),
                    command:     None,
                });
            }

            // Widespread / scattered errors
            if !scattered_clusters.is_empty() {
                actions.push(RecoveryAction {
                    priority:    Priority::Critical,
                    category:    "Memory",
                    description: format!(
                        "{} scattered error cluster(s) spanning large memory regions. \
                         This may indicate a bad memory stick, overclocking instability, \
                         or thermal damage. Check XMP/EXPO settings and reseat DIMMs.",
                        scattered_clusters.len()
                    ),
                    command:     None,
                });
            }

            // Any errors at all (catch-all if no strong pattern)
            if row_bank_clusters.is_empty() && scattered_clusters.is_empty() && stuck_bits == 0 {
                let pct = total_errors as f64
                    / (total_tested_mib as f64 * 1024.0 * 1024.0 / 8.0)
                    * 100.0;
                if fr.clusters.len() == 1 && total_errors < 4 {
                    actions.push(RecoveryAction {
                        priority:    Priority::Medium,
                        category:    "Memory",
                        description: format!(
                            "{total_errors} error(s) in a single cache-line cluster \
                             ({pct:.6}% of tested region). May be a transient upset. \
                             Re-run with more passes to confirm."
                        ),
                        command:     None,
                    });
                } else {
                    actions.push(RecoveryAction {
                        priority:    Priority::High,
                        category:    "Memory",
                        description: format!(
                            "{total_errors} error(s) across {} cluster(s) ({pct:.6}% failure rate). \
                             Run multiple passes to determine if errors are reproducible.",
                            fr.clusters.len()
                        ),
                        command:     None,
                    });
                }
            }

            // Soft-offline pages (advisory — requires root)
            if total_errors > 0 && total_errors <= 16 {
                actions.push(RecoveryAction {
                    priority:    Priority::Medium,
                    category:    "OS",
                    description: "If errors are reproducible, the kernel can soft-offline \
                                  specific pages to prevent reuse. Requires root and physical \
                                  addresses (obtained via /proc/PID/pagemap).".into(),
                    command: Some(
                        "echo <pfn_hex> > /sys/devices/system/memory/soft_offline_page".into()
                    ),
                });
            }
        }

        // Generic BIOS/XMP advice for any errors
        actions.push(RecoveryAction {
            priority:    Priority::High,
            category:    "BIOS",
            description: "If using XMP/EXPO profiles, try disabling them and running \
                          at JEDEC default speeds. Overclocked profiles are a common \
                          cause of memory errors.".into(),
            command:     None,
        });

        actions.push(RecoveryAction {
            priority:    Priority::Medium,
            category:    "Hardware",
            description: "Reseat all DIMM modules. Poor contact in the socket can cause \
                          intermittent errors. Clean gold contacts with isopropyl alcohol \
                          if the system is in a dusty environment.".into(),
            command:     None,
        });
    }

    // ── No errors but no ECC known ────────────────────────────────────────────
    if total_errors == 0 && health.ecc == EccStatus::Unknown {
        actions.push(RecoveryAction {
            priority:    Priority::Low,
            category:    "ECC",
            description: "No EDAC subsystem found — cannot confirm ECC status. \
                          If this is a production system, verify ECC is supported and \
                          enabled in BIOS.".into(),
            command:     Some("modprobe edac_core && ls /sys/devices/system/edac/mc/".into()),
        });
    }

    // ── Huge pages not configured ─────────────────────────────────────────────
    if health.hugepages.total == 0 && total_tested_mib >= 1024 {
        actions.push(RecoveryAction {
            priority:    Priority::Low,
            category:    "Performance",
            description: "Huge pages are not configured. Workloads with large memory \
                          footprints (databases, VMs) benefit from 2 MiB or 1 GiB \
                          huge pages to reduce TLB pressure.".into(),
            command:     Some("echo 512 > /proc/sys/vm/nr_hugepages  # 1 GiB of 2M pages".into()),
        });
    }

    // ── All clean ────────────────────────────────────────────────────────────
    if actions.is_empty() {
        actions.push(RecoveryAction {
            priority:    Priority::Low,
            category:    "Status",
            description: "No issues detected. Memory appears healthy.".into(),
            command:     None,
        });
    }

    // Sort by priority (Critical first)
    actions.sort_by_key(|a| a.priority.clone());
    actions
}
