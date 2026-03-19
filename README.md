# ddr5-memtest

A DDR5 memory stress tester written in Rust. Runs an interactive TUI by default, or a plain terminal mode with `--no-tui`.

## Features

- **7 memory tests** covering common DRAM failure modes
- **Interactive TUI** (ratatui) with live heatmap, progress, and per-cell latency coloring
- **Error forensics** — cluster analysis, stuck-bit detection, bit-flip histograms
- **Stability score** (0–100) with a four-component breakdown and a plain-English verdict
- **Recovery recommendations** — prioritised action list based on test results and system health
- **System health panel** — reads EDAC ECC counters, NUMA topology, huge-page config, and dmesg events
- **x86-64 optimisations** — non-temporal writes (`MOVNTI`) and explicit cache-line flushes (`CLFLUSH`) to ensure data hits DRAM
- **Parallel verification** via Rayon for fast read-back on multi-core systems

## Tests

| Key            | Name             | What it checks |
|----------------|------------------|----------------|
| `solid`        | Solid Bits       | All-0 and all-1 patterns — detects stuck bits |
| `checkerboard` | Checkerboard     | Alternating 0101… / 1010… — adjacent-cell coupling |
| `walking`      | Walking 1s/0s    | Single bit rotated through all 64 positions |
| `march`        | March C-         | Classic DRAM march algorithm — coupling faults |
| `address`      | Address Pattern  | Each word written with its own index — addressing faults |
| `random`       | LFSR Random      | Galois LFSR pseudo-random sequence — broad pattern coverage |
| `hammer`       | Row Hammer       | Hammers two aggressor rows, checks victim row for bit flips |

## Building

Requires a recent stable Rust toolchain and Linux.

```sh
cargo build --release
```

The binary will be at `target/release/ddr5-memtest`.

## Usage

### TUI mode (default)

```sh
sudo ./ddr5-memtest
```

The TUI auto-detects available RAM and lets you configure the test interactively.

### Plain CLI mode

```sh
sudo ./ddr5-memtest --no-tui [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mib <MiB>` | `256` | Memory region size to test |
| `-p, --passes <N>` | `1` | Number of full passes |
| `--skip <list>` | *(none)* | Comma-separated test keys to skip (e.g. `hammer,random`) |
| `--fail-fast` | *(off)* | Abort after the first error |

**Examples:**

```sh
# Test 1 GiB, 3 passes, skip row hammer
sudo ./ddr5-memtest --no-tui -m 1024 -p 3 --skip hammer

# Quick 256 MiB single-pass check, stop on first error
sudo ./ddr5-memtest --no-tui --fail-fast
```

### Why root?

`mmap` of large anonymous regions and reading EDAC/dmesg data may require elevated privileges depending on your kernel configuration. The tool itself performs no writes outside its own allocated region.

## Scoring

After a run the tool computes a **Stability Score** (0–100):

| Component | Max pts | Based on |
|-----------|---------|----------|
| Error accuracy | 60 | Error count, stuck bits, cluster type |
| Latency health | 20 | Fraction of slow / spike-latency chunks |
| Row disturbance | 10 | Row/bank-level clusters, rowhammer result |
| Test coverage | 10 | Number of tests run, number of passes |

| Score | Verdict |
|-------|---------|
| 90–100 | SAFE FOR HEAVY WORKLOADS |
| 75–89  | STABLE — minor anomalies detected |
| 60–74  | MARGINAL — monitor closely |
| 40–59  | UNSTABLE — replacement recommended |
| 0–39   | CRITICAL FAILURE — do not use |

## Error Forensics

Errors are grouped into clusters and classified by span:

| Kind | Span | Likely cause |
|------|------|--------------|
| Cache Line | < 64 B | Single column cell — monitor |
| Row | < 8 KiB | DRAM row failure — replace DIMM |
| Bank | < 8 MiB | Bank-level defect — replace DIMM |
| Scattered | ≥ 8 MiB | Bad stick or widespread cell failures |

Stuck bits (always read 0 or always read 1 regardless of pattern) are reported separately as definitive hardware failures.

## Platform notes

- Linux only (uses `/proc/meminfo`, `/sys/devices/system/edac/`, `mmap`, `dmesg`)
- x86-64 recommended for non-temporal write and cache-flush acceleration; other architectures fall back to standard writes

## Dependencies

- [`clap`](https://crates.io/crates/clap) — CLI argument parsing
- [`indicatif`](https://crates.io/crates/indicatif) — CLI progress spinners
- [`colored`](https://crates.io/crates/colored) — terminal colour output
- [`rayon`](https://crates.io/crates/rayon) — parallel pattern verification
- [`libc`](https://crates.io/crates/libc) — `mmap` / `munmap`
- [`ratatui`](https://crates.io/crates/ratatui) + [`crossterm`](https://crates.io/crates/crossterm) — TUI rendering
