mod dimm;
mod forensics;
mod heatmap;
mod recover;
mod score;
mod syscheck;
mod memory;
mod progress;
mod sysinfo;
mod tests;
mod tui;

use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use memory::MemRegion;
use progress::DiagState;
use tests::{
    TestResult, test_address_pattern, test_checkerboard, test_march_c, test_random_pattern,
    test_rowhammer, test_solid_bits, test_walking_bits,
};

#[derive(Parser)]
#[command(
    name = "ddr5-memtest",
    about = "DDR5 memory stress tester — TUI by default, --no-tui for plain output",
    version
)]
struct Args {
    /// Disable the TUI and use plain terminal output
    #[arg(long)]
    no_tui: bool,

    /// Memory to test in MiB [no-tui only]
    #[arg(short = 'm', long, default_value_t = 256)]
    mib: usize,

    /// Number of full passes [no-tui only]
    #[arg(short = 'p', long, default_value_t = 1)]
    passes: usize,

    /// Tests to skip, comma-separated: solid,checkerboard,walking,march,address,random,hammer
    /// [no-tui only]
    #[arg(long, default_value = "")]
    skip: String,

    /// Abort after the first error [no-tui only]
    #[arg(long)]
    fail_fast: bool,
}

// ── CLI mode ──────────────────────────────────────────────────────────────────

struct TestSpec {
    name: &'static str,
    key:  &'static str,
    run:  fn(&mut MemRegion, &DiagState) -> TestResult,
}

fn all_tests() -> Vec<TestSpec> {
    vec![
        TestSpec { name: "Solid Bits",      key: "solid",        run: test_solid_bits },
        TestSpec { name: "Checkerboard",    key: "checkerboard", run: test_checkerboard },
        TestSpec { name: "Walking 1s/0s",   key: "walking",      run: test_walking_bits },
        TestSpec { name: "March C-",        key: "march",        run: test_march_c },
        TestSpec { name: "Address Pattern", key: "address",      run: test_address_pattern },
        TestSpec { name: "LFSR Random",     key: "random",       run: test_random_pattern },
        TestSpec { name: "Row Hammer",      key: "hammer",       run: test_rowhammer },
    ]
}

fn print_result(r: &TestResult) {
    let status =
        if r.errors.is_empty() { "PASS".green().bold() } else { "FAIL".red().bold() };
    println!("  [{status}]  {name:<20}  {ms:>6} ms", name = r.name, ms = r.elapsed_ms);
    for e in &r.errors {
        println!(
            "           offset {:#012x}  exp {:#018x}  got {:#018x}  diff {:#018x}",
            e.offset, e.expected, e.actual, e.expected ^ e.actual,
        );
    }
}

fn print_summary(total_errors: usize, secs: u64) {
    println!("{}", "═".repeat(60).cyan());
    if total_errors == 0 {
        println!("  {}  — no errors in {}s", "ALL TESTS PASSED".green().bold(), secs);
    } else {
        println!(
            "  {}  — {} error(s) in {}s",
            "FAILURES DETECTED".red().bold(),
            total_errors,
            secs
        );
    }
    println!("{}", "═".repeat(60).cyan());
}

fn run_cli(args: Args) {
    let size = args.mib * 1024 * 1024;

    println!("{}", "═".repeat(60).cyan());
    println!("{}", "  DDR5 Memory Tester".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("  Region : {} MiB", args.mib);
    println!("  Passes : {}", args.passes);
    println!();

    let skip: Vec<&str> =
        args.skip.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    let all = all_tests();
    let specs: Vec<&TestSpec> = all.iter().filter(|s| !skip.contains(&s.key)).collect();

    println!(
        "  Tests  : {}",
        specs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
    );
    println!();

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap(),
    );
    spinner.set_message(format!("Allocating {} MiB …", args.mib));
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut region = match MemRegion::allocate(size) {
        Ok(r) => r,
        Err(e) => {
            spinner.finish_and_clear();
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };
    spinner.finish_with_message(format!("Allocated {} MiB at {:p}", args.mib, region.ptr));
    println!();

    let diag = DiagState::new();
    let mut total_errors = 0usize;
    let t0 = std::time::Instant::now();

    for pass in 1..=args.passes {
        if args.passes > 1 {
            println!(
                "{}",
                format!("── Pass {pass}/{} ────────────────────────", args.passes).bold()
            );
        }
        for spec in &specs {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} Running {msg} …")
                    .unwrap(),
            );
            pb.set_message(spec.name);
            pb.enable_steady_tick(std::time::Duration::from_millis(80));

            diag.reset_for_test();
            let result = (spec.run)(&mut region, &diag);

            pb.finish_and_clear();
            total_errors += result.errors.len();
            print_result(&result);

            if args.fail_fast && !result.errors.is_empty() {
                println!("\n{}", "  Stopped (--fail-fast).".yellow());
                print_summary(total_errors, t0.elapsed().as_secs());
                std::process::exit(1);
            }
        }
        if args.passes > 1 {
            println!();
        }
    }

    println!();
    print_summary(total_errors, t0.elapsed().as_secs());
    if total_errors > 0 {
        std::process::exit(1);
    }
}

fn main() {
    let args = Args::parse();
    if args.no_tui {
        run_cli(args);
    } else if let Err(e) = tui::run_tui() {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}
