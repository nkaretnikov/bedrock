// SPDX-License-Identifier: GPL-2.0

//! Fork-based fuzzer for the mptest concurrency-fuzz workload.
//!
//! Boots the mptest guest ONCE to the ready checkpoint, then forks one
//! kernel-seeded branch per child seed: each branch re-rolls the PCT schedule
//! from its own getrandom stream and runs mptest to completion, hunting the
//! libmultiprocess IPC races (#35491 hang, #34014 crash). The expensive boot
//! (kernel + podman + image load + container) is paid once and shared by every
//! child via copy-on-write; only the workload tail runs per seed.
//!
//! Run with:
//!
//! ```text
//! cargo run -p bedrock-lab --example mptest_fuzz -- \
//!     <vmlinux> <initramfs> <compose.yaml> <images.tar> [--count N] [--out DIR]
//! ```
//!
//! A repro is the pair `(boot_seed, child_seed)`: re-boot to the same checkpoint
//! with `--boot-seed` and try the single `--seed-base`/`--count` that produced
//! the failing `child_seed`. Both are printed for every FAILED branch.
//!
//! REQUIRES the guest-side post-ready pool re-roll (scx-init refills rnd_pool
//! from getrandom after `bedrock-vmcall --ready`, driven by the /bedrock/scx
//! handshake). Without it every branch inherits the same pre-filled pool and
//! replays the identical schedule (all `child_seed`s give the same result) --
//! the fork still works, it just does not explore.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};

use bedrock_lab::{
    BranchId, Checkpoint, Event, EventSink, LabOpts, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{boot::defaults, load_kernel, ExitKind, LinuxBootConfig, VmBuilder};
use clap::Parser;

bedrock_lab::define_virt_time_macros!($, bedrock_vm::DEFAULT_TSC_FREQUENCY);

const MEMORY_MB: usize = 5120;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Boot the guest exactly as bedrock-cli does for this workload (same memory,
    // cmdline, kernel + podman initrd), then hand it to the lab.
    let mut vm = VmBuilder::new().memory_mb(MEMORY_MB).build()?;
    let kernel = fs::read(&args.vmlinux)?;
    let initramfs = fs::read(&args.initramfs)?;
    let (kernel_entry, kernel_end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, &kernel)?
    };
    let boot = LinuxBootConfig::new(kernel_entry, kernel_end)
        .cmdline(defaults::CMDLINE)
        .initramfs(&initramfs);
    vm.setup_linux_boot(&boot)?;

    // Boot to the ready checkpoint (run.sh's `bedrock-vmcall --ready`). The two
    // workload files are served over the file-fetch hypercall exactly as the
    // CLI's `--file compose.yaml=... --file images.tar=...`. The boot runs under
    // `boot_seed`, which fixes the shared PCT regime (horizon/slice/depth/spread
    // that scx-init draws); children vary only the pool.
    let sink = Arc::new(CaptureSink::new(!args.quiet));
    let boot_deadline =
        VirtTime::from_secs_f64(args.boot_deadline, bedrock_vm::DEFAULT_TSC_FREQUENCY);
    let ready = Checkpoint::initial_when_ready_with(
        vm,
        boot_deadline,
        LabOpts {
            sink: sink.clone(),
            rng: RngMode::Seeded(args.boot_seed),
            files: vec![
                ("compose.yaml".to_string(), args.compose.clone()),
                ("images.tar".to_string(), args.images.clone()),
            ],
            ..Default::default()
        },
    )?;
    eprintln!(
        "ready checkpoint {:?} at vt {:.3}s (boot_seed={:#018x}); forking {} children",
        ready.id(),
        ready.time().as_secs_f64(),
        args.boot_seed,
        args.count,
    );

    // Per-branch wall of virtual time. A healthy mptest run halts itself with the
    // shutdown vmcall well before this; the deadline only bounds a wedged branch.
    let run_deadline =
        ready.time() + VirtDuration::from_secs_f64(args.run_deadline, ready.tsc_frequency());

    let mut summary = args
        .out
        .as_ref()
        .map(|dir| -> std::io::Result<fs::File> {
            fs::create_dir_all(dir)?;
            let mut f = fs::File::create(format!("{dir}/summary.txt"))?;
            writeln!(f, "# boot_seed={:#018x}", args.boot_seed)?;
            writeln!(f, "# columns: <child_seed> <result>")?;
            Ok(f)
        })
        .transpose()?;

    let mut repros = 0u32;
    for i in 0..args.count {
        let child_seed = split_mix64(args.seed_base.wrapping_add(i as u64));

        // Fork a plain (kernel-seeded) branch and re-seed it: from here its
        // getrandom stream -- including scx-init's post-ready pool refill -- is a
        // pure function of child_seed, so it draws a distinct PCT schedule.
        let mut branch = ready.branch()?;
        let id = branch.id();
        branch.reseed(child_seed)?;

        let outcome = run_branch(&mut branch, run_deadline)?;
        let result = classify(&sink.lines(id), outcome);
        drop(branch); // free the live-branch slot before the next fork

        let repro = matches!(result, Outcome::Failed(_));
        if repro {
            repros += 1;
        }
        let line = format!("{child_seed:#018x}  {}", result.describe());
        println!(
            "[{:>4}/{}] {}{}",
            i + 1,
            args.count,
            line,
            if repro { "   <<< REPRO" } else { "" }
        );
        if let Some(f) = summary.as_mut() {
            writeln!(f, "{line}")?;
        }
        if repro {
            eprintln!(
                ">>> REPRO: boot_seed={:#018x} child_seed={child_seed:#018x}",
                args.boot_seed
            );
        }
    }

    eprintln!("done: {}/{} branches FAILED", repros, args.count);
    Ok(())
}

/// Drive one branch to its self-issued shutdown (normal mptest completion) or to
/// the deadline (a wedged branch). Seeded-RNG branches never exit to userspace
/// for randomness, so the only outcomes are shutdown, the deadline, or an
/// unexpected yield.
fn run_branch(
    branch: &mut bedrock_lab::Branch,
    deadline: VirtTime,
) -> Result<BranchEnd, Box<dyn Error>> {
    loop {
        let (at, outcome) = branch.run_until(deadline)?;
        match outcome {
            RunOutcome::Yielded {
                kind: ExitKind::VmcallShutdown,
            } => return Ok(BranchEnd::Shutdown),
            RunOutcome::ReachedTime => return Ok(BranchEnd::Deadline),
            // No second ready in this workload, but tolerate it rather than abort.
            RunOutcome::Ready => continue,
            RunOutcome::Yielded { kind } => {
                eprintln!(
                    "  unexpected yield at vt {:.3}s: {kind:?}",
                    at.as_secs_f64()
                );
                return Ok(BranchEnd::Unexpected(format!("{kind:?}")));
            }
            other => {
                // ActionResponse / RngExhausted only arise with an InputSource,
                // which a reseed()'d branch does not use.
                eprintln!(
                    "  unexpected outcome at vt {:.3}s: {other:?}",
                    at.as_secs_f64()
                );
                return Ok(BranchEnd::Unexpected(format!("{other:?}")));
            }
        }
    }
}

enum BranchEnd {
    Shutdown,
    Deadline,
    Unexpected(String),
}

enum Outcome {
    Failed(String),
    Survived(String),
    NoResult(String),
}

impl Outcome {
    fn describe(&self) -> String {
        match self {
            Outcome::Failed(s) => format!("FAILED  {s}"),
            Outcome::Survived(s) => format!("survived  {s}"),
            Outcome::NoResult(s) => format!("(no result; {s})"),
        }
    }
}

/// Map a finished branch's serial output to a workload result. The result line
/// is guest console output (`mptest FAILED ...` / `mptest survived ...`, run.sh),
/// not anchored, so match on the FAILED/survived keyword.
fn classify(lines: &[String], end: BranchEnd) -> Outcome {
    let hit = lines
        .iter()
        .find(|l| l.contains("mptest FAILED") || l.contains("mptest survived"));
    match hit {
        Some(l) if l.contains("mptest FAILED") => Outcome::Failed(l.trim().to_string()),
        Some(l) => Outcome::Survived(l.trim().to_string()),
        None => Outcome::NoResult(match end {
            BranchEnd::Shutdown => "shutdown, no result line".to_string(),
            BranchEnd::Deadline => "hit run deadline (wedged?)".to_string(),
            BranchEnd::Unexpected(k) => k,
        }),
    }
}

/// splitmix64: turn a counter into a well-spread 64-bit seed so consecutive
/// `seed_base + i` do not give near-identical schedules. Deterministic, so the
/// same `(seed_base, i)` always yields the same `child_seed` (replayable).
fn split_mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[derive(Parser, Debug)]
#[command(name = "mptest_fuzz")]
#[command(about = "Fork-based fuzzer for the mptest concurrency-fuzz workload")]
struct Args {
    /// Path to the vmlinux ELF image (guest kernel).
    vmlinux: String,
    /// Path to the podman initrd image.
    initramfs: String,
    /// Host path served to the guest as `compose.yaml`.
    compose: String,
    /// Host path served to the guest as `images.tar`.
    images: String,

    /// Seed for the shared boot / PCT regime. All children in one run share it;
    /// vary it across runs for regime diversity.
    #[arg(long, default_value_t = 0xbed0_0001)]
    boot_seed: u64,

    /// Base for the swept child seeds: child i uses `splitmix64(seed_base + i)`.
    #[arg(long, default_value_t = 1)]
    seed_base: u64,

    /// Number of child branches (seeds) to fork from the one boot.
    #[arg(long, default_value_t = 8)]
    count: u32,

    /// Virtual-time budget for boot to reach the ready checkpoint, seconds.
    #[arg(long, default_value_t = 900.0)]
    boot_deadline: f64,

    /// Per-branch virtual-time budget after ready, seconds (wedge guard).
    #[arg(long, default_value_t = 1800.0)]
    run_deadline: f64,

    /// If set, write `summary.txt` (per-seed results) under this directory.
    #[arg(long)]
    out: Option<String>,

    /// Suppress per-line serial echo to stderr (results still print to stdout).
    #[arg(long)]
    quiet: bool,
}

/// Event sink that retains each branch's serial lines (keyed by `BranchId`) so
/// the driver can scan them for the result after the branch finishes, and
/// optionally echoes them to stderr as they arrive.
struct CaptureSink {
    serial: Mutex<HashMap<BranchId, Vec<String>>>,
    echo: bool,
}

impl CaptureSink {
    fn new(echo: bool) -> Self {
        Self {
            serial: Mutex::new(HashMap::new()),
            echo,
        }
    }

    fn lines(&self, branch: BranchId) -> Vec<String> {
        self.serial
            .lock()
            .unwrap()
            .get(&branch)
            .cloned()
            .unwrap_or_default()
    }
}

impl EventSink for CaptureSink {
    fn on_event(&self, event: Event<'_>) {
        if let Event::SerialLine { branch, at, line } = event {
            let s = String::from_utf8_lossy(line).into_owned();
            if self.echo {
                eprintln!("[br {branch:?} vt {:>8.3}] {s}", at.as_secs_f64());
            }
            self.serial
                .lock()
                .unwrap()
                .entry(branch)
                .or_default()
                .push(s);
        }
    }
}
