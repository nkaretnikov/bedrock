// SPDX-License-Identifier: GPL-2.0

//! Fork-based fuzzer for the mptest concurrency-fuzz workload.
//!
//! Boots the mptest guest to the ready checkpoint, then forks one kernel-seeded
//! branch per child seed: each branch re-rolls the PCT schedule from its own
//! getrandom stream and runs mptest to completion, hunting the libmultiprocess
//! IPC races (#35491 hang, #34014 crash). The expensive boot (kernel + podman +
//! image load + container) is paid once per regime and shared by every child via
//! copy-on-write; only the workload tail runs per seed.
//!
//! One-shot (a batch off a single boot):
//!
//! ```text
//! cargo run --release -p bedrock-lab --example mptest_fuzz -- \
//!     <vmlinux> <initramfs> <compose.yaml> <images.tar> --count 16 --out DIR
//! ```
//!
//! Continuous campaign (keep booting fresh regimes and forking batches until the
//! wall-clock budget; this is what `fork-parallel.sh` runs per worker):
//!
//! ```text
//! ... --count 64 --duration-secs 86400 --out DIR --quiet
//! ```
//!
//! Replay a repro (reproduce one `(boot_seed, child_seed)` pair):
//!
//! ```text
//! ... --boot-seed <BS> --replay-child <CS>
//! ```
//!
//! A repro is the pair `(boot_seed, child_seed)`, both recorded per branch in
//! `summary.txt` (with the branch's `pool[0]` fingerprint) and re-runnable with
//! `--replay-child`.
//!
//! REQUIRES the guest-side post-ready pool re-roll (scx-init refills rnd_pool
//! from getrandom after `bedrock-vmcall --ready`, driven by the /bedrock/scx
//! handshake). Without it every branch inherits the same pre-filled pool and
//! replays the identical schedule (identical `pool[0]` across seeds).

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bedrock_lab::{
    BranchId, Checkpoint, Event, EventSink, LabOpts, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{boot::defaults, load_kernel, ExitKind, LinuxBootConfig, VmBuilder};
use clap::Parser;

bedrock_lab::define_virt_time_macros!($, bedrock_vm::DEFAULT_TSC_FREQUENCY);

const MEMORY_MB: usize = 5120;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let sink = Arc::new(CaptureSink::new(!args.quiet));

    // Read the guest images once; every boot reuses these bytes.
    let kernel = fs::read(&args.vmlinux)?;
    let initramfs = fs::read(&args.initramfs)?;
    let guest = Guest {
        kernel: &kernel,
        initramfs: &initramfs,
        compose: &args.compose,
        images: &args.images,
    };

    // Replay mode: reproduce exactly one (boot_seed, child_seed) and report.
    if let Some(child_seed) = args.replay_child {
        let ready = boot_ready(&guest, args.boot_seed, args.boot_deadline, &sink)?;
        let (result, lines) = run_one(&ready, child_seed, args.run_deadline, &sink)?;
        println!(
            "replay boot_seed={:#018x} child_seed={child_seed:#018x} pool[0]={}  {}",
            args.boot_seed,
            pool0(&lines).unwrap_or_else(|| "?".into()),
            result.describe(),
        );
        return Ok(());
    }

    if let Some(dir) = &args.out {
        fs::create_dir_all(dir)?;
    }
    let mut summary = open_summary(&args)?;

    // Campaign loop: each epoch boots a fresh regime (boot_seed = base + epoch)
    // and forks `--count` child branches from it; child seeds are swept from one
    // monotonic counter across all epochs so no seed repeats. With
    // `--duration-secs 0` (default) it runs exactly one epoch (a single batch);
    // otherwise it keeps going until the wall-clock budget.
    let start = Instant::now();
    let budget = Duration::from_secs(args.duration_secs);
    let over_budget = |s: &Instant| args.duration_secs > 0 && s.elapsed() >= budget;

    let mut child_counter = args.seed_base;
    let mut epoch: u64 = 0;
    let mut total = 0u64;
    let mut repros = 0u64;

    while !over_budget(&start) {
        let boot_seed = args.boot_seed.wrapping_add(epoch);
        let ready = boot_ready(&guest, boot_seed, args.boot_deadline, &sink)?;
        eprintln!(
            "[epoch {epoch}] boot_seed={boot_seed:#018x} ready at vt {:.3}s (elapsed {:.0}s)",
            ready.time().as_secs_f64(),
            start.elapsed().as_secs_f64(),
        );

        for k in 0..args.count {
            if over_budget(&start) {
                break;
            }
            let child_seed = split_mix64(child_counter);
            child_counter = child_counter.wrapping_add(1);

            let (result, lines) = run_one(&ready, child_seed, args.run_deadline, &sink)?;
            total += 1;
            let repro = matches!(result, Outcome::Failed(_));
            if repro {
                repros += 1;
            }

            let p0 = pool0(&lines).unwrap_or_else(|| "?".into());
            println!(
                "[e{epoch} {:>4}/{}] {boot_seed:#018x} {child_seed:#018x} {p0}  {}{}",
                k + 1,
                args.count,
                result.describe(),
                if repro { "   <<< REPRO" } else { "" },
            );
            if let Some(f) = summary.as_mut() {
                // Flush every line so a kill/crash mid-campaign loses nothing.
                writeln!(
                    f,
                    "{boot_seed:#018x} {child_seed:#018x} {p0}  {}",
                    result.describe()
                )?;
                f.flush()?;
            }
            // Keep a full log only for repros: a 24h run cannot keep one per branch.
            if repro {
                eprintln!(">>> REPRO boot_seed={boot_seed:#018x} child_seed={child_seed:#018x}");
                if let Some(dir) = &args.out {
                    let path = format!("{dir}/repro-{boot_seed:#018x}-{child_seed:#018x}.log");
                    if let Err(e) = write_branch_log(&path, &lines) {
                        eprintln!("  warn: could not write {path}: {e}");
                    }
                }
            }
        }

        eprintln!(
            "[epoch {epoch}] done: total={total} repros={repros} elapsed={:.0}s",
            start.elapsed().as_secs_f64(),
        );
        epoch += 1;
        drop(ready); // free the VM/checkpoint before booting the next regime
        if args.duration_secs == 0 {
            break; // single-batch mode
        }
    }

    eprintln!(
        "campaign done: {epoch} regimes, {total} branches, {repros} repros, {:.0}s",
        start.elapsed().as_secs_f64(),
    );
    Ok(())
}

/// The guest images, borrowed for the lifetime of the run so every boot reuses
/// the same in-memory bytes rather than re-reading from disk.
struct Guest<'a> {
    kernel: &'a [u8],
    initramfs: &'a [u8],
    compose: &'a str,
    images: &'a str,
}

/// Boot one guest under `boot_seed` and return its ready checkpoint. Serves the
/// two workload files over the file-fetch hypercall (like `bedrock-cli --file`).
fn boot_ready(
    guest: &Guest,
    boot_seed: u64,
    boot_deadline: f64,
    sink: &Arc<CaptureSink>,
) -> Result<Checkpoint, Box<dyn Error>> {
    let mut vm = VmBuilder::new().memory_mb(MEMORY_MB).build()?;
    let (kernel_entry, kernel_end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, guest.kernel)?
    };
    let boot = LinuxBootConfig::new(kernel_entry, kernel_end)
        .cmdline(defaults::CMDLINE)
        .initramfs(guest.initramfs);
    vm.setup_linux_boot(&boot)?;

    let deadline = VirtTime::from_secs_f64(boot_deadline, bedrock_vm::DEFAULT_TSC_FREQUENCY);
    let ready = Checkpoint::initial_when_ready_with(
        vm,
        deadline,
        LabOpts {
            sink: sink.clone(),
            rng: RngMode::Seeded(boot_seed),
            files: vec![
                ("compose.yaml".to_string(), guest.compose.to_string()),
                ("images.tar".to_string(), guest.images.to_string()),
            ],
            ..Default::default()
        },
    )?;
    Ok(ready)
}

/// Fork one kernel-seeded branch, re-seed it, and drive it to completion. From
/// the reseed its getrandom stream -- including scx-init's post-ready pool refill
/// -- is a pure function of `child_seed`, so it draws a distinct PCT schedule.
/// Returns the classified result and the branch's captured serial.
fn run_one(
    ready: &Checkpoint,
    child_seed: u64,
    run_deadline: f64,
    sink: &Arc<CaptureSink>,
) -> Result<(Outcome, Vec<String>), Box<dyn Error>> {
    let mut branch = ready.branch()?;
    let id = branch.id();
    branch.reseed(child_seed)?;

    let deadline = ready.time() + VirtDuration::from_secs_f64(run_deadline, ready.tsc_frequency());
    let end = run_branch(&mut branch, deadline)?;
    let lines = sink.take(id);
    drop(branch); // free the live-branch slot before the next fork
    Ok((classify(&lines, end), lines))
}

/// Open (truncate) the campaign summary file if `--out` is set, writing a header
/// that pins the run. One line per branch is appended as it finishes.
fn open_summary(args: &Args) -> std::io::Result<Option<fs::File>> {
    let Some(dir) = &args.out else {
        return Ok(None);
    };
    let mut f = fs::File::create(format!("{dir}/summary.txt"))?;
    writeln!(
        f,
        "# boot_seed base={:#018x}  seed_base={:#018x}",
        args.boot_seed, args.seed_base
    )?;
    writeln!(f, "# columns: <boot_seed> <child_seed> <pool0> <result>")?;
    Ok(Some(f))
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

/// Pull the human text out of a serial line. The guest routes console output
/// through journald, so lines arrive as JSON like
/// `{"SYSLOG_IDENTIFIER":"scx-fuzz","MESSAGE":"..."}`; return the `MESSAGE` field
/// (trimmed) when the line parses as such, else the line as-is.
fn message_text(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| {
            v.get("MESSAGE")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| line.to_string())
        .trim()
        .to_string()
}

/// The branch's post-ready pool fingerprint (`pool[0] 0x…`, logged once by
/// scx-init after the re-roll). Distinct values across branches prove divergence.
fn pool0(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|l| {
        let m = message_text(l);
        let i = m.find("pool refilled post-ready")?;
        let hex = m[i..].split("pool[0]").nth(1)?.trim();
        hex.split_whitespace().next().map(str::to_string)
    })
}

/// Map a finished branch's serial output to a workload result. The result line
/// is guest console output (`mptest FAILED ...` / `mptest survived ...`, run.sh),
/// not anchored, so match on the FAILED/survived keyword.
fn classify(lines: &[String], end: BranchEnd) -> Outcome {
    let hit = lines
        .iter()
        .map(|l| message_text(l))
        .find(|m| m.contains("mptest FAILED") || m.contains("mptest survived"));
    match hit {
        Some(m) if m.contains("mptest FAILED") => Outcome::Failed(m),
        Some(m) => Outcome::Survived(m),
        None => Outcome::NoResult(match end {
            BranchEnd::Shutdown => "shutdown, no result line".to_string(),
            BranchEnd::Deadline => "hit run deadline (wedged?)".to_string(),
            BranchEnd::Unexpected(k) => k,
        }),
    }
}

/// Write one branch's captured serial to a log file, one cleaned line each, so a
/// repro is inspectable after the fact.
fn write_branch_log(path: &str, lines: &[String]) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    for l in lines {
        writeln!(f, "{}", message_text(l))?;
    }
    Ok(())
}

/// splitmix64: turn a counter into a well-spread 64-bit seed so consecutive
/// counter values do not give near-identical schedules. Deterministic, so a
/// recorded `child_seed` always maps back to the same schedule (replayable).
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

    /// Base boot / PCT-regime seed. In a campaign, epoch e boots `boot_seed + e`,
    /// so each regime is a distinct PCT profile; children of one boot vary the
    /// pool within it.
    #[arg(long, default_value_t = 0xbed0_0001)]
    boot_seed: u64,

    /// Base for the swept child seeds: they are `splitmix64(seed_base + n)` for a
    /// monotonic n across the whole run.
    #[arg(long, default_value_t = 1)]
    seed_base: u64,

    /// Child branches to fork per boot (per regime).
    #[arg(long, default_value_t = 8)]
    count: u32,

    /// Total wall-clock budget in seconds. 0 = a single batch of `--count` off
    /// one boot; >0 = keep booting fresh regimes and forking batches until it
    /// elapses (a continuous campaign).
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,

    /// Reproduce exactly one `(--boot-seed, this)` pair and exit. Ignores
    /// `--count`/`--duration-secs`.
    #[arg(long)]
    replay_child: Option<u64>,

    /// Virtual-time budget for boot to reach the ready checkpoint, seconds.
    #[arg(long, default_value_t = 900.0)]
    boot_deadline: f64,

    /// Per-branch virtual-time budget after ready, seconds (wedge guard).
    #[arg(long, default_value_t = 1800.0)]
    run_deadline: f64,

    /// If set, write `summary.txt` (one line per branch) and one
    /// `repro-<boot_seed>-<child_seed>.log` per FAILED branch here.
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

    /// Remove and return a finished branch's captured lines. Removing bounds the
    /// map to only the in-flight branch's output rather than the whole run's.
    fn take(&self, branch: BranchId) -> Vec<String> {
        self.serial
            .lock()
            .unwrap()
            .remove(&branch)
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
