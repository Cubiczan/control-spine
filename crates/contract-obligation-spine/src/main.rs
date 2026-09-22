//! CLI for the contract obligation spine. Thin file IO over the pure
//! library: the engine itself never touches the filesystem, the clock, or
//! the network — every date, including today, is caller input.
//!
//! Exit codes: 0 success, 1 verification refused (fail-closed), 2 config or
//! schema error (no pack produced).

use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use serde::Deserialize;

use contract_obligation_spine::model::{PolicyParams, RegisterInputs};
use contract_obligation_spine::{
    build_pack, evaluate, finalize_lock, verify_pack, Evaluation, EvidencePack,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Refused(String),
}

#[derive(Parser)]
#[command(
    name = "contract-obligation-spine",
    version,
    about = "Legal control spine: typed obligation register with deterministic deadline and renewal-window arithmetic"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate the register at the caller-supplied clock and emit a sealed
    /// evidence pack (JSON).
    Compute {
        /// Register JSON: the append-only obligation records.
        #[arg(long)]
        inputs: PathBuf,
        /// Policy config JSON: warn windows, roll mode, calendars, SLA tiers.
        #[arg(long)]
        params: PathBuf,
        /// The clock, as YYYY-MM-DD. The engine never reads a real clock.
        #[arg(long)]
        clock: String,
        /// Optional signoff receipts JSON: { "signoffs": [...] }.
        #[arg(long)]
        signoffs: Option<PathBuf>,
        /// Write the pack here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fail-closed verification of an evidence pack against register and
    /// params. Refuses tampered packs, foreign versions, unresolved
    /// breaches, and corrections lacking four-eyes signoff.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        params: PathBuf,
    },
    /// Explain the computed deadlines, renewal windows, and SLA credits in
    /// plain text — the same arithmetic `compute` runs, unpacked.
    Explain {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        params: PathBuf,
        #[arg(long)]
        clock: String,
    },
}

#[derive(Deserialize)]
struct SignoffsFile {
    signoffs: Vec<spine::Signoff>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T, CliError> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| CliError::Config(format!("cannot read {what} {}: {e}", path.display())))?;
    serde_json::from_str(&s).map_err(|e| {
        CliError::Config(format!(
            "schema check failed for {what} {}: {e}",
            path.display()
        ))
    })
}

fn parse_clock(s: &str) -> Result<NaiveDate, CliError> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|e| CliError::Config(format!("invalid --clock '{s}': {e}")))
}

fn short(hash: &str) -> &str {
    hash.get(0..12).unwrap_or("(none)")
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Compute {
            inputs,
            params,
            clock,
            signoffs,
            out,
        } => {
            let inputs: RegisterInputs = read_json(&inputs, "inputs")?;
            let params: PolicyParams = read_json(&params, "params")?;
            let clock = parse_clock(&clock)?;
            let evaluation =
                evaluate(&inputs, &params, clock).map_err(|e| CliError::Config(e.to_string()))?;
            let signoffs = match &signoffs {
                Some(p) => read_json::<SignoffsFile>(p, "signoffs")?.signoffs,
                None => Vec::new(),
            };
            let pack = build_pack(evaluation.findings, &inputs, &params, signoffs);
            let (pack, state) = finalize_lock(pack);
            let json = serde_json::to_string_pretty(&pack)
                .expect("EvidencePack serialization cannot fail");
            match &out {
                Some(p) => std::fs::write(p, format!("{json}\n"))
                    .map_err(|e| CliError::Config(format!("cannot write {}: {e}", p.display())))?,
                None => println!("{json}"),
            }
            let (b, w, i) = pack
                .findings
                .iter()
                .fold((0, 0, 0), |acc, f| match f.severity {
                    spine::Severity::Breach => (acc.0 + 1, acc.1, acc.2),
                    spine::Severity::Warn => (acc.0, acc.1 + 1, acc.2),
                    spine::Severity::Info => (acc.0, acc.1, acc.2 + 1),
                });
            eprintln!(
                "findings: {b} breach, {w} warn, {i} info; lock: {state:?} (inputs {})",
                short(&pack.inputs_hash)
            );
            Ok(())
        }
        Commands::Verify {
            pack,
            inputs,
            params,
        } => {
            let pack: EvidencePack = read_json(&pack, "pack")?;
            let inputs: RegisterInputs = read_json(&inputs, "inputs")?;
            let params: PolicyParams = read_json(&params, "params")?;
            match verify_pack(&pack, &inputs, &params) {
                Ok(()) => {
                    println!(
                        "verified: pack {} ({}) over inputs {} params {}",
                        short(&pack.body_hash),
                        pack.spine_version,
                        short(&pack.inputs_hash),
                        short(&pack.params_hash)
                    );
                    Ok(())
                }
                Err(e) => Err(CliError::Refused(e.to_string())),
            }
        }
        Commands::Explain {
            inputs,
            params,
            clock,
        } => {
            let inputs: RegisterInputs = read_json(&inputs, "inputs")?;
            let params: PolicyParams = read_json(&params, "params")?;
            let clock = parse_clock(&clock)?;
            let evaluation: Evaluation =
                evaluate(&inputs, &params, clock).map_err(|e| CliError::Config(e.to_string()))?;
            explain(&evaluation, clock);
            Ok(())
        }
    }
}

fn explain(evaluation: &Evaluation, clock: NaiveDate) {
    println!("contract obligation register — evaluated at {clock}");
    for r in &evaluation.resolutions {
        println!();
        println!(
            "{} [{}] {}",
            r.obligation_id,
            kind_label(r.kind),
            r.counterparty
        );
        match r.due_date {
            Some(due) => {
                let base = r
                    .base_date
                    .map(|b| format!("base {b}"))
                    .unwrap_or_else(|| "no anchor base".to_string());
                let roll = if r.roll_applied {
                    ", rolled to business day"
                } else {
                    ""
                };
                println!("  effective date {due} ({base}{roll})");
                if let Some(days) = r.days_remaining {
                    println!("  days remaining: {days}");
                }
            }
            None => println!("  effective date: pending (anchor event has not occurred)"),
        }
        if let Some(tier) = r.tier_min_uptime_bp {
            println!(
                "  latest measurement: tier floor {tier} bp, credit {} cents",
                r.credit_cents.unwrap_or(0)
            );
        }
    }
    println!();
    if evaluation.findings.is_empty() {
        println!("findings: none");
        return;
    }
    println!("findings:");
    for f in &evaluation.findings {
        let sev = match f.severity {
            spine::Severity::Breach => "breach",
            spine::Severity::Warn => "warn",
            spine::Severity::Info => "info",
        };
        println!("  [{sev}] {} {}: {}", f.rule_id, f.subject, f.message);
    }
}

fn kind_label(kind: contract_obligation_spine::ResolutionKind) -> &'static str {
    match kind {
        contract_obligation_spine::ResolutionKind::Due => "due",
        contract_obligation_spine::ResolutionKind::OptOut => "opt-out",
        contract_obligation_spine::ResolutionKind::Sla => "sla",
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        match e {
            CliError::Refused(_) => {
                eprintln!("refused: {e}");
                std::process::exit(1);
            }
            CliError::Config(_) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }
}
