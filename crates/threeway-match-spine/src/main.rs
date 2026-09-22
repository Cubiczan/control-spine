//! CLI for the procurement control spine: `compute | verify | explain`.
//! All filesystem access lives here — the engine stays pure.
//!
//! Exit codes: 0 success; 1 verify refusal (fail-closed); 2 usage, IO,
//! parse, or compute-validation errors.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;

use spine::{EvidencePack, Severity, Signoff, SignoffDecision};
use threeway_match_spine::{verify_pack, MatchConfig, MatchInputs};

#[derive(Parser)]
#[command(
    name = "threeway-match-spine",
    version,
    about = "Procurement control spine: deterministic three-way/two-way match with fail-closed evidence packs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute the evidence pack for the presented inputs.
    Compute {
        /// JSON file: array of purchase orders.
        #[arg(long)]
        pos: PathBuf,
        /// JSON file: array of goods receipt lines.
        #[arg(long)]
        receipts: PathBuf,
        /// JSON file: array of invoices.
        #[arg(long)]
        invoices: PathBuf,
        /// JSON file: match config.
        #[arg(long)]
        config: PathBuf,
        /// Identity of this engine instance (separation of duties: approvals
        /// from this actor cannot resolve the pack's breaches).
        #[arg(long, default_value = "threeway-match-spine")]
        engine_id: String,
        /// Optional JSON file: array of signoff receipts to embed.
        #[arg(long)]
        signoffs: Option<PathBuf>,
        /// Pretty-print the pack.
        #[arg(long)]
        pretty: bool,
    },
    /// Verify a pack fail-closed against the presented inputs.
    Verify {
        /// JSON file: the evidence pack.
        #[arg(long)]
        pack: PathBuf,
        /// JSON file: array of purchase orders.
        #[arg(long)]
        pos: PathBuf,
        /// JSON file: array of goods receipt lines.
        #[arg(long)]
        receipts: PathBuf,
        /// JSON file: array of invoices.
        #[arg(long)]
        invoices: PathBuf,
        /// JSON file: match config.
        #[arg(long)]
        config: PathBuf,
    },
    /// Print a human-readable summary of a pack's findings and lock state.
    Explain {
        /// JSON file: the evidence pack.
        #[arg(long)]
        pack: PathBuf,
    },
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

fn load_inputs(pos: &Path, receipts: &Path, invoices: &Path) -> Result<MatchInputs, String> {
    Ok(MatchInputs {
        purchase_orders: load_json(pos)?,
        goods_receipts: load_json(receipts)?,
        invoices: load_json(invoices)?,
    })
}

fn run_compute(
    pos: &Path,
    receipts: &Path,
    invoices: &Path,
    config: &Path,
    engine_id: &str,
    signoffs: Option<&Path>,
    pretty: bool,
) -> Result<String, String> {
    let inputs = load_inputs(pos, receipts, invoices)?;
    let config: MatchConfig = load_json(config)?;
    let signoffs: Vec<Signoff> = match signoffs {
        Some(p) => load_json(p)?,
        None => Vec::new(),
    };
    let pack = threeway_match_spine::compute(
        &inputs,
        &config,
        engine_id,
        env!("CARGO_PKG_VERSION"),
        signoffs,
    )
    .map_err(|e| e.to_string())?;
    if pretty {
        serde_json::to_string_pretty(&pack).map_err(|e| e.to_string())
    } else {
        serde_json::to_string(&pack).map_err(|e| e.to_string())
    }
}

fn run_verify(
    pack: &Path,
    pos: &Path,
    receipts: &Path,
    invoices: &Path,
    config: &Path,
) -> Result<(), String> {
    let pack: EvidencePack = load_json(pack)?;
    let inputs = load_inputs(pos, receipts, invoices)?;
    let config: MatchConfig = load_json(config)?;
    verify_pack(&pack, &inputs, &config).map_err(|e| e.to_string())
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Breach => "BREACH",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

fn decision_label(decision: SignoffDecision) -> &'static str {
    match decision {
        SignoffDecision::Approve => "approve",
        SignoffDecision::Reject => "reject",
    }
}

fn explain(pack: &EvidencePack) {
    println!("engine         {}", pack.engine_id);
    println!("tool version   {}", pack.tool_version);
    println!("spine version  {}", pack.spine_version);
    println!("inputs hash    {}", pack.inputs_hash);
    println!("params hash    {}", pack.params_hash);
    println!("body hash      {}", pack.body_hash);

    let breaches = pack
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .count();
    let warns = pack
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();
    let infos = pack.findings.len() - breaches - warns;
    println!(
        "findings       {} (breach {breaches}, warn {warns}, info {infos})",
        pack.findings.len()
    );
    for f in &pack.findings {
        println!(
            "  [{}] {} {} — {}",
            severity_label(f.severity),
            f.rule_id,
            f.subject,
            f.message
        );
        if f.requires_signoff {
            println!("    signoff required on subject {}", f.subject);
        }
    }

    println!("signoffs       {}", pack.signoffs.len());
    for s in &pack.signoffs {
        println!(
            "  {} ({}) -> {} [{} @ {}]",
            s.actor,
            s.role,
            s.subject,
            decision_label(s.decision),
            s.at
        );
    }

    match spine::first_unresolved_finding(pack) {
        Some(f) => println!(
            "lock state     not signable — unresolved finding {} on {} (HALT by crosswalk)",
            f.rule_id, f.subject
        ),
        None => println!(
            "lock state     signable — draft -> awaiting_signoff -> signed; signing seals the pack (LOCKED by crosswalk)"
        ),
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Compute {
            pos,
            receipts,
            invoices,
            config,
            engine_id,
            signoffs,
            pretty,
        } => match run_compute(
            &pos,
            &receipts,
            &invoices,
            &config,
            &engine_id,
            signoffs.as_deref(),
            pretty,
        ) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
        Command::Verify {
            pack,
            pos,
            receipts,
            invoices,
            config,
        } => match run_verify(&pack, &pos, &receipts, &invoices, &config) {
            Ok(()) => {
                println!("verified: pack matches a fresh compute over the presented inputs and resolves its findings");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("REFUSED: {e}");
                ExitCode::from(1)
            }
        },
        Command::Explain { pack } => match load_json::<EvidencePack>(&pack) {
            Ok(p) => {
                explain(&p);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
    }
}
