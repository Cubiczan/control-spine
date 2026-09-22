//! CLI: `compute | verify | explain`. The binary only moves bytes across
//! process boundaries — reading files and printing. All logic lives in the
//! pure library; exit code 0 verifies, 1 is a refusal, 2 is a usage/IO
//! error.

use crate::pack::{self, GhgEvidencePack, RestatementRequest};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "ghg-ledger-spine",
    version,
    about = "Deterministic Scope 1/2/3 GHG inventory control spine (ESG/Sustainability)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Compute an inventory and emit a sealed evidence pack on stdout.
    Compute {
        /// Activity records JSON.
        #[arg(long)]
        inputs: PathBuf,
        /// Config JSON: factor table, conversions, scope 3 categories, DQ tiers.
        #[arg(long)]
        config: PathBuf,
        /// Predecessor pack to restate from (new ledger version; the
        /// predecessor is never modified).
        #[arg(long, requires = "reason")]
        prior_pack: Option<PathBuf>,
        /// Mandatory restatement reason when --prior-pack is given.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Verify a pack against its inputs and config. Refuses on any doubt.
    Verify {
        /// Evidence pack JSON.
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        config: PathBuf,
        /// Predecessor pack — required when the pack carries a restatement.
        #[arg(long)]
        prior_pack: Option<PathBuf>,
    },
    /// Render a human-readable summary of a pack (no verification).
    Explain {
        #[arg(long)]
        pack: PathBuf,
    },
}

/// A command failure with the process exit code it maps to.
struct CmdError {
    code: u8,
    message: String,
}

impl CmdError {
    fn refusal(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
    fn io(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
}

type CmdResult = Result<(), CmdError>;

fn read_file(path: &Path) -> Result<Vec<u8>, CmdError> {
    std::fs::read(path).map_err(|e| CmdError::io(format!("cannot read {}: {e}", path.display())))
}

fn parse_pack(bytes: &[u8], label: &str) -> Result<GhgEvidencePack, CmdError> {
    serde_json::from_slice(bytes)
        .map_err(|e| CmdError::refusal(format!("{label} is not a ghg evidence pack: {e}")))
}

/// Entry point returning the process exit code.
pub fn run() -> u8 {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Compute {
            inputs,
            config,
            prior_pack,
            reason,
        } => cmd_compute(&inputs, &config, prior_pack.as_deref(), reason.as_deref()),
        Command::Verify {
            pack,
            inputs,
            config,
            prior_pack,
        } => cmd_verify(&pack, &inputs, &config, prior_pack.as_deref()),
        Command::Explain { pack } => cmd_explain(&pack),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {}", e.message);
            e.code
        }
    }
}

fn cmd_compute(
    inputs: &Path,
    config: &Path,
    prior_pack: Option<&Path>,
    reason: Option<&str>,
) -> CmdResult {
    let restatement = match (prior_pack, reason) {
        (Some(p), Some(r)) => {
            let prior_bytes = read_file(p)?;
            let prior = parse_pack(&prior_bytes, "predecessor pack")?;
            Some(RestatementRequest {
                prior,
                reason: r.to_string(),
            })
        }
        _ => None,
    };
    if reason.is_some() && prior_pack.is_none() {
        return Err(CmdError::io("--reason requires --prior-pack"));
    }

    let inputs_bytes = read_file(inputs)?;
    let config_bytes = read_file(config)?;
    let pack = pack::compute(&inputs_bytes, &config_bytes, restatement)
        .map_err(|e| CmdError::refusal(e.to_string()))?;
    let rendered = serde_json::to_string_pretty(&pack)
        .map_err(|e| CmdError::refusal(format!("pack serialization failed: {e}")))?;
    println!("{rendered}");
    Ok(())
}

fn cmd_verify(
    pack_path: &Path,
    inputs: &Path,
    config: &Path,
    prior_pack: Option<&Path>,
) -> CmdResult {
    let pack_bytes = read_file(pack_path)?;
    let parsed = parse_pack(&pack_bytes, "pack")?;
    let inputs_bytes = read_file(inputs)?;
    let config_bytes = read_file(config)?;
    let prior = match prior_pack {
        Some(p) => {
            let prior_bytes = read_file(p)?;
            Some(parse_pack(&prior_bytes, "predecessor pack")?)
        }
        None => None,
    };
    match pack::verify(&parsed, &inputs_bytes, &config_bytes, prior.as_ref()) {
        Ok(()) => {
            println!(
                "ok: pack verifies — spine {} seal intact, provenance hashes recompute, body matches its inputs",
                spine::SPINE_VERSION
            );
            Ok(())
        }
        Err(refusal) => Err(CmdError::refusal(format!("refused: {refusal}"))),
    }
}

fn cmd_explain(pack_path: &Path) -> CmdResult {
    let pack_bytes = read_file(pack_path)?;
    let parsed = parse_pack(&pack_bytes, "pack")?;
    println!("ghg-ledger-spine evidence pack");
    println!(
        "  engine: {} {} (spine {})",
        parsed.pack.engine_id, parsed.pack.tool_version, parsed.pack.spine_version
    );
    println!("  period: {}", parsed.period);
    println!("  inputs_hash: {}", parsed.pack.inputs_hash);
    println!("  params_hash: {}", parsed.pack.params_hash);
    println!("  body_hash: {}", parsed.pack.body_hash);

    match crate::ledger_totals(&parsed.lines) {
        Ok(totals) => {
            println!("  lines: {} — totals (grams CO2e):", parsed.lines.len());
            for (key, grams) in totals {
                println!("    {key}: {grams}");
            }
        }
        Err(e) => {
            return Err(CmdError::refusal(format!(
                "pack lines overflow the ledger: {e}"
            )))
        }
    }

    println!("  findings: {}", parsed.pack.findings.len());
    for f in &parsed.pack.findings {
        println!(
            "    [{:?}] {} {}: {}",
            f.severity, f.rule_id, f.subject, f.message
        );
    }
    println!("  signoffs: {}", parsed.pack.signoffs.len());
    for s in &parsed.pack.signoffs {
        println!(
            "    {} ({}): {:?} on {} at {}",
            s.actor, s.role, s.decision, s.subject, s.at
        );
    }
    match &parsed.restatement {
        None => println!("  restatement: none"),
        Some(r) => {
            println!(
                "  restatement: '{}' from predecessor body hash {} ({} deltas)",
                r.reason,
                r.predecessor_body_hash,
                r.deltas.len()
            );
            for d in &r.deltas {
                println!(
                    "    {}: prior {} g, current {} g, delta {} g",
                    d.ledger_key, d.prior_grams, d.current_grams, d.delta_grams
                );
            }
        }
    }
    Ok(())
}
