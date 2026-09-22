//! CLI surface: compute | verify | explain.
//!
//! The binary does the I/O — reading input files, writing the pack — and
//! the engine stays pure. Exit codes: 0 on success (verify: pack authentic),
//! 1 on any refusal or error.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use spine::{EvidencePack, Severity, VerifyError};

use capa_spine::{build_pack, evaluate, explain_one, CapaConfig, CapaRecord, ENGINE_ID};

#[derive(Parser)]
#[command(
    name = "capa-spine",
    version,
    about = "Quality/EHS CAPA control spine — deterministic severity, containment, aging, and closure governance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a CAPA population and emit a sealed evidence pack.
    Compute {
        /// Path to the CAPA population JSON (array of records).
        #[arg(long, value_name = "FILE")]
        capas: PathBuf,
        /// Path to the config table JSON.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The clock, RFC 3339 — the engine never reads a clock.
        #[arg(long, value_name = "RFC3339")]
        as_of: String,
        /// Write the pack here instead of stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Engine identity recorded in the pack.
        #[arg(long, value_name = "ID", default_value = ENGINE_ID)]
        engine_id: String,
    },
    /// Fail-closed verification of a pack against the input and config bytes.
    Verify {
        /// Path to the evidence pack JSON.
        #[arg(long, value_name = "FILE")]
        pack: PathBuf,
        /// Path to the CAPA population the pack was computed from.
        #[arg(long, value_name = "FILE")]
        capas: PathBuf,
        /// Path to the config table the pack was computed with.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Explain the deterministic derivation for one CAPA.
    Explain {
        #[arg(long, value_name = "FILE")]
        capas: PathBuf,
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The clock, RFC 3339.
        #[arg(long, value_name = "RFC3339")]
        as_of: String,
        #[arg(long, value_name = "ID")]
        capa_id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(message) = run(cli) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Compute {
            capas,
            config,
            as_of,
            output,
            engine_id,
        } => {
            let (capas_bytes, capas) = load_capas(&capas)?;
            let (config_bytes, config) = load_config(&config)?;
            let as_of = parse_clock(&as_of)?;
            let evaluations =
                evaluate(&capas, &config, as_of).map_err(|e| format!("config refused: {e}"))?;
            let findings = evaluations
                .iter()
                .flat_map(|evaluation| evaluation.findings.iter().cloned())
                .collect();
            let pack = build_pack(&engine_id, findings, &capas_bytes, &config_bytes);

            let pack_json = serde_json::to_vec_pretty(&pack)
                .map_err(|e| format!("pack serialization failed: {e}"))?;
            match output {
                Some(path) => fs::write(&path, pack_json)
                    .map_err(|e| format!("cannot write pack to {}: {e}", path.display()))?,
                None => {
                    let text = String::from_utf8(pack_json)
                        .map_err(|e| format!("pack is not valid UTF-8: {e}"))?;
                    println!("{text}");
                }
            }

            let breaches = count_severity(&pack, Severity::Breach);
            let warns = count_severity(&pack, Severity::Warn);
            let infos = count_severity(&pack, Severity::Info);
            eprintln!(
                "capa-spine: {} capa(s), {} finding(s) — {breaches} breach, {warns} warn, {infos} info",
                capas.len(),
                pack.findings.len(),
            );
            if breaches > 0 {
                eprintln!(
                    "capa-spine: {breaches} breach finding(s) require subject-scoped signoff receipts before this pack verifies"
                );
            }
            Ok(())
        }
        Command::Verify {
            pack,
            capas,
            config,
        } => {
            let (capas_bytes, _) = load_capas(&capas)?;
            let (config_bytes, _) = load_config(&config)?;
            let pack_bytes = fs::read(&pack)
                .map_err(|e| format!("cannot read pack file {}: {e}", pack.display()))?;
            let pack: EvidencePack = serde_json::from_slice(&pack_bytes)
                .map_err(|e| format!("pack file is not a valid evidence pack: {e}"))?;
            match pack.verify(&capas_bytes, &config_bytes) {
                Ok(()) => {
                    let breaches = count_severity(&pack, Severity::Breach);
                    println!(
                        "verified: pack is authentic — engine {}, spine {}, {} finding(s) ({breaches} breach), seal intact, provenance matches the presented bytes",
                        pack.engine_id,
                        pack.spine_version,
                        pack.findings.len(),
                    );
                    Ok(())
                }
                Err(err) => Err(verify_error_message(&err)),
            }
        }
        Command::Explain {
            capas,
            config,
            as_of,
            capa_id,
        } => {
            let (_, capas) = load_capas(&capas)?;
            let (_, config) = load_config(&config)?;
            let as_of = parse_clock(&as_of)?;
            let evaluations =
                evaluate(&capas, &config, as_of).map_err(|e| format!("config refused: {e}"))?;
            let record = capas.iter().find(|c| c.id == capa_id);
            let evaluation = evaluations.iter().find(|e| e.capa_id == capa_id);
            match (record, evaluation) {
                (Some(record), Some(evaluation)) => {
                    println!("{}", explain_one(record, evaluation, &config, as_of));
                    Ok(())
                }
                _ => Err(format!("no CAPA with id {capa_id} in the population")),
            }
        }
    }
}

fn load_capas(path: &Path) -> Result<(Vec<u8>, Vec<CapaRecord>), String> {
    let bytes =
        fs::read(path).map_err(|e| format!("cannot read capas file {}: {e}", path.display()))?;
    let capas: Vec<CapaRecord> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("capas file is not a valid CAPA population: {e}"))?;
    Ok((bytes, capas))
}

fn load_config(path: &Path) -> Result<(Vec<u8>, CapaConfig), String> {
    let bytes =
        fs::read(path).map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    let config = CapaConfig::parse(&bytes).map_err(|e| format!("config refused: {e}"))?;
    Ok((bytes, config))
}

fn parse_clock(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| format!("--as-of must be an RFC 3339 timestamp: {e}"))
}

fn count_severity(pack: &EvidencePack, severity: Severity) -> usize {
    pack.findings
        .iter()
        .filter(|f| f.severity == severity)
        .count()
}

fn verify_error_message(err: &VerifyError) -> String {
    match err {
        VerifyError::HashMismatch { field } => format!(
            "refused: presented {field} bytes do not match the pack's recorded hash — fail-closed"
        ),
        VerifyError::BodyHashMismatch => {
            "refused: pack body altered after production (seal mismatch) — fail-closed".to_string()
        }
        VerifyError::UnresolvedBreach { rule_id } => format!(
            "refused: breach finding {rule_id} lacks an approving signoff naming its subject — fail-closed"
        ),
        VerifyError::ForeignVersion => {
            "refused: pack was not produced under this spine version — fail-closed".to_string()
        }
    }
}
