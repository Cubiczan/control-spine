//! CLI: `compute | verify | explain`.
//!
//! The binary is the boundary: the engine stays pure, this file does all
//! filesystem access. Exit codes: 0 success, 1 verification failure
//! (fail-closed), 2 usage/schema errors.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use spine::Signoff;

use access_recert_spine::model::{validate, CampaignInput, RecertConfig};
use access_recert_spine::pack::{build_pack, render_explain, verify_pack, PackDocument};

#[derive(Parser)]
#[command(
    name = "access-recert-spine",
    version,
    about = "Quarterly access recertification control spine (IT/IAM)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute the campaign and emit an evidence pack (JSON).
    Compute {
        /// Path to the campaign input JSON.
        #[arg(long)]
        inputs: PathBuf,
        /// Path to the config JSON (rule thresholds).
        #[arg(long)]
        config: PathBuf,
        /// Path to a JSON array of signoff receipts (retention approvals).
        #[arg(long)]
        signoffs: Option<PathBuf>,
        /// Write the pack here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an evidence pack against its inputs and config. Fails closed.
    Verify {
        /// Path to the pack document JSON.
        #[arg(long)]
        pack: PathBuf,
        /// Path to the campaign input JSON the pack was computed from.
        #[arg(long)]
        inputs: PathBuf,
        /// Path to the config JSON the pack was computed with.
        #[arg(long)]
        config: PathBuf,
    },
    /// Explain a pack: queues, required signoffs, rule catalog.
    Explain {
        /// Path to the pack document JSON.
        #[arg(long)]
        pack: PathBuf,
    },
}

enum CliError {
    /// Bad files, bad schema, bad usage — exit 2.
    Usage(String),
    /// The pack did not verify — exit 1.
    Verification(String),
}

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|e| CliError::Usage(format!("cannot read {}: {e}", path.display())))
}

fn parse_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &str,
    path: &Path,
) -> Result<T, CliError> {
    serde_json::from_slice(bytes)
        .map_err(|e| CliError::Usage(format!("{what} {} is not valid: {e}", path.display())))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err(CliError::Usage(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
        Err(CliError::Verification(message)) => {
            eprintln!("verify: FAILED — {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Compute {
            inputs,
            config,
            signoffs,
            out,
        } => {
            let inputs_bytes = read_file(&inputs)?;
            let params_bytes = read_file(&config)?;
            let input: CampaignInput = parse_json(&inputs_bytes, "campaign inputs", &inputs)?;
            let recert_config: RecertConfig = parse_json(&params_bytes, "config", &config)?;
            validate(&input).map_err(CliError::Usage)?;
            let signoffs: Vec<Signoff> = match &signoffs {
                Some(path) => {
                    let bytes = read_file(path)?;
                    parse_json(&bytes, "signoff receipts", path)?
                }
                None => Vec::new(),
            };
            let document = build_pack(
                &input,
                &recert_config,
                &inputs_bytes,
                &params_bytes,
                signoffs,
            )
            .map_err(|e| CliError::Usage(format!("lock progression failed: {e}")))?;
            let body = serde_json::to_vec_pretty(&document)
                .expect("pack document serialization cannot fail");
            match out {
                Some(path) => {
                    fs::write(&path, body).map_err(|e| {
                        CliError::Usage(format!("cannot write {}: {e}", path.display()))
                    })?;
                }
                None => {
                    std::io::stdout().write_all(&body).map_err(|e| {
                        CliError::Usage(format!("cannot write pack to stdout: {e}"))
                    })?;
                    println!();
                }
            }
            Ok(())
        }
        Command::Verify {
            pack,
            inputs,
            config,
        } => {
            let pack_bytes = read_file(&pack)?;
            let document: PackDocument = parse_json(&pack_bytes, "pack document", &pack)?;
            let inputs_bytes = read_file(&inputs)?;
            let params_bytes = read_file(&config)?;
            let input: CampaignInput = parse_json(&inputs_bytes, "campaign inputs", &inputs)?;
            let recert_config: RecertConfig = parse_json(&params_bytes, "config", &config)?;
            validate(&input).map_err(CliError::Usage)?;
            verify_pack(
                &document,
                &input,
                &recert_config,
                &inputs_bytes,
                &params_bytes,
            )
            .map_err(|e| CliError::Verification(e.to_string()))?;
            println!(
                "OK: pack verifies (seal intact, provenance hashes recompute, findings reproduce from inputs, signoffs resolve all gated findings)"
            );
            Ok(())
        }
        Command::Explain { pack } => {
            let pack_bytes = read_file(&pack)?;
            let document: PackDocument = parse_json(&pack_bytes, "pack document", &pack)?;
            print!("{}", render_explain(&document));
            Ok(())
        }
    }
}
