//! `sox-testing-spine` CLI — the crate's only filesystem surface.
//!
//! Subcommands: `compute` (build the evidence pack for a population),
//! `verify` (fail-closed re-verification of a pack against the exact
//! inputs/params bytes), and `explain` (the deterministic plan a config
//! would apply). Exit codes: 0 on success, 1 on any refusal — malformed
//! inputs, invalid config, or a verification failure. Refusals never
//! produce a pack or a PASS line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sox_testing_spine::{compute_pack, finalize_signed, DEFAULT_ENGINE_ID};
use spine::{EvidencePack, LockError, Signoff, SPINE_VERSION};

#[derive(Debug, Parser)]
#[command(
    name = "sox-testing-spine",
    version,
    about = "Reproducible SOX control testing: seeded sampling, completeness checks, deficiency classification, fail-closed evidence packs.",
    after_help = "The engine is pure: time and every business fact are inputs. Signoff timestamps come from the caller's signoff file."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Compute the evidence pack for one control-testing population.
    /// With --signoffs, record the receipts and advance the lock to Signed
    /// (refuses while any finding is unresolved). The pack JSON is written
    /// to --output, or stdout when omitted.
    Compute {
        /// Population JSON (the exact bytes hashed into inputs_hash).
        #[arg(long, value_name = "FILE")]
        inputs: PathBuf,
        /// Test-plan config JSON (the exact bytes hashed into params_hash).
        #[arg(long, value_name = "FILE")]
        params: PathBuf,
        /// Producing-engine identity recorded in the pack. An approving
        /// signoff from this actor is void — an engine cannot countersign
        /// its own pack.
        #[arg(long, value_name = "ID", default_value = DEFAULT_ENGINE_ID)]
        engine_id: String,
        /// Optional JSON array of signoff receipts to record before sealing.
        #[arg(long, value_name = "FILE")]
        signoffs: Option<PathBuf>,
        /// Output path for the pack JSON (pretty-printed); stdout by default.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Verify an evidence pack against the exact inputs/params bytes.
    /// Fail-closed: any doubt — foreign version, broken seal, hash
    /// mismatch, unresolved finding — exits 1.
    Verify {
        #[arg(long, value_name = "FILE")]
        inputs: PathBuf,
        #[arg(long, value_name = "FILE")]
        params: PathBuf,
        /// Evidence pack JSON produced by `compute`.
        #[arg(long, value_name = "FILE")]
        pack: PathBuf,
    },
    /// Explain the deterministic plan a config applies: the sample-size
    /// table, the classification thresholds, and (with a population id and
    /// period) the sampling seed. No inputs required.
    Explain {
        /// Test-plan config JSON.
        #[arg(long, value_name = "FILE")]
        params: PathBuf,
        /// Population id whose sampling seed to show (with --period).
        #[arg(long, value_name = "ID", requires = "period")]
        population_id: Option<String>,
        /// Period whose sampling seed to show (with --population-id).
        #[arg(long, value_name = "PERIOD", requires = "population_id")]
        period: Option<String>,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Compute {
            inputs,
            params,
            engine_id,
            signoffs,
            output,
        } => run_compute(&inputs, &params, &engine_id, signoffs, output),
        Commands::Verify {
            inputs,
            params,
            pack,
        } => run_verify(&inputs, &params, &pack),
        Commands::Explain {
            params,
            population_id,
            period,
        } => run_explain(&params, population_id, period),
    }
}

fn read_file(path: &PathBuf, what: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {what} at {}: {e}", path.display()))
}

fn run_compute(
    inputs: &PathBuf,
    params: &PathBuf,
    engine_id: &str,
    signoffs: Option<PathBuf>,
    output: Option<PathBuf>,
) -> ExitCode {
    let inputs_bytes = match read_file(inputs, "inputs") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let params_bytes = match read_file(params, "params") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };

    let pack = match compute_pack(&inputs_bytes, &params_bytes, engine_id) {
        Ok(p) => p,
        Err(e) => return fail(&format!("compute failed: {e}")),
    };

    let (pack, lock_state) = match signoffs {
        None => (pack, spine::LockState::Draft),
        Some(path) => {
            let bytes = match read_file(&path, "signoffs") {
                Ok(b) => b,
                Err(e) => return fail(&e),
            };
            let receipts: Vec<Signoff> = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => return fail(&format!("signoffs JSON: {e}")),
            };
            match finalize_signed(pack, receipts) {
                Ok(signed) => signed,
                Err(LockError::UnresolvedBreach { rule_id }) => return fail(&format!(
                    "cannot sign: unresolved finding on rule {rule_id} (a human approval naming the finding subject is required)"
                )),
                Err(e) => return fail(&format!("cannot sign: {e}")),
            }
        }
    };

    let json = match serde_json::to_string_pretty(&pack) {
        Ok(j) => j,
        Err(e) => return fail(&format!("pack serialization: {e}")),
    };
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, json + "\n") {
                return fail(&format!("cannot write pack to {}: {e}", path.display()));
            }
            eprintln!(
                "pack written to {} (lock state: {lock_state:?})",
                path.display()
            );
        }
        None => println!("{json}"),
    }
    ExitCode::SUCCESS
}

fn run_verify(inputs: &PathBuf, params: &PathBuf, pack: &PathBuf) -> ExitCode {
    let inputs_bytes = match read_file(inputs, "inputs") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let params_bytes = match read_file(params, "params") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let pack_bytes = match read_file(pack, "pack") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let parsed: EvidencePack = match serde_json::from_slice(&pack_bytes) {
        Ok(p) => p,
        Err(e) => return fail(&format!("pack JSON: {e}")),
    };
    match parsed.verify(&inputs_bytes, &params_bytes) {
        Ok(()) => {
            println!(
                "PASS: {} findings, {} signoff(s), inputs {}, params {}, spine {SPINE_VERSION}",
                parsed.findings.len(),
                parsed.signoffs.len(),
                &parsed.inputs_hash[..16],
                &parsed.params_hash[..16],
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("VERIFY REFUSED: {e}")),
    }
}

fn run_explain(
    params: &PathBuf,
    population_id: Option<String>,
    period: Option<String>,
) -> ExitCode {
    let params_bytes = match read_file(params, "params") {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let config: sox_testing_spine::TestPlanConfig = match serde_json::from_slice(&params_bytes) {
        Ok(c) => c,
        Err(e) => return fail(&format!("config JSON: {e}")),
    };
    if let Err(e) = config.validate() {
        return fail(&format!("config refused: {e}"));
    }

    println!("sox-testing-spine plan (spine contract {SPINE_VERSION})");
    println!();
    println!("Sample-size table (frequency x risk tier -> minimum instances):");
    for rule in &config.sample_size_table {
        println!(
            "  {:>9?} x {:<6?} -> {}",
            rule.frequency, rule.risk_tier, rule.sample_size
        );
    }
    println!();
    println!("Classification thresholds (integer cents, strictly-above boundaries):");
    println!(
        "  significance (SOX-010/SOX-011 boundary):        {} cents",
        config.significance_threshold_cents
    );
    println!(
        "  materiality (SOX-012 boundary; final label human): {} cents",
        config.materiality_threshold_cents
    );

    // clap enforces the pair at parse time (requires), so both are Some or both None.
    if let (Some(id), Some(period)) = (population_id, period) {
        let seed = sox_testing_spine::testing_seed(&id, &period);
        println!();
        println!("Sampling seed for population {id} / period {period}:");
        println!("  {}", spine::sha256_hex(&seed));
        println!("  per-instance rank = SHA-256(seed || instance_id); lowest ranks are selected.");
    }
    ExitCode::SUCCESS
}

fn fail(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_compute_with_defaults() {
        let cli = Cli::try_parse_from([
            "sox-testing-spine",
            "compute",
            "--inputs",
            "pop.json",
            "--params",
            "plan.json",
        ])
        .expect("compute parses");
        match cli.command {
            Commands::Compute {
                inputs,
                params,
                engine_id,
                signoffs,
                output,
            } => {
                assert_eq!(inputs, PathBuf::from("pop.json"));
                assert_eq!(params, PathBuf::from("plan.json"));
                assert_eq!(engine_id, DEFAULT_ENGINE_ID);
                assert!(signoffs.is_none());
                assert!(output.is_none());
            }
            _ => panic!("expected compute"),
        }
    }

    #[test]
    fn cli_parses_verify_and_explain() {
        let cli = Cli::try_parse_from([
            "sox-testing-spine",
            "verify",
            "--inputs",
            "i.json",
            "--params",
            "p.json",
            "--pack",
            "pack.json",
        ])
        .expect("verify parses");
        assert!(matches!(cli.command, Commands::Verify { .. }));

        let cli = Cli::try_parse_from([
            "sox-testing-spine",
            "explain",
            "--params",
            "p.json",
            "--population-id",
            "CTRL-1",
            "--period",
            "FY2026-Q3",
        ])
        .expect("explain parses");
        assert!(matches!(cli.command, Commands::Explain { .. }));
    }

    #[test]
    fn cli_rejects_unknown_fields_and_partial_pairs() {
        // Unknown subcommand must be refused.
        assert!(Cli::try_parse_from(["sox-testing-spine", "migrate"]).is_err());
        // Half a seed pair is refused.
        assert!(Cli::try_parse_from([
            "sox-testing-spine",
            "explain",
            "--params",
            "p.json",
            "--population-id",
            "CTRL-1"
        ])
        .is_err());
    }
}
