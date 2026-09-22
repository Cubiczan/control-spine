//! dqf-spine CLI — `compute | verify | explain`.
//!
//! All domain logic lives in the library; this binary is the edge that reads
//! files and arguments. Exit codes: 0 = ok, 1 = verification refused
//! (fail-closed), 2 = usage or input error.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use dqf_spine::spine::{EvidencePack, Severity, Signoff, SignoffDecision};

#[derive(Parser)]
#[command(
    name = "dqf-spine",
    version,
    about = "Fleet/Logistics control spine: deterministic DQF checklist expiry and out-of-service risk flags"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute findings and emit a sealed evidence pack.
    Compute {
        /// Driver records JSON file.
        #[arg(long, value_name = "FILE")]
        drivers: PathBuf,
        /// Config tables JSON file (seed-data schema).
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Campaign date the engine evaluates against (YYYY-MM-DD).
        #[arg(long, value_name = "YYYY-MM-DD")]
        as_of: String,
        /// Write the pack to this file instead of stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Fail-closed verification: refuse unless provenance hashes, the seal,
    /// and every required signoff recompute.
    Verify {
        /// Evidence pack JSON file.
        #[arg(long, value_name = "FILE")]
        pack: PathBuf,
        /// The original driver records file the pack was computed from.
        #[arg(long, value_name = "FILE")]
        drivers: PathBuf,
        /// The original config file the pack was computed from.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Human-readable rendering of a pack's findings and signoff coverage.
    Explain {
        /// Evidence pack JSON file.
        #[arg(long, value_name = "FILE")]
        pack: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Compute {
            drivers,
            config,
            as_of,
            output,
        } => run_compute(&drivers, &config, &as_of, output.as_deref()),
        Commands::Verify {
            pack,
            drivers,
            config,
        } => run_verify(&pack, &drivers, &config),
        Commands::Explain { pack } => run_explain(&pack),
    }
}

fn run_compute(
    drivers_path: &Path,
    config_path: &Path,
    as_of_arg: &str,
    output: Option<&Path>,
) -> ExitCode {
    let drivers_bytes = match std::fs::read(drivers_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read drivers file {drivers_path:?}: {e}");
            return ExitCode::from(2);
        }
    };
    let config_bytes = match std::fs::read(config_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read config file {config_path:?}: {e}");
            return ExitCode::from(2);
        }
    };
    let as_of = match NaiveDate::parse_from_str(as_of_arg, "%Y-%m-%d") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("invalid --as-of {as_of_arg:?} (expected YYYY-MM-DD): {e}");
            return ExitCode::from(2);
        }
    };
    let pack = match dqf_spine::build_pack(&drivers_bytes, &config_bytes, as_of) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(2);
        }
    };
    let json = serde_json::to_string_pretty(&pack).expect("EvidencePack serialization cannot fail");
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("cannot write pack to {path:?}: {e}");
                return ExitCode::FAILURE;
            }
        }
        None => println!("{json}"),
    }
    eprintln!(
        "ok: {} findings; pack sealed (inputs {})",
        pack.findings.len(),
        pack.inputs_hash
    );
    ExitCode::SUCCESS
}

fn run_verify(pack_path: &Path, drivers_path: &Path, config_path: &Path) -> ExitCode {
    let pack = match read_pack(pack_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let drivers_bytes = match std::fs::read(drivers_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read drivers file {drivers_path:?}: {e}");
            return ExitCode::from(2);
        }
    };
    let config_bytes = match std::fs::read(config_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read config file {config_path:?}: {e}");
            return ExitCode::from(2);
        }
    };
    match pack.verify(&drivers_bytes, &config_bytes) {
        Ok(()) => {
            println!("OK: pack verifies against these inputs and params");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REFUSED: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_explain(pack_path: &Path) -> ExitCode {
    let pack = match read_pack(pack_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    println!("dqf-spine evidence pack");
    println!(
        "  engine_id: {}  tool_version: {}  spine_version: {}",
        pack.engine_id, pack.tool_version, pack.spine_version
    );
    println!("  inputs_hash: {}", pack.inputs_hash);
    println!("  params_hash: {}", pack.params_hash);
    println!(
        "  body_hash: {}",
        if pack.body_hash.is_empty() {
            "(unsealed)"
        } else {
            pack.body_hash.as_str()
        }
    );
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
        "  findings: {} (breach {breaches}, warn {warns}, info {infos}); signoffs: {}",
        pack.findings.len(),
        pack.signoffs.len()
    );
    for finding in &pack.findings {
        println!(
            "  [{}] {} {} :: {}",
            severity_tag(finding.severity),
            finding.subject,
            finding.rule_id,
            finding.message
        );
        if !finding.requires_signoff {
            continue;
        }
        let approvals: Vec<&Signoff> = pack
            .signoffs
            .iter()
            .filter(|s| s.subject == finding.subject && s.decision == SignoffDecision::Approve)
            .collect();
        if approvals.is_empty() {
            println!("      requires signoff: UNRESOLVED");
        } else {
            for a in approvals {
                println!("      approved by {} ({}) at {}", a.actor, a.role, a.at);
            }
        }
    }
    ExitCode::SUCCESS
}

fn severity_tag(severity: Severity) -> &'static str {
    match severity {
        Severity::Breach => "BREACH",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

fn read_pack(path: &Path) -> Result<EvidencePack, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("{path:?} is not a valid evidence pack: {e}"))
}
