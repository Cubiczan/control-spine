//! Clap CLI: `compute | verify | explain`.
//!
//! This is the crate's only I/O boundary — argument parsing, file reads,
//! and stdout writes live here, never in the engine. Time enters as the
//! caller-supplied `--as-of` date; the binary never reads a clock either.
//!
//! Exit codes: `0` success (for `verify`: the pack verified), `1` verify
//! refusal (fail-closed), `2` usage/IO/parse error.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use spine::{EvidencePack, Severity, Signoff, SPINE_VERSION};

use crate::{
    build_pack, compute, fmt_cents, parse_config, parse_inputs, ComputeOutput, MatchTier,
    UnmatchedItem, ENGINE_ID, TOOL_VERSION,
};

const EXIT_OK: u8 = 0;
const EXIT_VERIFY_REFUSED: u8 = 1;
const EXIT_ERROR: u8 = 2;

/// Treasury bank reconciliation control spine.
#[derive(Debug, Parser)]
#[command(
    name = "bankrec-spine",
    version,
    about = "Tiered statement-to-ledger matching with fail-closed evidence packs.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Match statement lines to ledger entries and emit a sealed evidence pack.
    Compute {
        /// Path to the inputs JSON (statement lines + ledger entries).
        #[arg(long)]
        inputs: PathBuf,
        /// Path to the config JSON (rule table; schema-checked).
        #[arg(long)]
        config: PathBuf,
        /// Reporting date (YYYY-MM-DD), supplied by the caller — the engine never reads a clock.
        #[arg(long)]
        as_of: String,
        /// Engine identity stamped into the pack (separation of duties: this actor cannot sign off).
        #[arg(long, default_value = ENGINE_ID)]
        engine_id: String,
        /// Optional path to a JSON array of signoff receipts to embed.
        #[arg(long)]
        signoffs: Option<PathBuf>,
        /// Output path (default: stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Re-verify a pack against the original inputs and config bytes.
    /// Exit 0 = verified; exit 1 = refused (fail-closed).
    Verify {
        /// Path to the evidence pack JSON.
        #[arg(long)]
        pack: PathBuf,
        /// Path to the original inputs JSON.
        #[arg(long)]
        inputs: PathBuf,
        /// Path to the original config JSON.
        #[arg(long)]
        config: PathBuf,
    },
    /// Render a compute output as human-readable text.
    Explain {
        /// Path to a compute output JSON.
        #[arg(long)]
        report: PathBuf,
    },
}

pub fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Compute {
            inputs,
            config,
            as_of,
            engine_id,
            signoffs,
            output,
        } => run_compute(
            &inputs,
            &config,
            &as_of,
            &engine_id,
            signoffs.as_deref(),
            output.as_deref(),
        ),
        Command::Verify {
            pack,
            inputs,
            config,
        } => run_verify(&pack, &inputs, &config),
        Command::Explain { report } => run_explain(&report),
    }
}

fn fail(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(EXIT_ERROR)
}

/// Accept either a full compute output (the envelope `compute` writes) or a
/// bare evidence pack. Fail-closed: anything else is a malformed pack.
fn extract_pack(bytes: &[u8]) -> Result<EvidencePack, serde_json::Error> {
    if let Ok(output) = serde_json::from_slice::<ComputeOutput>(bytes) {
        return Ok(output.evidence_pack);
    }
    serde_json::from_slice::<EvidencePack>(bytes)
}

fn read_or_fail(path: &Path, what: &str) -> Result<Vec<u8>, ExitCode> {
    fs::read(path).map_err(|e| fail(format!("cannot read {what} {}: {e}", path.display())))
}

fn run_compute(
    inputs_path: &Path,
    config_path: &Path,
    as_of: &str,
    engine_id: &str,
    signoffs_path: Option<&Path>,
    output_path: Option<&Path>,
) -> ExitCode {
    let inputs_bytes = match read_or_fail(inputs_path, "inputs") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let params_bytes = match read_or_fail(config_path, "config") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let as_of_date = match NaiveDate::parse_from_str(as_of, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => return fail(format!("--as-of must be YYYY-MM-DD, got {as_of:?}")),
    };
    let signoffs = match signoffs_path {
        Some(p) => {
            let bytes = match read_or_fail(p, "signoffs") {
                Ok(b) => b,
                Err(code) => return code,
            };
            match serde_json::from_slice::<Vec<Signoff>>(&bytes) {
                Ok(list) => list,
                Err(e) => return fail(format!("malformed signoffs JSON: {e}")),
            }
        }
        None => Vec::new(),
    };

    let validated = match parse_inputs(&inputs_bytes) {
        Ok(v) => v,
        Err(e) => return fail(e.to_string()),
    };
    let config = match parse_config(&params_bytes) {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };

    let report = compute(&validated, &config, as_of_date);
    let pack = build_pack(
        &report,
        engine_id,
        TOOL_VERSION,
        &inputs_bytes,
        &params_bytes,
        signoffs,
    );
    let output = ComputeOutput {
        engine_id: engine_id.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        as_of: as_of_date.to_string(),
        report,
        evidence_pack: pack,
    };

    let bytes = match serde_json::to_vec_pretty(&output) {
        Ok(b) => b,
        Err(e) => return fail(format!("cannot serialize output: {e}")),
    };
    match output_path {
        Some(p) => {
            if let Err(e) = fs::write(p, &bytes) {
                return fail(format!("cannot write {}: {e}", p.display()));
            }
        }
        None => {
            let mut stdout = std::io::stdout();
            if stdout.write_all(&bytes).is_err() || stdout.write_all(b"\n").is_err() {
                return fail("cannot write to stdout".to_string());
            }
        }
    }
    ExitCode::from(EXIT_OK)
}

fn run_verify(pack_path: &Path, inputs_path: &Path, config_path: &Path) -> ExitCode {
    let pack_bytes = match read_or_fail(pack_path, "pack") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let pack: EvidencePack = match extract_pack(&pack_bytes) {
        Ok(p) => p,
        Err(e) => return fail(format!("malformed pack JSON: {e}")),
    };
    let inputs_bytes = match read_or_fail(inputs_path, "inputs") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let params_bytes = match read_or_fail(config_path, "config") {
        Ok(b) => b,
        Err(code) => return code,
    };
    match pack.verify(&inputs_bytes, &params_bytes) {
        Ok(()) => {
            println!(
                "verified: pack intact, provenance hashes match, all required signoffs present"
            );
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("REFUSED: {e}");
            ExitCode::from(EXIT_VERIFY_REFUSED)
        }
    }
}

fn run_explain(report_path: &Path) -> ExitCode {
    let bytes = match read_or_fail(report_path, "report") {
        Ok(b) => b,
        Err(code) => return code,
    };
    let out: ComputeOutput = match serde_json::from_slice(&bytes) {
        Ok(o) => o,
        Err(e) => return fail(format!("malformed report JSON: {e}")),
    };
    let r = &out.report;

    println!("bankrec-spine — bank reconciliation report");
    println!(
        "  as_of {} | engine {} v{} | spine {SPINE_VERSION}",
        out.as_of, out.engine_id, out.tool_version
    );

    println!();
    println!("Matches ({}):", r.matches.len());
    for m in &r.matches {
        let tier = match m.tier {
            MatchTier::Exact => "exact        ",
            MatchTier::Tolerance => "tolerance    ",
            MatchTier::ManyToOne => "many-to-one  ",
        };
        println!(
            "  [{}] {} ← {}  statement {} matched {} variance {}",
            tier,
            m.statement_id,
            m.ledger_ids.join(", "),
            fmt_cents(m.statement_amount_cents),
            fmt_cents(m.matched_amount_cents),
            fmt_cents(m.variance_cents)
        );
    }

    print_unmatched("Unmatched statement lines", &r.unmatched_statement);
    print_unmatched("Unmatched ledger entries", &r.unmatched_ledger);

    println!();
    println!("Findings ({}):", r.findings.len());
    for f in &r.findings {
        let severity = match f.severity {
            Severity::Info => "info   ",
            Severity::Warn => "warn   ",
            Severity::Breach => "BREACH ",
        };
        let signoff_note = if f.requires_signoff {
            " — signoff required to resolve"
        } else {
            ""
        };
        println!(
            "  [{}] {} {}: {}{signoff_note}",
            severity, f.rule_id, f.subject, f.message
        );
    }

    println!();
    println!("Adjustment proposals ({}):", r.adjustment_proposals.len());
    for p in &r.adjustment_proposals {
        println!("  {:?} {} : {}", p.kind, p.subject, p.detail);
    }

    ExitCode::from(EXIT_OK)
}

fn print_unmatched(label: &str, items: &[UnmatchedItem]) {
    println!();
    println!("{label} ({}):", items.len());
    for u in items {
        let flag = if u.stale {
            " STALE — breach finding; signoff required to resolve"
        } else {
            ""
        };
        println!("  {}  date={} age={}d{flag}", u.id, u.date, u.age_days);
    }
}
