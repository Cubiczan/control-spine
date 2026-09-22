//! Command surface: `compute | verify | explain`. This module is the I/O
//! boundary — it reads files, prints, and maps refusals to exit codes; the
//! engine stays pure.
//!
//! `verify` is fail-closed twice over: the spine pack verification
//! (provenance hashes, seal, signoffs) must pass, and the engine must
//! reproduce the pack's findings bit-for-bit from the presented inputs and
//! config. Any refusal exits nonzero.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use spine::{EvidencePack, Severity};

use crate::config::PayrollConfig;
use crate::engine::{compute, PayrollInput, PayrollOutcome};
use crate::pack::{build_pack, canonical_input_bytes, canonical_param_bytes, findings_match};

/// Integer-only cents formatting for human output — no floats, ever.
pub fn fmt_cents(cents: i128) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let abs = cents.unsigned_abs();
    format!("{sign}${}.${rem:02}", abs / 100, rem = abs % 100)
}

#[derive(Debug, Parser)]
#[command(
    name = "payroll-spine",
    version,
    about = "Payroll control spine: deterministic gross-to-net recomputation with fail-closed evidence packs"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Recompute gross-to-net and emit an evidence pack (JSON). Findings
    /// that require signoff are listed on stderr; the pack carries them.
    Compute {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        config: PathBuf,
        /// Write the pack to this path instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fail-closed verification: provenance hashes, seal, signoffs, and
    /// reproduced findings. Exits nonzero on any refusal.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Human-readable breakdown of the computation for a run.
    Explain {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Run the parsed CLI. Errors are refusal messages, not panics.
pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Compute {
            inputs,
            config,
            out,
        } => {
            let inputs: PayrollInput = read_json(&inputs)?;
            let config: PayrollConfig = read_json(&config)?;
            let outcome = compute(&inputs, &config).map_err(|e| e.to_string())?;
            let pack = build_pack(&inputs, &config, &outcome).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&pack).map_err(|e| e.to_string())?;
            match &out {
                Some(path) => {
                    fs::write(path, format!("{json}\n"))
                        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                    println!("evidence pack written to {}", path.display());
                }
                None => println!("{json}"),
            }
            for finding in outcome
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Breach || f.requires_signoff)
            {
                eprintln!(
                    "SIGNOFF REQUIRED: {} [{:?}] {}: {}",
                    finding.rule_id, finding.severity, finding.subject, finding.message
                );
            }
            Ok(())
        }
        Command::Verify {
            pack,
            inputs,
            config,
        } => {
            let pack: EvidencePack = read_json(&pack)?;
            let inputs: PayrollInput = read_json(&inputs)?;
            let config: PayrollConfig = read_json(&config)?;
            let input_bytes = canonical_input_bytes(&inputs).map_err(|e| e.to_string())?;
            let param_bytes = canonical_param_bytes(&config).map_err(|e| e.to_string())?;
            if let Err(err) = pack.verify(&input_bytes, &param_bytes) {
                return Err(format!(
                    "REFUSED: evidence pack failed fail-closed verification: {err}"
                ));
            }
            // Defense in depth: a deterministic engine must reproduce the
            // pack's findings exactly from these inputs and config.
            let outcome = compute(&inputs, &config).map_err(|e| e.to_string())?;
            if !findings_match(&outcome.findings, &pack.findings) {
                return Err(
                    "REFUSED: recomputed findings do not match the pack — it was not produced by \
                     this engine from these inputs"
                        .to_string(),
                );
            }
            println!("OK: evidence pack verifies (provenance hashes, seal, signoffs, reproduced findings)");
            Ok(())
        }
        Command::Explain { inputs, config } => {
            let inputs: PayrollInput = read_json(&inputs)?;
            let config: PayrollConfig = read_json(&config)?;
            let outcome = compute(&inputs, &config).map_err(|e| e.to_string())?;
            print!("{}", explain_text(&inputs, &config, &outcome));
            Ok(())
        }
    }
}

/// Deterministic human-readable explanation of a computed run. Pure
/// formatting over the outcome — no I/O.
pub fn explain_text(
    inputs: &PayrollInput,
    config: &PayrollConfig,
    outcome: &PayrollOutcome,
) -> String {
    let mut out = String::new();
    out.push_str("payroll-spine gross-to-net explanation\n");
    out.push_str(&format!(
        "period: {:?} {}..{} (calendar days: {})\n",
        inputs.period.calendar,
        inputs.period.start,
        inputs.period.end,
        outcome.summaries.first().map_or(0, |s| s.period_days),
    ));
    out.push_str(&format!(
        "401(k) treatment: {} | register tolerance: {}\n",
        if config.retirement_401k_pre_tax {
            "pre-tax for FIT"
        } else {
            "post-tax"
        },
        fmt_cents(config.register_tolerance_cents),
    ));
    for s in &outcome.summaries {
        out.push_str(&format!(
            "\n{} — employed {} of {} calendar days\n",
            s.employee_id, s.employed_days, s.period_days
        ));
        for (label, value) in [
            ("gross", s.gross_cents),
            ("section 125", -s.section125_cents),
            ("401(k)", -s.retirement_401k_cents),
            ("federal income tax (FIT)", -s.fit_cents),
            ("social security (employee)", -s.ss_cents),
            ("medicare (employee)", -s.medicare_cents),
            (
                "additional medicare (employee)",
                -s.additional_medicare_cents,
            ),
        ] {
            out.push_str(&format!("  {label:<34}{:>14}\n", fmt_cents(value)));
        }
        out.push_str(&format!(
            "  {:<34}{:>14}\n",
            "net pay",
            fmt_cents(s.net_cents)
        ));
        out.push_str(&format!(
            "  employer: FICA match {} | FUTA {} | SUTA {}\n",
            fmt_cents(s.employer_fica_match_cents),
            fmt_cents(s.employer_futa_cents),
            fmt_cents(s.employer_suta_cents),
        ));
        if let Some(variance) = s.register_variance_cents {
            out.push_str(&format!(
                "  register: expected {} | variance {}\n",
                s.register_net_cents
                    .map_or_else(|| "n/a".to_string(), fmt_cents),
                fmt_cents(variance),
            ));
        }
    }
    out.push_str("\nfindings:\n");
    for f in &outcome.findings {
        out.push_str(&format!(
            "  [{:?}] {} ({}): {}\n",
            f.severity, f.rule_id, f.subject, f.message
        ));
    }
    out
}
