//! covenant-spine CLI — compute | sign | verify | explain.
//!
//! The library is pure; this binary is the boundary that reads files,
//! canonicalizes JSON, and prints packs. Exit codes: 0 = success, 1 =
//! verification refused, 2 = usage/config error.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Parser, Subcommand, ValueEnum};
use spine::{LockState, Severity, Signoff, SignoffDecision, VerifyError};

use covenant_spine::config::{validate, CovenantConfig, CovenantRule, EquityCure};
use covenant_spine::engine::evaluate;
use covenant_spine::input::Financials;
use covenant_spine::pack::{
    attempt_seal, canonical_json, compute_envelope, PackEnvelope, SealError, SealOutcome,
};

#[derive(Parser)]
#[command(
    name = "covenant-spine",
    version,
    about = "Deterministic debt-covenant control spine (Treasury/Finance)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the engine and emit an evidence pack in awaiting_signoff state.
    Compute {
        /// Covenant configuration JSON (schema-checked).
        #[arg(long)]
        config: PathBuf,
        /// Normalized financials JSON (carries measurement_date — the clock is an input).
        #[arg(long)]
        financials: PathBuf,
        /// Write the pack envelope here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Record a signoff receipt and seal the pack when requirements are met.
    Sign {
        /// Pack envelope path (as emitted by compute).
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: String,
        /// Finding subject the receipt covers.
        #[arg(long)]
        subject: String,
        #[arg(long)]
        decision: DecisionArg,
        /// ISO-8601 timestamp, supplied by the caller — the engine never reads a clock.
        #[arg(long)]
        at: String,
    },
    /// Fail-closed verification: recompute provenance hashes, seal, and signoff coverage.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        financials: PathBuf,
    },
    /// Show the covenant text in force at a date — config only, no financials.
    Explain {
        #[arg(long)]
        config: PathBuf,
        /// Date YYYY-MM-DD.
        #[arg(long)]
        date: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum DecisionArg {
    Approve,
    Reject,
}

impl From<DecisionArg> for SignoffDecision {
    fn from(d: DecisionArg) -> Self {
        match d {
            DecisionArg::Approve => SignoffDecision::Approve,
            DecisionArg::Reject => SignoffDecision::Reject,
        }
    }
}

enum CliError {
    Verify(VerifyError),
    Usage(String),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Verify(err)) => {
            eprintln!("REFUSED: {err}");
            ExitCode::from(1)
        }
        Err(CliError::Usage(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Compute {
            config,
            financials,
            out,
        } => compute(&config, &financials, out),
        Command::Sign {
            pack,
            actor,
            role,
            subject,
            decision,
            at,
        } => sign(&pack, actor, role, subject, decision, at),
        Command::Verify {
            pack,
            config,
            financials,
        } => verify(&pack, &config, &financials),
        Command::Explain { config, date } => explain(&config, &date),
    }
}

fn read_canonical(path: &Path, label: &str) -> Result<Vec<u8>, CliError> {
    let raw = fs::read(path)
        .map_err(|e| CliError::Usage(format!("cannot read {label} {}: {e}", path.display())))?;
    canonical_json(&raw)
        .map_err(|e| CliError::Usage(format!("{label} {} is not valid JSON: {e}", path.display())))
}

fn usage_json<'a>(
    label: &'static str,
    path: &'a Path,
) -> impl Fn(serde_json::Error) -> CliError + 'a {
    move |e| {
        CliError::Usage(format!(
            "{label} {} does not match the schema: {e}",
            path.display()
        ))
    }
}

fn compute(
    config_path: &Path,
    financials_path: &Path,
    out: Option<PathBuf>,
) -> Result<(), CliError> {
    let params = read_canonical(config_path, "config")?;
    let inputs = read_canonical(financials_path, "financials")?;
    let config: CovenantConfig =
        serde_json::from_slice(&params).map_err(usage_json("config", config_path))?;
    validate(&config).map_err(|e| CliError::Usage(format!("config invalid: {e}")))?;
    let financials: Financials =
        serde_json::from_slice(&inputs).map_err(usage_json("financials", financials_path))?;

    let evaluation = evaluate(&config, &financials);
    let envelope = compute_envelope(&params, &inputs, &evaluation);
    let rendered = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| CliError::Usage(format!("pack serialization failed: {e}")))?;
    match out {
        Some(path) => fs::write(&path, rendered)
            .map_err(|e| CliError::Usage(format!("cannot write {}: {e}", path.display())))?,
        None => std::io::stdout()
            .write_all(&rendered)
            .map_err(|e| CliError::Usage(format!("cannot write to stdout: {e}")))?,
    }
    let breaches = evaluation
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .count();
    eprintln!(
        "covenant-spine: {} findings, {breaches} breach; pack state awaiting_signoff",
        evaluation.findings.len()
    );
    Ok(())
}

fn sign(
    pack_path: &Path,
    actor: String,
    role: String,
    subject: String,
    decision: DecisionArg,
    at: String,
) -> Result<(), CliError> {
    if actor.trim().is_empty()
        || role.trim().is_empty()
        || subject.trim().is_empty()
        || at.trim().is_empty()
    {
        return Err(CliError::Usage(
            "actor, role, subject, and at must be non-empty".to_string(),
        ));
    }
    let raw = fs::read(pack_path)
        .map_err(|e| CliError::Usage(format!("cannot read pack {}: {e}", pack_path.display())))?;
    let mut envelope: PackEnvelope =
        serde_json::from_slice(&raw).map_err(usage_json("pack", pack_path))?;
    if envelope.lock_state == LockState::Signed {
        return Err(CliError::Usage(
            "pack is already signed; signed packs are immutable — compute a fresh pack instead"
                .to_string(),
        ));
    }
    envelope.pack.signoffs.push(Signoff {
        actor,
        role,
        subject,
        decision: SignoffDecision::from(decision),
        at,
    });
    let outcome = match attempt_seal(&mut envelope) {
        Ok(outcome) => outcome,
        Err(SealError::AlreadySigned) => {
            return Err(CliError::Usage("pack is already signed".to_string()))
        }
        Err(SealError::Lock(e)) => return Err(CliError::Usage(format!("lock error: {e}"))),
    };
    let rendered = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| CliError::Usage(format!("pack serialization failed: {e}")))?;
    fs::write(pack_path, rendered)
        .map_err(|e| CliError::Usage(format!("cannot write {}: {e}", pack_path.display())))?;
    match outcome {
        SealOutcome::Signed => println!(
            "sealed: pack is signed; body hash {}",
            envelope.pack.body_hash
        ),
        SealOutcome::Awaiting(reason) => println!("awaiting signoff: {reason}"),
    }
    Ok(())
}

fn verify(pack_path: &Path, config_path: &Path, financials_path: &Path) -> Result<(), CliError> {
    let raw = fs::read(pack_path)
        .map_err(|e| CliError::Usage(format!("cannot read pack {}: {e}", pack_path.display())))?;
    let envelope: PackEnvelope =
        serde_json::from_slice(&raw).map_err(usage_json("pack", pack_path))?;
    let params = read_canonical(config_path, "config")?;
    let inputs = read_canonical(financials_path, "financials")?;
    envelope
        .pack
        .verify(&inputs, &params)
        .map_err(CliError::Verify)?;
    println!(
        "OK: pack verifies; {} findings, state {}",
        envelope.pack.findings.len(),
        lock_label(envelope.lock_state)
    );
    Ok(())
}

fn lock_label(state: LockState) -> &'static str {
    match state {
        LockState::Draft => "draft",
        LockState::AwaitingSignoff => "awaiting_signoff",
        LockState::Signed => "signed",
    }
}

fn explain(config_path: &Path, date_raw: &str) -> Result<(), CliError> {
    let params = read_canonical(config_path, "config")?;
    let config: CovenantConfig =
        serde_json::from_slice(&params).map_err(usage_json("config", config_path))?;
    validate(&config).map_err(|e| CliError::Usage(format!("config invalid: {e}")))?;
    let date = NaiveDate::parse_from_str(date_raw, "%Y-%m-%d")
        .map_err(|e| CliError::Usage(format!("--date must be YYYY-MM-DD: {e}")))?;

    println!("covenants in force at {date}:");
    let mut ids: Vec<&str> = Vec::new();
    for rule in &config.covenants {
        if !ids.contains(&rule.id.as_str()) {
            ids.push(rule.id.as_str());
        }
    }
    for id in ids {
        let in_force: Vec<&CovenantRule> = config
            .covenants
            .iter()
            .filter(|r| r.id == id && r.is_in_force(date))
            .collect();
        match in_force.as_slice() {
            [] => println!("  {id}: no version in force"),
            [one] => println!(
                "  {id}: {} {} {}x, basis {}, window [{}, {})",
                one.kind.label(),
                if one.kind.is_maximum() { "max" } else { "min" },
                one.threshold,
                one.basis.label(),
                one.effective_from,
                one.effective_to
                    .map_or_else(|| "open".to_string(), |d| d.to_string())
            ),
            many => println!(
                "  {id}: AMBIGUOUS — {} versions in force; compute refuses this config",
                many.len()
            ),
        }
    }

    let cures: Vec<&EquityCure> = config
        .equity_cures
        .iter()
        .filter(|c| c.is_in_force(date))
        .collect();
    if cures.is_empty() {
        println!("equity cures in force: (none)");
    } else {
        println!("equity cures in force:");
        for cure in cures {
            println!(
                "  {}: add_to_ebitda {} cents, reduce_debt {} cents",
                cure.description, cure.add_to_ebitda_cents, cure.reduce_debt_cents
            );
        }
    }
    println!(
        "projection: horizon {} quarters, min history {} points (deterministic linear trend over computable points)",
        config.projection.horizon_quarters, config.projection.min_history_points
    );
    println!("formulas:");
    println!("  max_leverage              = total debt / EBITDA (<= threshold)");
    println!("  min_interest_coverage     = EBITDA / interest expense (>= threshold)");
    println!("  min_current_ratio         = current assets / current liabilities (>= threshold)");
    println!(
        "  min_fixed_charge_coverage = (EBITDA + rent) / (interest + rent + current maturities) (>= threshold)"
    );
    Ok(())
}
