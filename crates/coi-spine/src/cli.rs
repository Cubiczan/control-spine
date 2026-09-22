//! CLI surface: `compute | sign | verify | explain`.
//!
//! Filesystem access lives here and only here — the engine and pack modules
//! stay pure. Exit codes: 0 success, 1 refusal or failure, 2 usage error.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use clap::{Parser, Subcommand, ValueEnum};
use spine::{advance_lock, EvidencePack, LockError, LockState, Severity, Signoff, SignoffDecision};

use crate::cert::Certificate;
use crate::config::RequirementsConfig;
use crate::engine::format_cents;
use crate::error::CoiError;
use crate::pack::{build_pack, canonical_json};

#[derive(Parser)]
#[command(
    name = "coi-spine",
    version,
    about = "Vendor certificate-of-insurance coverage-gap control spine"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DecisionArg {
    Approve,
    Reject,
}

impl From<DecisionArg> for SignoffDecision {
    fn from(decision: DecisionArg) -> Self {
        match decision {
            DecisionArg::Approve => SignoffDecision::Approve,
            DecisionArg::Reject => SignoffDecision::Reject,
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Evaluate a typed certificate against the requirements matrix and emit
    /// an evidence pack.
    Compute {
        /// Certificate JSON (typed, manually maintained).
        #[arg(long)]
        inputs: PathBuf,
        /// Requirements matrix JSON (seed data).
        #[arg(long)]
        config: PathBuf,
        /// Clock date, YYYY-MM-DD. The engine never reads a clock.
        #[arg(long)]
        as_of: String,
        /// Write the evidence pack JSON here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Apply a signoff receipt (optional) and advance the pack toward Signed,
    /// which seals it. Signed packs are immutable.
    Sign {
        #[arg(long)]
        pack: PathBuf,
        /// Approving (or rejecting) human; omit to sign a breachless pack as-is.
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        role: Option<String>,
        /// The finding subject (vendor id) this receipt covers.
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, value_enum, default_value = "approve")]
        decision: DecisionArg,
        /// ISO-8601 receipt time, supplied by the caller.
        #[arg(long)]
        at: Option<String>,
        /// Write the updated pack here (default: overwrite --pack in place).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fail-closed verification: recompute the seal and provenance hashes and
    /// re-check signoff coverage against the presented inputs.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Render the rule set in force from a requirements matrix.
    Explain {
        #[arg(long)]
        config: PathBuf,
    },
}

/// Dispatch a parsed CLI; returns the process exit code.
pub fn run(cli: Cli) -> i32 {
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            if matches!(err, CoiError::Usage(_)) {
                2
            } else {
                1
            }
        }
    }
}

fn dispatch(command: Command) -> Result<i32, CoiError> {
    match command {
        Command::Compute {
            inputs,
            config,
            as_of,
            out,
        } => compute(&inputs, &config, &as_of, out),
        Command::Sign {
            pack,
            actor,
            role,
            subject,
            decision,
            at,
            out,
        } => sign(&pack, actor, role, subject, decision, at, out),
        Command::Verify {
            pack,
            inputs,
            config,
        } => verify(&pack, &inputs, &config),
        Command::Explain { config } => explain(&config),
    }
}

fn read_document(path: &Path) -> Result<String, CoiError> {
    fs::read_to_string(path).map_err(|e| CoiError::Io(format!("{}: {e}", path.display())))
}

fn parse_date(raw: &str) -> Result<NaiveDate, CoiError> {
    NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
        .map_err(|e| CoiError::Usage(format!("--as-of '{raw}' is not a YYYY-MM-DD date: {e}")))
}

fn write_pack(path: &Path, pack: &EvidencePack) -> Result<(), CoiError> {
    let json = serde_json::to_string_pretty(pack)
        .map_err(|e| CoiError::Schema(format!("pack serialization: {e}")))?;
    fs::write(path, format!("{json}\n"))
        .map_err(|e| CoiError::Io(format!("{}: {e}", path.display())))
}

fn compute(
    inputs: &Path,
    config: &Path,
    as_of: &str,
    out: Option<PathBuf>,
) -> Result<i32, CoiError> {
    let cert = Certificate::from_json_str(&read_document(inputs)?)?;
    let cfg = RequirementsConfig::from_json_str(&read_document(config)?)?;
    let as_of = parse_date(as_of)?;
    let (pack, evaluation) = build_pack(&cert, &cfg, as_of)?;
    let json = serde_json::to_string_pretty(&pack)
        .map_err(|e| CoiError::Schema(format!("pack serialization: {e}")))?;
    match out {
        Some(path) => fs::write(&path, format!("{json}\n"))
            .map_err(|e| CoiError::Io(format!("{}: {e}", path.display())))?,
        None => println!("{json}"),
    }
    let breaches = evaluation
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .count();
    let warnings = evaluation
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();
    eprintln!(
        "coi-spine: vendor {} — {} breach finding(s), {} warning(s); lockout recommended: {}; pack is unsealed and verifies only after signoff",
        cert.vendor_id,
        breaches,
        warnings,
        if evaluation.lockout_recommended { "yes" } else { "no" }
    );
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn sign(
    pack_path: &Path,
    actor: Option<String>,
    role: Option<String>,
    subject: Option<String>,
    decision: DecisionArg,
    at: Option<String>,
    out: Option<PathBuf>,
) -> Result<i32, CoiError> {
    let mut pack: EvidencePack = serde_json::from_str(&read_document(pack_path)?)
        .map_err(|e| CoiError::Schema(format!("evidence pack: {e}")))?;
    let target = out.as_deref().unwrap_or(pack_path);

    if !pack.body_hash.is_empty() {
        return Err(CoiError::Refused(
            "pack is already sealed — signed packs are immutable; corrections require a new pack from corrected inputs"
                .to_string(),
        ));
    }

    let rejecting = actor.is_some() && matches!(decision, DecisionArg::Reject);
    if let Some(actor) = actor {
        let role =
            role.ok_or_else(|| CoiError::Usage("--role is required with --actor".to_string()))?;
        let subject = subject.ok_or_else(|| {
            CoiError::Usage(
                "--subject is required with --actor: the receipt names the finding subject it covers"
                    .to_string(),
            )
        })?;
        let at = at.ok_or_else(|| {
            CoiError::Usage("--at is required with --actor (ISO-8601, caller-supplied)".to_string())
        })?;
        if actor.trim().is_empty() {
            return Err(CoiError::Usage("--actor must not be blank".to_string()));
        }
        pack.signoffs.push(Signoff {
            actor: actor.trim().to_string(),
            role: role.trim().to_string(),
            subject: subject.trim().to_string(),
            decision: decision.into(),
            at: at.trim().to_string(),
        });
    }

    if rejecting {
        write_pack(target, &pack)?;
        eprintln!(
            "coi-spine: rejection receipt recorded; pack remains unsealed — corrections require a new pack from corrected inputs"
        );
        return Ok(1);
    }

    // Unsealed packs (draft or awaiting signoff) step up to Signed, which
    // seals the body. The first hop cannot fail from Draft.
    let mut state = LockState::Draft;
    state = advance_lock(state, &mut pack).map_err(|e| CoiError::Refused(format!("lock: {e}")))?;
    match advance_lock(state, &mut pack) {
        Ok(LockState::Signed) => {
            write_pack(target, &pack)?;
            eprintln!(
                "coi-spine: pack signed and sealed (body hash {})",
                pack.body_hash
            );
            Ok(0)
        }
        Ok(reached) => {
            // Unreachable under the current three-state lifecycle; visible
            // and persisted in case a future spine version widens it.
            write_pack(target, &pack)?;
            eprintln!("coi-spine: pack advanced to {reached:?} without sealing");
            Ok(0)
        }
        Err(LockError::UnresolvedBreach { rule_id }) => {
            write_pack(target, &pack)?;
            eprintln!(
                "coi-spine: pack NOT signed — unresolved finding on rule {rule_id}; a subject-scoped approval or corrected inputs is required"
            );
            Ok(1)
        }
        Err(other) => Err(CoiError::Refused(format!("lock: {other}"))),
    }
}

fn verify(pack_path: &Path, inputs: &Path, config: &Path) -> Result<i32, CoiError> {
    let pack: EvidencePack = serde_json::from_str(&read_document(pack_path)?)
        .map_err(|e| CoiError::Schema(format!("evidence pack: {e}")))?;
    let cert = Certificate::from_json_str(&read_document(inputs)?)?;
    let cfg = RequirementsConfig::from_json_str(&read_document(config)?)?;
    let inputs_bytes = canonical_json(&cert)?;
    let params_bytes = canonical_json(&cfg)?;
    match pack.verify(&inputs_bytes, &params_bytes) {
        Ok(()) => {
            eprintln!(
                "coi-spine: pack verifies — seal, provenance hashes, and signoff coverage all hold ({} finding(s))",
                pack.findings.len()
            );
            Ok(0)
        }
        Err(err) => {
            eprintln!("coi-spine: REFUSED — {err}");
            Ok(1)
        }
    }
}

fn explain(config: &Path) -> Result<i32, CoiError> {
    let cfg = RequirementsConfig::from_json_str(&read_document(config)?)?;
    println!(
        "coi-spine {} — rule set in force (spine {})",
        env!("CARGO_PKG_VERSION"),
        spine::SPINE_VERSION
    );
    println!(
        "expiry warning window: {} day(s) (inclusive) | carrier rating floor: {} | lockout: advisory recommendation only — a human executes any PO hold",
        cfg.expiry_warning_days,
        cfg.min_carrier_rating.label()
    );
    println!("money is integer cents; limits shown in dollars");
    for (name, category) in &cfg.categories {
        println!(
            "\ncategory {} [{}]",
            name,
            if category.critical {
                "critical"
            } else {
                "standard"
            }
        );
        for (coverage, requirement) in &category.coverages {
            let endorsements = if requirement.endorsements.is_empty() {
                "none".to_string()
            } else {
                requirement
                    .endorsements
                    .iter()
                    .map(|endorsement| endorsement.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!(
                "  {}: per-occurrence ≥ {}, aggregate ≥ {}, endorsements: {}",
                coverage.as_label(),
                format_cents(requirement.per_occurrence_cents),
                format_cents(requirement.aggregate_cents),
                endorsements
            );
        }
    }
    println!("\nmatrix is seed data — verify against executed contracts before relying on it");
    Ok(0)
}
