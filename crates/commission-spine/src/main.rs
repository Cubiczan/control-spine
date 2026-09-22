//! commission-spine CLI: `compute | verify | explain | sign | seal`.
//!
//! The binary is a thin, honest wrapper over the library: it reads files,
//! reports errors on stderr with a non-zero exit, and never fixes up or
//! swallows a refusal. Timestamps for signoffs are caller-supplied — the
//! CLI never reads a clock either.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use commission_spine::config::{BandMode, PlanConfig};
use commission_spine::engine;
use commission_spine::evidence::{self, EvidenceDocument};
use commission_spine::input::TransactionsFile;

#[derive(Parser)]
#[command(
    name = "commission-spine",
    about = "Deterministic sales commission control spine (evidence packs fail closed)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute commissions and emit an evidence document (JSON).
    Compute {
        /// Plan config JSON (schema-checked, validated).
        #[arg(long)]
        plan: PathBuf,
        /// Transactions JSON (validated).
        #[arg(long)]
        transactions: PathBuf,
        /// Producing-engine identity; signoffs from this actor are void.
        #[arg(long, default_value = "commission-spine")]
        engine_id: String,
        /// Write the evidence document here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an evidence document: deep recompute + spine gate. Exit 0
    /// only when the pack proves itself.
    Verify {
        /// Evidence document to verify.
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        transactions: PathBuf,
    },
    /// Explain the deterministic calculation in human-readable form.
    Explain {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        transactions: PathBuf,
        /// Restrict the explanation to one rep id.
        #[arg(long)]
        rep: Option<String>,
    },
    /// Append a human signoff receipt to a draft/awaiting evidence document.
    Sign {
        /// Evidence document; modified in place.
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: String,
        /// Finding subject the receipt covers (must name a finding).
        #[arg(long)]
        subject: String,
        /// approve | reject
        #[arg(long, default_value = "approve")]
        decision: String,
        /// ISO-8601 receipt time, supplied by the caller.
        #[arg(long)]
        at: String,
    },
    /// Advance the lock: draft → awaiting_signoff → signed (seals at signed).
    Seal {
        /// Evidence document; modified in place.
        #[arg(long)]
        pack: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Compute {
            plan,
            transactions,
            engine_id,
            out,
        } => {
            let plan_bytes = read_or_exit(&plan);
            let txn_bytes = read_or_exit(&transactions);
            match evidence::compute_document(&plan_bytes, &txn_bytes, &engine_id) {
                Ok(doc) => write_or_exit(&out, &doc),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        Commands::Verify {
            pack,
            plan,
            transactions,
        } => {
            let doc = read_or_exit(&pack);
            let doc: EvidenceDocument = parse_or_exit(&doc, "--pack");
            let plan_bytes = read_or_exit(&plan);
            let txn_bytes = read_or_exit(&transactions);
            match evidence::verify_document(&doc, &plan_bytes, &txn_bytes) {
                Ok(()) => {
                    println!(
                        "verified: pack proves itself under spine {} (lock: {})",
                        doc.pack.spine_version,
                        state_label(doc.lock_state)
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("verify REFUSED: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Explain {
            plan,
            transactions,
            rep,
        } => {
            let plan_bytes = read_or_exit(&plan);
            let txn_bytes = read_or_exit(&transactions);
            if let Err(e) = explain(&plan_bytes, &txn_bytes, rep.as_deref()) {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Commands::Sign {
            pack,
            actor,
            role,
            subject,
            decision,
            at,
        } => {
            let bytes = read_or_exit(&pack);
            let mut doc: EvidenceDocument = parse_or_exit(&bytes, "--pack");
            let decision = match decision.to_ascii_lowercase().as_str() {
                "approve" => spine::SignoffDecision::Approve,
                "reject" => spine::SignoffDecision::Reject,
                other => {
                    eprintln!("error: --decision must be 'approve' or 'reject', got {other:?}");
                    return ExitCode::FAILURE;
                }
            };
            let signoff = spine::Signoff {
                actor,
                role,
                subject,
                decision,
                at,
            };
            match evidence::append_signoff(&mut doc, signoff) {
                Ok(()) => {
                    write_or_exit(&Some(pack), &doc);
                    println!("signoff recorded; lock: {}", state_label(doc.lock_state));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sign REFUSED: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Seal { pack } => {
            let bytes = read_or_exit(&pack);
            let mut doc: EvidenceDocument = parse_or_exit(&bytes, "--pack");
            match evidence::advance_lock(&mut doc) {
                Ok(state) => {
                    write_or_exit(&Some(pack), &doc);
                    println!("lock advanced to {}", state_label(state));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("seal REFUSED: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn state_label(state: spine::LockState) -> &'static str {
    match state {
        spine::LockState::Draft => "draft",
        spine::LockState::AwaitingSignoff => "awaiting_signoff",
        spine::LockState::Signed => "signed",
    }
}

fn read_or_exit(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {e}", path.display());
        std::process::exit(1);
    })
}

fn parse_or_exit<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|e| {
        eprintln!("error: {what} is not valid JSON for this document type: {e}");
        std::process::exit(1);
    })
}

fn write_or_exit(out: &Option<PathBuf>, doc: &EvidenceDocument) {
    let rendered = serde_json::to_vec_pretty(doc).expect("evidence document serializes");
    match out {
        Some(path) => std::fs::write(path, &rendered).unwrap_or_else(|e| {
            eprintln!("error: cannot write {}: {e}", path.display());
            std::process::exit(1);
        }),
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(&rendered)
                .and_then(|_| std::io::stdout().write_all(b"\n"))
                .expect("stdout write");
        }
    }
}

/// Deterministic human-readable rendering of the run — integer-only
/// formatting, no recomputation tricks. Findings and credit lines are
/// already in canonical order.
fn explain(plan_bytes: &[u8], txn_bytes: &[u8], rep_filter: Option<&str>) -> Result<(), String> {
    let plan: PlanConfig =
        serde_json::from_slice(plan_bytes).map_err(|e| format!("plan config JSON: {e}"))?;
    plan.validate()
        .map_err(|e| format!("plan config invalid: {e}"))?;
    let txns: TransactionsFile =
        serde_json::from_slice(txn_bytes).map_err(|e| format!("transactions JSON: {e}"))?;
    txns.validate()
        .map_err(|e| format!("transactions invalid: {e}"))?;
    let out = engine::run(&plan, &txns).map_err(|e| format!("engine: {e}"))?;

    println!("commission-spine — plan {}", plan.plan_id);
    for v in &plan.versions {
        println!(
            "  plan v{} effective {}..{} — quota {} c, {:?} bands, windfall cap {}",
            v.version,
            v.effective_from,
            v.effective_to.map_or("open".to_string(), |d| d.to_string()),
            v.quota_cents,
            v.band_mode,
            v.windfall_cap_ppm
                .map_or("none".to_string(), |c| format!("{c} ppm")),
        );
    }
    for s in &out.rep_summaries {
        if rep_filter.is_some_and(|f| s.rep_id != f) {
            continue;
        }
        println!();
        println!(
            "rep {} (plan v{}): gross {} c, returned {} c, net {} c",
            s.rep_id,
            s.plan_version,
            s.gross_credited_cents,
            s.returned_cents,
            s.net_credited_cents
        );
        let quota = plan
            .versions
            .iter()
            .find(|v| v.version == s.plan_version)
            .map(|v| v.quota_cents)
            .unwrap_or_default();
        println!(
            "  attainment {} of quota {} c{}{}",
            fmt_ppm(s.attainment_ppm),
            quota,
            s.windfall_cap_ppm
                .map_or(String::new(), |c| format!(" (windfall cap {c} ppm)")),
            if s.windfall_cap_applied {
                " — windfall cap applied to the payout basis"
            } else {
                ""
            }
        );
        println!(
            "  commission: net {} c (gross {} c, clawback {} c) — {:?} mode",
            s.net_commission_cents,
            s.gross_commission_cents,
            s.clawback_commission_cents,
            s.band_mode
        );
        if s.band_mode == BandMode::Marginal {
            for b in &s.net_band_slices {
                println!(
                    "    band {} ≤{}: {} c × {} bps → {} c",
                    b.band_index,
                    b.up_to_ppm
                        .map_or("open".to_string(), |u| format!("{u} ppm")),
                    b.slice_cents,
                    b.rate_bps,
                    b.commission_cents
                );
            }
        }
    }
    println!();
    println!("credit lines:");
    for l in &out.credit_lines {
        let link = l
            .links_original
            .as_ref()
            .map_or(String::new(), |o| format!(" [clawback of {o}]"));
        println!(
            "  {} → {} ({}) {:+} c{}",
            l.transaction_id, l.rep_id, l.role, l.credited_cents, link
        );
    }
    println!();
    println!("findings:");
    for f in &out.findings {
        println!(
            "  [{:?}] {} on {} — {}{}",
            f.severity,
            f.rule_id,
            f.subject,
            f.message,
            if f.requires_signoff {
                " (signoff required)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn fmt_ppm(ppm: i128) -> String {
    let sign = if ppm < 0 { "-" } else { "" };
    let abs = ppm.abs();
    format!("{sign}{}.{:04}%", abs / 10_000, abs % 10_000)
}
