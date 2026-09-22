//! Human-readable derivations for explain output.
//!
//! Pure formatting over already-computed evaluations — no recomputation, no
//! divergence from what `compute` put in the evidence pack.

use chrono::{DateTime, Utc};

use crate::config::CapaConfig;
use crate::engine::{severity_label, CapaEvaluation};
use crate::model::{CapaRecord, Status};

/// Render the deterministic derivation for one CAPA.
pub fn explain_one(
    record: &CapaRecord,
    evaluation: &CapaEvaluation,
    config: &CapaConfig,
    as_of: DateTime<Utc>,
) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!(
        "CAPA {id} — classified {severity} (severity matrix: {category} × {detectability})",
        id = record.id,
        severity = severity_label(evaluation.severity),
        category = record.category,
        detectability = record.detectability,
    ));
    lines.push(format!("description: {}", record.description));
    lines.push(format!("opened: {}", record.opened_at));
    lines.push(format!("as of: {as_of}"));

    match (evaluation.containment_required, evaluation.containment_due) {
        (true, Some(due)) => {
            let recorded = match evaluation.containment_recorded_at {
                Some(at) => format!("recorded {at}"),
                None => "not recorded".to_string(),
            };
            lines.push(format!(
                "containment: required within {hours}h of opening — due {due}; {recorded}",
                hours = evaluation.containment_hours.unwrap_or_default(),
            ));
        }
        _ => lines.push("containment: not required at this severity".to_string()),
    }

    let effective_status = if evaluation.treated_as_open {
        if record.status == Status::Closed {
            "closure REFUSED — treated as open (fail-closed)"
        } else {
            "open"
        }
    } else {
        "closed"
    };
    lines.push(format!("effective status: {effective_status}"));

    match record.status {
        Status::Closed => {
            let root_cause_recorded = record
                .root_cause
                .as_deref()
                .is_some_and(|cause| !cause.trim().is_empty());
            let effectiveness_completed = record
                .effectiveness_check
                .as_ref()
                .is_some_and(|check| check.completed);
            let due_line = match evaluation.effectiveness_due {
                Some(due) => format!(
                    "; effectiveness due {due} (closure + {} days)",
                    config.effectiveness_window_days
                ),
                None => String::new(),
            };
            lines.push(format!(
                "closure checklist: root cause {} — effectiveness {}{due_line}",
                if root_cause_recorded {
                    "recorded"
                } else {
                    "MISSING"
                },
                if effectiveness_completed {
                    "completed"
                } else {
                    "incomplete"
                },
            ));
        }
        Status::Open => lines.push("closure checklist: not yet requested".to_string()),
    }

    if evaluation.treated_as_open {
        lines.push(format!(
            "aging: open {} day(s) as of the clock — warn after {} day(s), breach after {} day(s)",
            (as_of - record.opened_at).num_days(),
            config.aging.warn_after_days,
            config.aging.breach_after_days,
        ));
    }

    match &evaluation.parent_id {
        Some(parent) => {
            let state = if evaluation.parent_present {
                "present"
            } else {
                "MISSING — broken linkage"
            };
            lines.push(format!("reopen linkage: new cycle of {parent} ({state})"));
        }
        None => lines.push("reopen linkage: none".to_string()),
    }

    match &evaluation.duplicate_of {
        Some(other) => lines.push(format!(
            "duplicate: description matches CAPA {other} after normalization"
        )),
        None => lines.push("duplicate: none detected".to_string()),
    }

    if evaluation.findings.is_empty() {
        lines.push("findings: none".to_string());
    } else {
        lines.push(format!("findings ({}):", evaluation.findings.len()));
        for finding in &evaluation.findings {
            lines.push(format!(
                "  [{}] {} — {}",
                severity_label(finding.severity).to_lowercase(),
                finding.rule_id,
                finding.message,
            ));
        }
    }

    lines.join("\n")
}
