//! The pure CAPA rule engine.
//!
//! Purity contract: explicit inputs, caller-supplied clock, no filesystem,
//! no network, no RNG. Identical records, config, and clock produce
//! identical findings in identical order.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use spine::{sha256_hex, Finding, Severity};

use crate::config::{CapaConfig, ConfigError};
use crate::model::{CapaRecord, Status};

pub const RULE_CONTAINMENT_OVERDUE: &str = "CONTAINMENT_OVERDUE";
pub const RULE_CONTAINMENT_LATE: &str = "CONTAINMENT_LATE";
pub const RULE_CLOSURE_BLOCKED: &str = "CLOSURE_BLOCKED";
pub const RULE_EFFECTIVENESS_OVERDUE: &str = "EFFECTIVENESS_OVERDUE";
pub const RULE_AGING_WARN: &str = "AGING_WARN";
pub const RULE_AGING_BREACH: &str = "AGING_BREACH";
pub const RULE_DUPLICATE_DESCRIPTION: &str = "DUPLICATE_DESCRIPTION";
pub const RULE_BROKEN_REOPEN_LINK: &str = "BROKEN_REOPEN_LINK";

/// Human label for a severity, used in messages and explain output.
pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Breach => "BREACH",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

/// Normalized description for duplicate detection: case- and
/// whitespace-insensitive. Two records whose normalizations agree describe
/// (probably) the same nonconformance.
pub fn normalize_description(description: &str) -> String {
    description
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// SHA-256 of the normalized description.
pub fn description_hash(description: &str) -> String {
    sha256_hex(normalize_description(description).as_bytes())
}

/// Deterministic evaluation of one CAPA as of the clock.
#[derive(Debug, Clone)]
pub struct CapaEvaluation {
    pub capa_id: String,
    /// Severity assigned by the configured matrix.
    pub severity: Severity,
    pub containment_required: bool,
    /// Configured containment window in hours, when required.
    pub containment_hours: Option<u64>,
    /// `opened_at + containment_hours` when containment is required.
    pub containment_due: Option<DateTime<Utc>>,
    pub containment_recorded_at: Option<DateTime<Utc>>,
    /// True when the closure request was refused or absent: the CAPA ages
    /// as an open item.
    pub treated_as_open: bool,
    /// `closed_at + effectiveness_window_days` for an honored closure.
    pub effectiveness_due: Option<DateTime<Utc>>,
    /// Lexicographically smallest other CAPA whose description normalizes to
    /// the same hash, if any.
    pub duplicate_of: Option<String>,
    pub parent_id: Option<String>,
    /// Whether the named parent cycle exists in the population and is not
    /// this record itself.
    pub parent_present: bool,
    /// This CAPA's findings, in fixed rule order.
    pub findings: Vec<Finding>,
}

/// Manual equality: `spine::Finding` does not implement `PartialEq`, so
/// findings compare field-by-field. Determinism tests rely on this.
impl PartialEq for CapaEvaluation {
    fn eq(&self, other: &Self) -> bool {
        self.capa_id == other.capa_id
            && self.severity == other.severity
            && self.containment_required == other.containment_required
            && self.containment_hours == other.containment_hours
            && self.containment_due == other.containment_due
            && self.containment_recorded_at == other.containment_recorded_at
            && self.treated_as_open == other.treated_as_open
            && self.effectiveness_due == other.effectiveness_due
            && self.duplicate_of == other.duplicate_of
            && self.parent_id == other.parent_id
            && self.parent_present == other.parent_present
            && self.findings.len() == other.findings.len()
            && self
                .findings
                .iter()
                .zip(other.findings.iter())
                .all(|(a, b)| {
                    a.rule_id == b.rule_id
                        && a.severity == b.severity
                        && a.subject == b.subject
                        && a.message == b.message
                        && a.requires_signoff == b.requires_signoff
                })
    }
}

/// Evaluate the population. Deterministic: input order fixes evaluation
/// order; findings carry stable subjects and rule ids. Fail-closed: a
/// population with duplicate ids is refused before any evaluation.
pub fn evaluate(
    capas: &[CapaRecord],
    config: &CapaConfig,
    as_of: DateTime<Utc>,
) -> Result<Vec<CapaEvaluation>, ConfigError> {
    // Ids are the subject keys for findings and signoff receipts: a repeated
    // id would let one subject-scoped receipt stand as evidence for two
    // records. Refuse before any evaluation; input order fixes which
    // duplicate is named.
    let mut seen_ids: HashSet<&str> = HashSet::with_capacity(capas.len());
    for capa in capas {
        if !seen_ids.insert(capa.id.as_str()) {
            return Err(ConfigError::DuplicateCapaId(capa.id.clone()));
        }
    }

    // Duplicate detection needs the whole population: map each normalized
    // description hash to the lexicographically smallest id carrying it, so
    // one deterministic record is canonical and every other carrier names it.
    let mut first_by_hash: HashMap<String, String> = HashMap::new();
    for capa in capas {
        let hash = description_hash(&capa.description);
        let first = first_by_hash.entry(hash).or_insert_with(|| capa.id.clone());
        if capa.id < *first {
            *first = capa.id.clone();
        }
    }

    let mut evaluations = Vec::with_capacity(capas.len());
    for capa in capas {
        evaluations.push(evaluate_one(capa, capas, config, as_of, &first_by_hash)?);
    }
    Ok(evaluations)
}

fn evaluate_one(
    capa: &CapaRecord,
    capas: &[CapaRecord],
    config: &CapaConfig,
    as_of: DateTime<Utc>,
    first_by_hash: &HashMap<String, String>,
) -> Result<CapaEvaluation, ConfigError> {
    let severity = config
        .severity_for(capa.category, capa.detectability)
        .ok_or_else(|| {
            ConfigError::MissingMatrixCell(
                capa.category.to_string(),
                capa.detectability.to_string(),
            )
        })?;

    let mut findings: Vec<Finding> = Vec::new();

    // Rule 1 — containment windows, anchored at opening, scaled by the
    // classified severity. Overdue only strictly past the due instant.
    let containment_hours = config.containment_hours_for(severity);
    let containment_required = containment_hours.is_some();
    let mut containment_due: Option<DateTime<Utc>> = None;
    if let Some(hours) = containment_hours {
        let due = capa.opened_at + Duration::hours(hours as i64);
        containment_due = Some(due);
        match capa.containment_recorded_at {
            None if as_of > due => findings.push(Finding::breach(
                RULE_CONTAINMENT_OVERDUE,
                &capa.id,
                format!(
                    "containment not recorded; {label} severity requires containment within {hours}h of opening (due {due})",
                    label = severity_label(severity).to_lowercase(),
                ),
            )),
            Some(recorded) if recorded > due => findings.push(Finding {
                rule_id: RULE_CONTAINMENT_LATE.to_string(),
                severity: Severity::Warn,
                subject: capa.id.clone(),
                message: format!(
                    "containment recorded at {recorded}, past the {hours}h window (due {due})",
                ),
                requires_signoff: false,
            }),
            _ => {}
        }
    }

    // Rule 2 — closure validity. A closure without recorded root cause, or
    // without its effective date, is refused: the CAPA is not honored as
    // closed and ages as open.
    let root_cause_present = capa
        .root_cause
        .as_deref()
        .is_some_and(|cause| !cause.trim().is_empty());
    let mut treated_as_open = capa.status == Status::Open;
    if capa.status == Status::Closed {
        if !root_cause_present {
            treated_as_open = true;
            findings.push(Finding::breach(
                RULE_CLOSURE_BLOCKED,
                &capa.id,
                "closure refused: root cause not recorded — the closure is not honored and the CAPA ages as open",
            ));
        } else if capa.closed_at.is_none() {
            treated_as_open = true;
            findings.push(Finding::breach(
                RULE_CLOSURE_BLOCKED,
                &capa.id,
                "closure refused: closed_at missing — a closure without its effective date is not honored",
            ));
        }
    }

    // Rule 3 — effectiveness verification. The check is due
    // `effectiveness_window_days` after the recorded closure; its lapse is a
    // breach, and an unresolved breach blocks the pack from reaching Signed —
    // so closure cannot finalize without the check and a signoff.
    let effectiveness_due = capa
        .closed_at
        .map(|closed| closed + Duration::days(config.effectiveness_window_days as i64));
    if capa.status == Status::Closed && root_cause_present {
        if let Some(due) = effectiveness_due {
            let completed = capa
                .effectiveness_check
                .as_ref()
                .is_some_and(|check| check.completed);
            if !completed && as_of > due {
                findings.push(Finding::breach(
                    RULE_EFFECTIVENESS_OVERDUE,
                    &capa.id,
                    format!(
                        "effectiveness check incomplete past its due date {due} ({days} days after closure) — closure cannot finalize while unresolved",
                        days = config.effectiveness_window_days,
                    ),
                ));
            }
        }
    }

    // Rule 4 — aging, applied to everything treated as open. Breach
    // supersedes warn; boundaries are strict (at the threshold is not past).
    if treated_as_open {
        let warn_due = capa.opened_at + Duration::days(config.aging.warn_after_days as i64);
        let breach_due = capa.opened_at + Duration::days(config.aging.breach_after_days as i64);
        let age_days = (as_of - capa.opened_at).num_days();
        if as_of > breach_due {
            findings.push(Finding::breach(
                RULE_AGING_BREACH,
                &capa.id,
                format!(
                    "CAPA open {age_days} days as of {as_of}, past the {breach} day aging limit",
                    breach = config.aging.breach_after_days,
                ),
            ));
        } else if as_of > warn_due {
            findings.push(Finding {
                rule_id: RULE_AGING_WARN.to_string(),
                severity: Severity::Warn,
                subject: capa.id.clone(),
                message: format!(
                    "CAPA open {age_days} days as of {as_of}, past the {warn} day aging review threshold",
                    warn = config.aging.warn_after_days,
                ),
                requires_signoff: false,
            });
        }
    }

    // Rule 5 — reopen linkage: a reopened cycle must name a parent that
    // exists in the population and is not itself.
    let mut parent_present = false;
    if let Some(parent) = &capa.parent_id {
        parent_present = *parent != capa.id && capas.iter().any(|other| &other.id == parent);
        if !parent_present {
            findings.push(Finding::breach(
                RULE_BROKEN_REOPEN_LINK,
                &capa.id,
                format!(
                    "reopen linkage broken: parent cycle {parent} is not present in the population"
                ),
            ));
        }
    }

    // Rule 6 — duplicate detection on normalized description hash.
    let hash = description_hash(&capa.description);
    let duplicate_of = first_by_hash
        .get(&hash)
        .filter(|first| **first != capa.id)
        .cloned();
    if let Some(other) = &duplicate_of {
        findings.push(Finding {
            rule_id: RULE_DUPLICATE_DESCRIPTION.to_string(),
            severity: Severity::Warn,
            subject: capa.id.clone(),
            message: format!(
                "description normalizes to the same hash as CAPA {other} — possible duplicate cycle"
            ),
            requires_signoff: false,
        });
    }

    Ok(CapaEvaluation {
        capa_id: capa.id.clone(),
        severity,
        containment_required,
        containment_hours,
        containment_due,
        containment_recorded_at: capa.containment_recorded_at,
        treated_as_open,
        effectiveness_due,
        duplicate_of,
        parent_id: capa.parent_id.clone(),
        parent_present,
        findings,
    })
}
