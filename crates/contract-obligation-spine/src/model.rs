//! Input register and policy config schemas for the contract obligation
//! spine, plus fail-closed semantic validation.
//!
//! Every structure deserializes with `deny_unknown_fields`: config that does
//! not match the schema is refused at load, never silently coerced. Semantic
//! rules (version lineage, anchor resolution, tier ordering, calendar
//! references, arithmetic bounds) are validated by [`validate`] before the
//! engine runs — an invalid register never produces findings.

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// Inclusive upper bound of the valid date window for every date in config
/// and inputs. Keeps date arithmetic far from `chrono` overflow panics; a
/// date outside the window is a config error, never a panic.
pub const MAX_DATE: NaiveDate = match NaiveDate::from_ymd_opt(2999, 12, 31) {
    Some(d) => d,
    None => panic!("2999-12-31 is a valid date"),
};

/// Inclusive lower bound for the caller-supplied clock: with window/notice
/// knobs bounded at MAX_DAY_SPAN, subtracting them from a clock at or after
/// this date can never underflow.
pub const MIN_CLOCK: NaiveDate = match NaiveDate::from_ymd_opt(1970, 1, 1) {
    Some(d) => d,
    None => panic!("1970-01-01 is a valid date"),
};

/// Upper bound for any money amount in integer cents (10^15 cents = 10
/// trillion units). Keeps `charges * credit_bp` inside i128 with overflow
/// checks enabled.
pub const MAX_MONEY_CENTS: i128 = 1_000_000_000_000_000;

/// Upper bound for day-valued config knobs (notice periods, warn windows,
/// day offsets): roughly ten years of days.
pub const MAX_DAY_SPAN: u32 = 3_660;

/// Upper bound for month offsets: ten years.
pub const MAX_MONTH_OFFSET: u32 = 120;

/// Upper bound for uptime expressed in basis points of a percent: 10_000 bp
/// = 100.00%.
pub const MAX_UPTIME_BP: u64 = 10_000;

/// Upper bound for a service credit expressed in basis points of period
/// charges: 10_000 bp = 100%.
pub const MAX_CREDIT_BP: u64 = 10_000;

/// Semantic validation failure. The engine refuses to compute on any of
/// these — fail-closed, with no partial output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("params: {0}")]
    InvalidParams(String),
    #[error("register: {0}")]
    InvalidRegister(String),
    #[error("obligation {id}: {reason}")]
    InvalidObligation { id: String, reason: String },
    #[error("obligation {id}: anchor {anchor_id}: {reason}")]
    InvalidAnchor {
        id: String,
        anchor_id: String,
        reason: String,
    },
    #[error("calendar {jurisdiction}: {reason}")]
    InvalidCalendar {
        jurisdiction: String,
        reason: String,
    },
    #[error("no business day on or after {from} within one year in calendar {jurisdiction}")]
    NoBusinessDay { jurisdiction: String, from: String },
}

/// Typed obligation kinds. `payment`, `delivery`, `indemnity`, and
/// `termination_for_convenience` carry due-date semantics; `sla` and
/// `renewal_opt_out` carry their own term blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationType {
    Payment,
    Delivery,
    Sla,
    TerminationForConvenience,
    Indemnity,
    RenewalOptOut,
}

/// The event on an anchor obligation that starts a dependent clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorEvent {
    /// The anchor obligation's computed due date.
    Due,
    /// The date the anchor obligation was actually completed, as recorded in
    /// the register (`completed_on`). Pending while unrecorded.
    Completed,
}

/// Where a due date comes from. Relative dates ("within 30 days of
/// delivery") are modeled as dependent dates with an explicit anchor: the
/// base date is always named, never guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DateSpec {
    /// A contract-stated date, taken as fact (never business-day rolled).
    Explicit {
        #[serde(rename = "date")]
        date: NaiveDate,
    },
    /// A date computed from an anchor obligation: anchor base date shifted
    /// by `offset_months` (month-end clamped) then `offset_days`, then
    /// business-day rolled per this obligation's jurisdiction.
    Dependent {
        anchor_id: String,
        anchor_event: AnchorEvent,
        #[serde(default)]
        offset_days: u32,
        #[serde(default)]
        offset_months: u32,
    },
}

/// Renewal / opt-out terms for a `renewal_opt_out` obligation. The opt-out
/// deadline is `renewal_date - notice_days` (business-day rolled per
/// jurisdiction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalTerms {
    pub renewal_date: NaiveDate,
    pub notice_days: u32,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default)]
    pub opted_out: bool,
}

/// SLA measurement-window terms for an `sla` obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaTerms {
    /// Measurement period length in days; drives staleness detection.
    pub window_days: u32,
}

/// One measured SLA period. Percentages are basis points of a percent
/// (99.50% = 9_950 bp) so no float ever enters the engine; charges are
/// integer cents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaMeasurement {
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub achieved_uptime_bp: u64,
    pub charges_cents: i128,
}

/// One version of an obligation record. The register is append-only: a
/// correction is a new record with a higher `version` and `supersedes`
/// naming the version it replaces — never an edit to an existing record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationRecord {
    pub id: String,
    pub version: u64,
    /// Version number this record corrects, if any.
    #[serde(default)]
    pub supersedes: Option<u64>,
    pub counterparty: String,
    pub obligation_type: ObligationType,
    /// Key into the params calendar table; absent means no business-day
    /// rolling applies to this record's computed dates.
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub due: Option<DateSpec>,
    /// Exposure in integer cents, where applicable (payment, indemnity).
    #[serde(default)]
    pub amount_cents: Option<i128>,
    /// The date the obligation was satisfied, per the register.
    #[serde(default)]
    pub satisfied_on: Option<NaiveDate>,
    /// Completion date of the obligation's anchor event, available to other
    /// records' dependent-date anchors (`AnchorEvent::Completed`).
    #[serde(default)]
    pub completed_on: Option<NaiveDate>,
    #[serde(default)]
    pub renewal: Option<RenewalTerms>,
    #[serde(default)]
    pub sla: Option<SlaTerms>,
    #[serde(default)]
    pub sla_measurements: Vec<SlaMeasurement>,
}

/// The register: the input side of every compute run. Provenance-hashed as
/// canonical JSON in the order given here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterInputs {
    pub obligations: Vec<ObligationRecord>,
}

/// Business-day rolling mode for computed deadlines. `none` honors raw
/// arithmetic (the spec-exact deadline); `forward` rolls a computed deadline
/// falling on a weekend or holiday to the next business day. Explicit
/// contract-stated dates are never rolled under either mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollMode {
    None,
    Forward,
}

/// A jurisdiction calendar: weekend day names ("mon".."sun") and holiday
/// dates. Shipped calendars are seed data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calendar {
    pub weekend: Vec<String>,
    #[serde(default)]
    pub holidays: Vec<NaiveDate>,
}

/// One SLA credit tier. `min_uptime_bp` is the minimum achieved uptime that
/// lands in this tier (9_900 = 99.00%); `credit_bp` is the service credit as
/// basis points of period charges (500 = 5%).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlaTier {
    pub min_uptime_bp: u64,
    pub credit_bp: u64,
}

/// Policy config (the params side): warn windows, roll mode, jurisdiction
/// calendars, and the SLA credit tier table. Provenance-hashed as canonical
/// JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyParams {
    pub warn_days_before_due: u32,
    pub warn_days_before_optout: u32,
    pub business_day_roll: RollMode,
    #[serde(default)]
    pub calendars: BTreeMap<String, Calendar>,
    pub sla_credit_tiers: Vec<SlaTier>,
}

const WEEKDAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn check_date(d: NaiveDate, what: &str, id: &str) -> Result<(), ConfigError> {
    if d > MAX_DATE {
        return Err(ConfigError::InvalidObligation {
            id: id.to_string(),
            reason: format!("{what} {d} after the valid window end {MAX_DATE}"),
        });
    }
    Ok(())
}

fn check_money(v: i128, what: &str, id: &str) -> Result<(), ConfigError> {
    if !(0..=MAX_MONEY_CENTS).contains(&v) {
        return Err(ConfigError::InvalidObligation {
            id: id.to_string(),
            reason: format!("{what} {v} outside the valid range 0..={MAX_MONEY_CENTS}"),
        });
    }
    Ok(())
}

fn check_day_span(v: u32, what: &str, id: &str) -> Result<(), ConfigError> {
    if v > MAX_DAY_SPAN {
        return Err(ConfigError::InvalidObligation {
            id: id.to_string(),
            reason: format!("{what} {v} exceeds the maximum {MAX_DAY_SPAN} days"),
        });
    }
    Ok(())
}

fn validate_params(params: &PolicyParams) -> Result<(), ConfigError> {
    if params.warn_days_before_due > MAX_DAY_SPAN || params.warn_days_before_optout > MAX_DAY_SPAN {
        return Err(ConfigError::InvalidParams(
            "warn windows exceed the maximum day span".to_string(),
        ));
    }
    if params.sla_credit_tiers.is_empty() {
        return Err(ConfigError::InvalidParams(
            "sla_credit_tiers must not be empty: with no tiers every measured period would be a breach, which is a config error, not a policy".to_string(),
        ));
    }
    // Tiers must be strictly descending by threshold so the lookup (first
    // tier whose minimum the measurement meets) is unambiguous.
    let mut sorted = params.sla_credit_tiers.clone();
    sorted.sort_by_key(|t| std::cmp::Reverse(t.min_uptime_bp));
    if sorted != params.sla_credit_tiers {
        return Err(ConfigError::InvalidParams(
            "sla_credit_tiers must be strictly descending by min_uptime_bp".to_string(),
        ));
    }
    for t in &params.sla_credit_tiers {
        if t.min_uptime_bp > MAX_UPTIME_BP {
            return Err(ConfigError::InvalidParams(format!(
                "tier min_uptime_bp {} exceeds {MAX_UPTIME_BP}",
                t.min_uptime_bp
            )));
        }
        if t.credit_bp > MAX_CREDIT_BP {
            return Err(ConfigError::InvalidParams(format!(
                "tier credit_bp {} exceeds {MAX_CREDIT_BP}",
                t.credit_bp
            )));
        }
    }
    for (i, a) in params.sla_credit_tiers.iter().enumerate() {
        for b in params.sla_credit_tiers.iter().skip(i + 1) {
            if a.min_uptime_bp == b.min_uptime_bp {
                return Err(ConfigError::InvalidParams(format!(
                    "sla_credit_tiers contains duplicate min_uptime_bp {}",
                    a.min_uptime_bp
                )));
            }
        }
    }
    for (jurisdiction, cal) in &params.calendars {
        for name in &cal.weekend {
            if !WEEKDAY_NAMES.contains(&name.as_str()) {
                return Err(ConfigError::InvalidCalendar {
                    jurisdiction: jurisdiction.clone(),
                    reason: format!("unknown weekend day name '{name}' (expected mon..sun)"),
                });
            }
        }
        for h in &cal.holidays {
            if *h > MAX_DATE {
                return Err(ConfigError::InvalidCalendar {
                    jurisdiction: jurisdiction.clone(),
                    reason: format!("holiday {h} after the valid date window"),
                });
            }
        }
    }
    Ok(())
}

fn validate_record(record: &ObligationRecord) -> Result<(), ConfigError> {
    let id = &record.id;
    if id.trim().is_empty() {
        return Err(ConfigError::InvalidObligation {
            id: id.clone(),
            reason: "obligation id must not be empty".to_string(),
        });
    }
    if record.counterparty.trim().is_empty() {
        return Err(ConfigError::InvalidObligation {
            id: id.clone(),
            reason: "counterparty must not be empty".to_string(),
        });
    }
    if record.version == 0 {
        return Err(ConfigError::InvalidObligation {
            id: id.clone(),
            reason: "version must be at least 1".to_string(),
        });
    }
    if let Some(v) = record.supersedes {
        if v >= record.version {
            return Err(ConfigError::InvalidObligation {
                id: id.clone(),
                reason: format!(
                    "supersedes {v} must be below this record's version {}",
                    record.version
                ),
            });
        }
    }
    if let Some(amount) = record.amount_cents {
        check_money(amount, "amount_cents", id)?;
    }
    // Type / term-block coherence.
    match record.obligation_type {
        ObligationType::Sla => {
            if record.sla.is_none() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "sla obligations must carry an sla terms block".to_string(),
                });
            }
            if record.due.is_some() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "sla obligations must not carry a due date spec".to_string(),
                });
            }
        }
        ObligationType::RenewalOptOut => {
            if record.renewal.is_none() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "renewal_opt_out obligations must carry a renewal terms block"
                        .to_string(),
                });
            }
            if record.due.is_some() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "renewal_opt_out obligations must not carry a due date spec"
                        .to_string(),
                });
            }
        }
        _ => {
            if record.renewal.is_some() || record.sla.is_some() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "only sla / renewal_opt_out obligations carry sla or renewal terms"
                        .to_string(),
                });
            }
            if !record.sla_measurements.is_empty() {
                return Err(ConfigError::InvalidObligation {
                    id: id.clone(),
                    reason: "sla_measurements are only valid on sla obligations".to_string(),
                });
            }
        }
    }
    if let Some(renewal) = &record.renewal {
        check_date(renewal.renewal_date, "renewal_date", id)?;
        check_day_span(renewal.notice_days, "notice_days", id)?;
    }
    if let Some(sla) = &record.sla {
        check_day_span(sla.window_days, "sla window_days", id)?;
    }
    for m in &record.sla_measurements {
        check_date(m.period_start, "measurement period_start", id)?;
        check_date(m.period_end, "measurement period_end", id)?;
        if m.period_end < m.period_start {
            return Err(ConfigError::InvalidObligation {
                id: id.clone(),
                reason: format!(
                    "measurement period {}..{} ends before it starts",
                    m.period_start, m.period_end
                ),
            });
        }
        if m.achieved_uptime_bp > MAX_UPTIME_BP {
            return Err(ConfigError::InvalidObligation {
                id: id.clone(),
                reason: format!(
                    "achieved_uptime_bp {} exceeds {MAX_UPTIME_BP}",
                    m.achieved_uptime_bp
                ),
            });
        }
        check_money(m.charges_cents, "measurement charges_cents", id)?;
    }
    if let Some(due) = &record.due {
        match due {
            DateSpec::Explicit { date } => check_date(*date, "explicit due date", id)?,
            DateSpec::Dependent {
                offset_days,
                offset_months,
                ..
            } => {
                check_day_span(*offset_days, "dependent offset_days", id)?;
                if *offset_months > MAX_MONTH_OFFSET {
                    return Err(ConfigError::InvalidObligation {
                        id: id.clone(),
                        reason: format!(
                            "dependent offset_months {} exceeds the maximum {MAX_MONTH_OFFSET}",
                            offset_months
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate the whole register and cross-check it against params: version
/// lineage, anchor resolution, dependency acyclicity, calendar references.
pub fn validate(inputs: &RegisterInputs, params: &PolicyParams) -> Result<(), ConfigError> {
    validate_params(params)?;
    // Version lineage, in register order: per id, versions strictly ascend
    // and each correction supersedes exactly the prior version.
    let mut last_version: BTreeMap<&str, u64> = BTreeMap::new();
    let mut seen: BTreeSet<(&str, u64)> = BTreeSet::new();
    for record in &inputs.obligations {
        validate_record(record)?;
        let id = record.id.as_str();
        if !seen.insert((id, record.version)) {
            return Err(ConfigError::InvalidRegister(format!(
                "duplicate record for obligation {id} version {}",
                record.version
            )));
        }
        if let Some(prior) = last_version.get(id) {
            if record.supersedes != Some(*prior) {
                return Err(ConfigError::InvalidRegister(format!(
                    "correction for obligation {id} to version {} must supersede the prior version {prior}",
                    record.version
                )));
            }
        } else if record.supersedes.is_some() {
            return Err(ConfigError::InvalidRegister(format!(
                "first record for obligation {id} must not claim to supersede a version"
            )));
        }
        last_version.insert(id, record.version);
    }
    // Anchor references resolve and form no cycles.
    let ids: BTreeSet<&str> = inputs.obligations.iter().map(|r| r.id.as_str()).collect();
    let mut graph: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for record in &inputs.obligations {
        if let Some(DateSpec::Dependent { anchor_id, .. }) = &record.due {
            if !ids.contains(anchor_id.as_str()) {
                return Err(ConfigError::InvalidAnchor {
                    id: record.id.clone(),
                    anchor_id: anchor_id.clone(),
                    reason: "anchor obligation not found in the register".to_string(),
                });
            }
            graph
                .entry(record.id.as_str())
                .or_default()
                .push(anchor_id.as_str());
        }
    }
    for id in &ids {
        detect_cycle(id, &graph)?;
    }
    // Calendar references exist.
    for record in &inputs.obligations {
        if let Some(j) = &record.jurisdiction {
            if !params.calendars.contains_key(j) {
                return Err(ConfigError::InvalidCalendar {
                    jurisdiction: j.clone(),
                    reason: format!(
                        "obligation {} references a calendar that is not defined in params",
                        record.id
                    ),
                });
            }
        }
    }
    Ok(())
}

fn detect_cycle(start: &str, graph: &BTreeMap<&str, Vec<&str>>) -> Result<(), ConfigError> {
    fn dfs(
        node: &str,
        graph: &BTreeMap<&str, Vec<&str>>,
        stack: &mut Vec<String>,
        in_stack: &mut BTreeSet<String>,
    ) -> Result<(), ConfigError> {
        if in_stack.contains(node) {
            return Err(ConfigError::InvalidAnchor {
                id: node.to_string(),
                anchor_id: node.to_string(),
                reason: format!("dependency cycle through {}", stack.join(" -> ")),
            });
        }
        if let Some(neighbors) = graph.get(node) {
            stack.push(node.to_string());
            in_stack.insert(node.to_string());
            for n in neighbors {
                dfs(n, graph, stack, in_stack)?;
            }
            in_stack.remove(node);
            stack.pop();
        }
        Ok(())
    }
    let mut stack = Vec::new();
    let mut in_stack = BTreeSet::new();
    dfs(start, graph, &mut stack, &mut in_stack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid test date")
    }

    fn params() -> PolicyParams {
        PolicyParams {
            warn_days_before_due: 10,
            warn_days_before_optout: 14,
            business_day_roll: RollMode::None,
            calendars: Map::new(),
            sla_credit_tiers: vec![
                SlaTier {
                    min_uptime_bp: 9990,
                    credit_bp: 100,
                },
                SlaTier {
                    min_uptime_bp: 9900,
                    credit_bp: 500,
                },
            ],
        }
    }

    fn rec(id: &str, kind: ObligationType) -> ObligationRecord {
        ObligationRecord {
            id: id.to_string(),
            version: 1,
            supersedes: None,
            counterparty: "Acme Corp".to_string(),
            obligation_type: kind,
            jurisdiction: None,
            due: None,
            amount_cents: None,
            satisfied_on: None,
            completed_on: None,
            renewal: None,
            sla: None,
            sla_measurements: vec![],
        }
    }

    fn validate_all(
        records: &[ObligationRecord],
        params: &PolicyParams,
    ) -> Result<(), ConfigError> {
        validate(
            &RegisterInputs {
                obligations: records.to_vec(),
            },
            params,
        )
    }

    #[test]
    fn unknown_fields_are_rejected_in_inputs() {
        let raw = r#"{"obligations": [], "surprise": 1}"#;
        assert!(serde_json::from_str::<RegisterInputs>(raw).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected_in_params() {
        let raw = r#"{"warn_days_before_due": 10, "warn_days_before_optout": 14,
            "business_day_roll": "none", "sla_credit_tiers": [{"min_uptime_bp": 9900, "credit_bp": 100}],
            "surprise": true}"#;
        assert!(serde_json::from_str::<PolicyParams>(raw).is_err());
    }

    #[test]
    fn duplicate_id_version_pair_is_rejected() {
        let a = rec("O-1", ObligationType::Payment);
        let b = rec("O-1", ObligationType::Payment);
        assert!(validate_all(&[a, b], &params()).is_err());
    }

    #[test]
    fn correction_must_supersede_the_prior_version() {
        let mut v2 = rec("O-1", ObligationType::Payment);
        v2.version = 2;
        v2.supersedes = Some(1);
        // v1 missing: a correction with nothing to correct.
        assert!(validate_all(&[v2.clone()], &params()).is_err());
        // Correct chain.
        let v1 = rec("O-1", ObligationType::Payment);
        assert!(validate_all(&[v1, v2.clone()], &params()).is_ok());
        // Supersedes must name the immediately prior version.
        let mut v3 = rec("O-1", ObligationType::Payment);
        v3.version = 3;
        v3.supersedes = Some(1);
        let v1b = rec("O-1", ObligationType::Payment);
        assert!(validate_all(&[v1b, v2, v3], &params()).is_err());
    }

    #[test]
    fn first_version_must_not_supersede_anything() {
        let mut v1 = rec("O-1", ObligationType::Payment);
        v1.supersedes = Some(1);
        assert!(validate_all(&[v1], &params()).is_err());
    }

    #[test]
    fn dependency_cycle_is_rejected() {
        let mut a = rec("O-A", ObligationType::Payment);
        let mut b = rec("O-B", ObligationType::Payment);
        a.due = Some(DateSpec::Dependent {
            anchor_id: "O-B".to_string(),
            anchor_event: AnchorEvent::Due,
            offset_days: 0,
            offset_months: 0,
        });
        b.due = Some(DateSpec::Dependent {
            anchor_id: "O-A".to_string(),
            anchor_event: AnchorEvent::Due,
            offset_days: 0,
            offset_months: 0,
        });
        assert!(matches!(
            validate_all(&[a, b], &params()),
            Err(ConfigError::InvalidAnchor { .. })
        ));
    }

    #[test]
    fn unknown_anchor_is_rejected() {
        let mut a = rec("O-A", ObligationType::Payment);
        a.due = Some(DateSpec::Dependent {
            anchor_id: "O-GHOST".to_string(),
            anchor_event: AnchorEvent::Due,
            offset_days: 5,
            offset_months: 0,
        });
        assert!(matches!(
            validate_all(&[a], &params()),
            Err(ConfigError::InvalidAnchor { .. })
        ));
    }

    #[test]
    fn unknown_calendar_reference_is_rejected() {
        let mut a = rec("O-1", ObligationType::Payment);
        a.jurisdiction = Some("US-NY".to_string());
        assert!(matches!(
            validate_all(&[a], &params()),
            Err(ConfigError::InvalidCalendar { .. })
        ));
    }

    #[test]
    fn sla_tiers_must_descend_strictly() {
        let mut p = params();
        p.sla_credit_tiers = vec![
            SlaTier {
                min_uptime_bp: 9900,
                credit_bp: 100,
            },
            SlaTier {
                min_uptime_bp: 9990,
                credit_bp: 500,
            },
        ];
        assert!(matches!(
            validate_all(&[rec("O-1", ObligationType::Payment)], &p),
            Err(ConfigError::InvalidParams(_))
        ));
        // Equal thresholds are duplicates — also rejected.
        p.sla_credit_tiers = vec![
            SlaTier {
                min_uptime_bp: 9900,
                credit_bp: 100,
            },
            SlaTier {
                min_uptime_bp: 9900,
                credit_bp: 500,
            },
        ];
        assert!(validate_all(&[rec("O-1", ObligationType::Payment)], &p).is_err());
        // Empty tier table is a config error, not an implicit all-breach policy.
        p.sla_credit_tiers = vec![];
        assert!(validate_all(&[rec("O-1", ObligationType::Payment)], &p).is_err());
    }

    #[test]
    fn sla_measurement_window_must_be_ordered() {
        let mut s = rec("O-S", ObligationType::Sla);
        s.sla = Some(SlaTerms { window_days: 90 });
        s.sla_measurements = vec![SlaMeasurement {
            period_start: d(2026, 4, 1),
            period_end: d(2026, 3, 31),
            achieved_uptime_bp: 9900,
            charges_cents: 1_000_000,
        }];
        assert!(validate_all(&[s], &params()).is_err());
    }

    #[test]
    fn oversized_notice_days_is_rejected() {
        let mut r = rec("O-R", ObligationType::RenewalOptOut);
        r.renewal = Some(RenewalTerms {
            renewal_date: d(2027, 1, 5),
            notice_days: MAX_DAY_SPAN + 1,
            auto_renew: true,
            opted_out: false,
        });
        assert!(validate_all(&[r], &params()).is_err());
    }

    #[test]
    fn negative_amount_is_rejected() {
        let mut p = rec("O-1", ObligationType::Payment);
        p.amount_cents = Some(-1);
        assert!(validate_all(&[p], &params()).is_err());
        let mut p2 = rec("O-2", ObligationType::Payment);
        p2.amount_cents = Some(MAX_MONEY_CENTS + 1);
        assert!(validate_all(&[p2], &params()).is_err());
    }

    #[test]
    fn term_blocks_are_typed_per_obligation_kind() {
        // A payment carrying SLA terms is malformed.
        let mut p = rec("O-1", ObligationType::Payment);
        p.sla = Some(SlaTerms { window_days: 30 });
        assert!(validate_all(&[p], &params()).is_err());
        // An SLA obligation without its terms block is malformed.
        assert!(validate_all(&[rec("O-S", ObligationType::Sla)], &params()).is_err());
        // A renewal obligation without its terms block is malformed.
        assert!(validate_all(&[rec("O-R", ObligationType::RenewalOptOut)], &params()).is_err());
    }

    #[test]
    fn achieved_uptime_above_10000_is_rejected() {
        let mut s = rec("O-S", ObligationType::Sla);
        s.sla = Some(SlaTerms { window_days: 90 });
        s.sla_measurements = vec![SlaMeasurement {
            period_start: d(2026, 4, 1),
            period_end: d(2026, 6, 30),
            achieved_uptime_bp: MAX_UPTIME_BP + 1,
            charges_cents: 1_000_000,
        }];
        assert!(validate_all(&[s], &params()).is_err());
    }

    #[test]
    fn json_round_trip_preserves_the_register() {
        let mut p = rec("O-1", ObligationType::Payment);
        p.amount_cents = Some(123_456);
        p.due = Some(DateSpec::Explicit {
            date: d(2026, 12, 1),
        });
        let inputs = RegisterInputs {
            obligations: vec![p],
        };
        let json = serde_json::to_string(&inputs).expect("serialize");
        let back: RegisterInputs = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, inputs);
    }
}
