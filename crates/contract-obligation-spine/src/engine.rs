//! The pure contract-obligation engine.
//!
//! Deterministic date and rule arithmetic over an obligation register: given
//! the register, the policy params, and a caller-supplied clock date, it
//! resolves every due date and opt-out deadline and emits typed findings.
//! No clock reads, no filesystem, no network, no randomness — the same
//! inputs always produce byte-identical output.
//!
//! Money is integer cents (i128); percentages are basis points of a percent
//! so no float ever enters the computation.

use std::collections::BTreeMap;

use chrono::{Datelike, Days, NaiveDate, Weekday};
use serde::{Deserialize, Serialize};

use spine::{Finding, Severity};

use crate::model::{
    validate, AnchorEvent, Calendar, ConfigError, DateSpec, ObligationRecord, ObligationType,
    PolicyParams, RegisterInputs, RollMode, SlaMeasurement, SlaTier, MAX_DATE, MIN_CLOCK,
};

/// One evaluation of the register at one clock date.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub findings: Vec<Finding>,
    /// Per-obligation deadline resolution detail — what `explain` prints and
    /// what makes each finding's arithmetic auditable.
    pub resolutions: Vec<DeadlineResolution>,
}

/// Which deadline family a resolution describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    Due,
    OptOut,
    Sla,
}

/// The resolved dates for one obligation at the evaluated clock. Resolved
/// values are the latest register version of the obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineResolution {
    pub obligation_id: String,
    pub kind: ResolutionKind,
    pub counterparty: String,
    /// The anchor base date a dependent date was computed from, when known.
    pub base_date: Option<NaiveDate>,
    /// The final (rolled) effective date. `None` when the date is not yet
    /// fixed (a dependent date whose anchor event has not occurred) or does
    /// not apply.
    pub due_date: Option<NaiveDate>,
    /// Effective date minus the clock, in days (negative when past).
    pub days_remaining: Option<i64>,
    /// True when business-day rolling moved the computed date.
    pub roll_applied: bool,
    /// SLA only: the tier the latest measurement lands in.
    pub tier_min_uptime_bp: Option<u64>,
    /// SLA only: computed service credit in integer cents for the latest
    /// measurement.
    pub credit_cents: Option<i128>,
}

/// Rule identifiers. Order within this list is the order findings are
/// evaluated per obligation; output order is obligation id, then this order.
pub mod rule_ids {
    pub const REGISTER_CORRECTION: &str = "REGISTER-CORRECTION";
    pub const DUE_MET: &str = "OBL-DUE-MET";
    pub const DUE_UPCOMING: &str = "OBL-DUE-UPCOMING";
    pub const DUE_OVERDUE: &str = "OBL-DUE-OVERDUE";
    pub const DEPENDENT_PENDING: &str = "OBL-DEPENDENT-PENDING";
    pub const SLA_CREDIT_DUE: &str = "SLA-CREDIT-DUE";
    pub const SLA_BREACH: &str = "SLA-BREACH";
    pub const SLA_STALE: &str = "SLA-STALE";
    pub const OPTOUT_OPEN: &str = "RENEW-OPTOUT-OPEN";
    pub const OPTOUT_CLOSING: &str = "RENEW-OPTOUT-CLOSING";
    pub const OPTOUT_PASSED: &str = "RENEW-OPTOUT-PASSED";
    pub const AUTO_RENEWED: &str = "RENEW-AUTO-RENEWED";
    pub const OPTOUT_EXERCISED: &str = "RENEW-OPTOUT-EXERCISED";
    pub const TERM_ENDED: &str = "RENEW-TERM-ENDED";
}

fn info(rule_id: &str, subject: &str, message: String) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Info,
        subject: subject.to_string(),
        message,
        requires_signoff: false,
    }
}

fn warn(rule_id: &str, subject: &str, message: String) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Warn,
        subject: subject.to_string(),
        message,
        requires_signoff: false,
    }
}

/// Clamp-add months: the day is clamped to the target month's last day, so
/// Jan 31 + 1 month = Feb 28 (Feb 29 in a leap year). Sequential additions
/// compound from the clamped date (Feb 28 + 1 month = Mar 28).
pub fn add_months(d: NaiveDate, n: u32) -> NaiveDate {
    let total = d.year() * 12 + d.month0() as i32 + n as i32;
    let y = total.div_euclid(12);
    let m = total.rem_euclid(12) as u32 + 1;
    let day = d.day().min(last_day_of_month(y, m));
    NaiveDate::from_ymd_opt(y, m, day).expect("clamped month-end date is valid")
}

fn last_day_of_month(y: i32, m: u32) -> u32 {
    let (next_y, next_m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    NaiveDate::from_ymd_opt(next_y, next_m, 1)
        .and_then(|d| d.pred_opt())
        .map(|d| d.day())
        .expect("first of a month always has a predecessor")
}

fn weekday_name(w: Weekday) -> &'static str {
    match w {
        Weekday::Mon => "mon",
        Weekday::Tue => "tue",
        Weekday::Wed => "wed",
        Weekday::Thu => "thu",
        Weekday::Fri => "fri",
        Weekday::Sat => "sat",
        Weekday::Sun => "sun",
    }
}

fn is_business_day(d: NaiveDate, cal: &Calendar) -> bool {
    let name = weekday_name(d.weekday());
    !cal.weekend.iter().any(|w| w.eq_ignore_ascii_case(name)) && !cal.holidays.contains(&d)
}

/// Roll forward to the next business day. Bounded by a one-year scan: a
/// calendar with no business days at all is a config error, not a hang.
fn roll_forward(
    d: NaiveDate,
    cal: &Calendar,
    jurisdiction: &str,
) -> Result<NaiveDate, ConfigError> {
    let mut cur = d;
    for _ in 0..=366 {
        if is_business_day(cur, cal) {
            return Ok(cur);
        }
        cur = cur.succ_opt().ok_or_else(|| ConfigError::NoBusinessDay {
            jurisdiction: jurisdiction.to_string(),
            from: d.to_string(),
        })?;
    }
    Err(ConfigError::NoBusinessDay {
        jurisdiction: jurisdiction.to_string(),
        from: d.to_string(),
    })
}

/// Business-day rolling for a computed date: only in `forward` mode and only
/// when the obligation names a jurisdiction with a defined calendar.
fn roll_computed(
    d: NaiveDate,
    jurisdiction: Option<&str>,
    params: &PolicyParams,
) -> Result<(NaiveDate, bool), ConfigError> {
    if params.business_day_roll == RollMode::None {
        return Ok((d, false));
    }
    let Some(j) = jurisdiction else {
        return Ok((d, false));
    };
    let cal = params
        .calendars
        .get(j)
        .ok_or_else(|| ConfigError::InvalidCalendar {
            jurisdiction: j.to_string(),
            reason: format!("obligation references calendar {j} which is not defined in params"),
        })?;
    let rolled = roll_forward(d, cal, j)?;
    Ok((rolled, rolled != d))
}

/// The result of resolving one obligation's due-date spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueComputation {
    /// The anchor base date the dependent arithmetic started from.
    pub base_date: Option<NaiveDate>,
    /// The final effective date, after offsets and rolling.
    pub due_date: Option<NaiveDate>,
    pub roll_applied: bool,
}

/// Resolve an obligation's due date. `None` means the date is not yet fixed:
/// either the obligation carries no due spec, or a dependent chain terminates
/// in an anchor event that has not occurred. Anchors always name an explicit
/// register id — never guessed, cycle-guarded.
fn due_computation_of(
    record: &ObligationRecord,
    latest: &BTreeMap<&str, &ObligationRecord>,
    params: &PolicyParams,
    chain: &mut Vec<String>,
) -> Result<DueComputation, ConfigError> {
    let Some(spec) = &record.due else {
        return Ok(DueComputation {
            base_date: None,
            due_date: None,
            roll_applied: false,
        });
    };
    match spec {
        DateSpec::Explicit { date } => Ok(DueComputation {
            base_date: Some(*date),
            due_date: Some(*date),
            roll_applied: false,
        }),
        DateSpec::Dependent {
            anchor_id,
            anchor_event,
            offset_days,
            offset_months,
        } => {
            if chain.contains(&record.id) {
                return Err(ConfigError::InvalidAnchor {
                    id: record.id.clone(),
                    anchor_id: anchor_id.clone(),
                    reason: format!("dependency cycle: {}", chain.join(" -> ")),
                });
            }
            let anchor =
                latest
                    .get(anchor_id.as_str())
                    .ok_or_else(|| ConfigError::InvalidAnchor {
                        id: record.id.clone(),
                        anchor_id: anchor_id.clone(),
                        reason: "anchor obligation not found in the register".to_string(),
                    })?;
            chain.push(record.id.clone());
            let base = match anchor_event {
                AnchorEvent::Completed => anchor.completed_on,
                AnchorEvent::Due => due_computation_of(anchor, latest, params, chain)?.due_date,
            };
            chain.pop();
            let Some(base) = base else {
                return Ok(DueComputation {
                    base_date: None,
                    due_date: None,
                    roll_applied: false,
                });
            };
            let shifted = add_months(base, *offset_months);
            let shifted = if *offset_days > 0 {
                shifted + Days::new(u64::from(*offset_days))
            } else {
                shifted
            };
            let (due, rolled) = roll_computed(shifted, record.jurisdiction.as_deref(), params)?;
            Ok(DueComputation {
                base_date: Some(base),
                due_date: Some(due),
                roll_applied: rolled,
            })
        }
    }
}

/// Look up the SLA credit tier for an achieved uptime. The tier table is
/// validated strictly descending by threshold, so the first tier whose
/// minimum the measurement meets is the binding one. `None` means the
/// measurement lands below every configured tier floor — an SLA breach.
pub fn tier_for(achieved_uptime_bp: u64, tiers: &[SlaTier]) -> Option<SlaTier> {
    tiers
        .iter()
        .find(|t| t.min_uptime_bp <= achieved_uptime_bp)
        .copied()
}

/// Integer-cents service credit: `charges * credit_bp / 10_000`, floored.
/// Deterministic integer arithmetic; validated bounds keep it overflow-free.
pub fn credit_cents(charges_cents: i128, credit_bp: u64) -> i128 {
    charges_cents * i128::from(credit_bp) / 10_000
}

fn evaluate_due(
    record: &ObligationRecord,
    clock: NaiveDate,
    params: &PolicyParams,
    latest: &BTreeMap<&str, &ObligationRecord>,
    chain: &mut Vec<String>,
    findings: &mut Vec<Finding>,
    resolutions: &mut Vec<DeadlineResolution>,
) -> Result<(), ConfigError> {
    let comp = due_computation_of(record, latest, params, chain)?;
    let mut resolution = DeadlineResolution {
        obligation_id: record.id.clone(),
        kind: ResolutionKind::Due,
        counterparty: record.counterparty.clone(),
        base_date: comp.base_date,
        due_date: comp.due_date,
        days_remaining: None,
        roll_applied: comp.roll_applied,
        tier_min_uptime_bp: None,
        credit_cents: None,
    };
    match comp.due_date {
        None => {
            if let Some(DateSpec::Dependent {
                anchor_id,
                anchor_event,
                ..
            }) = &record.due
            {
                findings.push(info(
                    rule_ids::DEPENDENT_PENDING,
                    &record.id,
                    format!(
                        "dependent due date not yet fixed: anchor {anchor_id} event {anchor_event:?} has not occurred"
                    ),
                ));
            }
        }
        Some(due) => {
            let days = (due - clock).num_days();
            resolution.days_remaining = Some(days);
            let satisfied = record.satisfied_on.is_some_and(|s| s <= clock);
            if satisfied {
                findings.push(info(
                    rule_ids::DUE_MET,
                    &record.id,
                    format!("satisfied on {:?}; due {due}", record.satisfied_on.unwrap()),
                ));
            } else if clock > due {
                findings.push(Finding::breach(
                    rule_ids::DUE_OVERDUE,
                    &record.id,
                    format!("obligation overdue since {due} ({0} days past)", -days),
                ));
            } else if days <= i64::from(params.warn_days_before_due) {
                findings.push(warn(
                    rule_ids::DUE_UPCOMING,
                    &record.id,
                    format!("due {due}, {days} days remaining"),
                ));
            }
        }
    }
    resolutions.push(resolution);
    Ok(())
}

fn evaluate_renewal(
    record: &ObligationRecord,
    clock: NaiveDate,
    params: &PolicyParams,
    findings: &mut Vec<Finding>,
    resolutions: &mut Vec<DeadlineResolution>,
) -> Result<(), ConfigError> {
    let renewal = record
        .renewal
        .as_ref()
        .expect("validated: renewal_opt_out carries renewal terms");
    let raw_deadline = renewal.renewal_date - Days::new(u64::from(renewal.notice_days));
    let (deadline, roll_applied) =
        roll_computed(raw_deadline, record.jurisdiction.as_deref(), params)?;
    let days_remaining = (deadline - clock).num_days();
    resolutions.push(DeadlineResolution {
        obligation_id: record.id.clone(),
        kind: ResolutionKind::OptOut,
        counterparty: record.counterparty.clone(),
        base_date: Some(renewal.renewal_date),
        due_date: Some(deadline),
        days_remaining: Some(days_remaining),
        roll_applied,
        tier_min_uptime_bp: None,
        credit_cents: None,
    });
    if renewal.opted_out {
        findings.push(info(
            rule_ids::OPTOUT_EXERCISED,
            &record.id,
            format!("opt-out recorded; term ends {0}", renewal.renewal_date),
        ));
        return Ok(());
    }
    if clock >= renewal.renewal_date {
        if renewal.auto_renew {
            findings.push(Finding::breach(
                rule_ids::AUTO_RENEWED,
                &record.id,
                format!("contract auto-renewed on {0}", renewal.renewal_date),
            ));
        } else {
            findings.push(info(
                rule_ids::TERM_ENDED,
                &record.id,
                format!("term ended on {0} without renewal", renewal.renewal_date),
            ));
        }
    } else if clock > deadline {
        if renewal.auto_renew {
            findings.push(Finding::breach(
                rule_ids::OPTOUT_PASSED,
                &record.id,
                format!(
                    "opt-out window closed {deadline}; contract auto-renews on {0}",
                    renewal.renewal_date
                ),
            ));
        }
        // Without auto-renew a missed opt-out has no cost: the term simply
        // ends; no finding in the gap between deadline and term end.
    } else if days_remaining <= i64::from(params.warn_days_before_optout) {
        findings.push(warn(
            rule_ids::OPTOUT_CLOSING,
            &record.id,
            format!(
                "opt-out deadline {deadline}, {days_remaining} days remaining; renewal {0}",
                renewal.renewal_date
            ),
        ));
    } else {
        findings.push(info(
            rule_ids::OPTOUT_OPEN,
            &record.id,
            format!(
                "opt-out window open until {deadline}, {days_remaining} days remaining; renewal {0}",
                renewal.renewal_date
            ),
        ));
    }
    Ok(())
}

fn evaluate_sla(
    record: &ObligationRecord,
    clock: NaiveDate,
    params: &PolicyParams,
    findings: &mut Vec<Finding>,
    resolutions: &mut Vec<DeadlineResolution>,
) -> Result<(), ConfigError> {
    let terms = record
        .sla
        .as_ref()
        .expect("validated: sla obligation carries sla terms");
    let mut measurements: Vec<&SlaMeasurement> = record.sla_measurements.iter().collect();
    // Deterministic order regardless of register input order.
    measurements.sort_by_key(|m| (m.period_end, m.period_start));
    let mut resolution = DeadlineResolution {
        obligation_id: record.id.clone(),
        kind: ResolutionKind::Sla,
        counterparty: record.counterparty.clone(),
        base_date: None,
        due_date: None,
        days_remaining: None,
        roll_applied: false,
        tier_min_uptime_bp: None,
        credit_cents: None,
    };
    // Staleness: no measurement recent enough to cover the clock's current
    // window is a monitoring gap — fail noisy, never silently current.
    let stale = match measurements.last() {
        None => true,
        Some(latest_m) => {
            let cutoff = clock - Days::new(u64::from(terms.window_days));
            latest_m.period_end < cutoff
        }
    };
    if stale {
        findings.push(warn(
            rule_ids::SLA_STALE,
            &record.id,
            format!(
                "no SLA measurement within the last {} days of the clock",
                terms.window_days
            ),
        ));
    }
    let latest_end = measurements.last().map(|m| m.period_end);
    for m in &measurements {
        match tier_for(m.achieved_uptime_bp, &params.sla_credit_tiers) {
            None => {
                findings.push(Finding::breach(
                    rule_ids::SLA_BREACH,
                    &record.id,
                    format!(
                        "period {}..{} achieved {} bp, below every configured tier floor",
                        m.period_start, m.period_end, m.achieved_uptime_bp
                    ),
                ));
            }
            Some(tier) => {
                let credit = credit_cents(m.charges_cents, tier.credit_bp);
                if Some(m.period_end) == latest_end {
                    resolution.tier_min_uptime_bp = Some(tier.min_uptime_bp);
                    resolution.credit_cents = Some(credit);
                }
                if tier.credit_bp > 0 {
                    findings.push(warn(
                        rule_ids::SLA_CREDIT_DUE,
                        &record.id,
                        format!(
                            "period {}..{} achieved {} bp: service credit of {credit} cents due ({} bp of {} cents charges)",
                            m.period_start, m.period_end, m.achieved_uptime_bp, tier.credit_bp, m.charges_cents
                        ),
                    ));
                }
            }
        }
    }
    resolutions.push(resolution);
    Ok(())
}

/// Evaluate the register at `clock`. Runs full validation first — an invalid
/// register produces a [`ConfigError`], never findings. Output is
/// deterministic: obligations in id order, rules in fixed order per
/// obligation, findings computed against the latest version of each
/// obligation.
pub fn evaluate(
    inputs: &RegisterInputs,
    params: &PolicyParams,
    clock: NaiveDate,
) -> Result<Evaluation, ConfigError> {
    // The clock is caller input like any other; an out-of-window clock is a
    // config error, never a date-arithmetic panic.
    if clock < MIN_CLOCK || clock > MAX_DATE {
        return Err(ConfigError::InvalidParams(format!(
            "clock {clock} outside the valid window {MIN_CLOCK}..{MAX_DATE}"
        )));
    }
    validate(inputs, params)?;
    // Latest version per id: register order plus validation guarantees the
    // last record for an id is its highest version.
    let mut latest: BTreeMap<&str, &ObligationRecord> = BTreeMap::new();
    for record in &inputs.obligations {
        latest.insert(record.id.as_str(), record);
    }
    let mut findings = Vec::new();
    let mut resolutions = Vec::new();
    let mut chain = Vec::new();
    for (id, record) in &latest {
        if record.supersedes.is_some() {
            findings.push(info(
                rule_ids::REGISTER_CORRECTION,
                id,
                format!(
                    "append-only correction: version {} supersedes version {}; findings are computed against the latest version",
                    record.version,
                    record.supersedes.unwrap_or(0)
                ),
            ));
        }
        match record.obligation_type {
            ObligationType::Sla => {
                evaluate_sla(record, clock, params, &mut findings, &mut resolutions)?
            }
            ObligationType::RenewalOptOut => {
                evaluate_renewal(record, clock, params, &mut findings, &mut resolutions)?
            }
            _ => evaluate_due(
                record,
                clock,
                params,
                &latest,
                &mut chain,
                &mut findings,
                &mut resolutions,
            )?,
        }
    }
    Ok(Evaluation {
        findings,
        resolutions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Calendar, RenewalTerms, SlaTerms};

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid test date")
    }

    fn params() -> PolicyParams {
        PolicyParams {
            warn_days_before_due: 10,
            warn_days_before_optout: 14,
            business_day_roll: RollMode::None,
            calendars: BTreeMap::new(),
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

    /// Clock used by most tests: 2026-09-22, a Tuesday.
    const CLOCK: NaiveDate = match NaiveDate::from_ymd_opt(2026, 9, 22) {
        Some(d) => d,
        None => panic!("2026-09-22 is a valid date"),
    };

    fn rec(id: &str, kind: ObligationType, due: Option<DateSpec>) -> ObligationRecord {
        ObligationRecord {
            id: id.to_string(),
            version: 1,
            supersedes: None,
            counterparty: "Acme Corp".to_string(),
            obligation_type: kind,
            jurisdiction: None,
            due,
            amount_cents: None,
            satisfied_on: None,
            completed_on: None,
            renewal: None,
            sla: None,
            sla_measurements: vec![],
        }
    }

    fn run(records: Vec<ObligationRecord>, params: &PolicyParams) -> Evaluation {
        evaluate(
            &RegisterInputs {
                obligations: records,
            },
            params,
            CLOCK,
        )
        .expect("valid test register")
    }

    fn run_at(
        records: Vec<ObligationRecord>,
        params: &PolicyParams,
        clock: NaiveDate,
    ) -> Evaluation {
        evaluate(
            &RegisterInputs {
                obligations: records,
            },
            params,
            clock,
        )
        .expect("valid test register")
    }

    fn severities(ev: &Evaluation) -> Vec<(Severity, &str)> {
        ev.findings
            .iter()
            .map(|f| (f.severity, f.rule_id.as_str()))
            .collect()
    }

    // --- month clamping ---------------------------------------------------

    #[test]
    fn add_months_clamps_month_end() {
        assert_eq!(add_months(d(2026, 1, 31), 1), d(2026, 2, 28));
        assert_eq!(add_months(d(2026, 5, 31), 1), d(2026, 6, 30));
        assert_eq!(add_months(d(2026, 1, 30), 1), d(2026, 2, 28));
        assert_eq!(add_months(d(2026, 3, 15), 1), d(2026, 4, 15));
        assert_eq!(add_months(d(2026, 12, 15), 2), d(2027, 2, 15));
    }

    #[test]
    fn add_months_clamps_to_leap_day() {
        assert_eq!(add_months(d(2024, 1, 31), 1), d(2024, 2, 29));
        assert_eq!(add_months(d(2023, 1, 31), 1), d(2023, 2, 28));
    }

    // --- due-date findings -------------------------------------------------

    #[test]
    fn explicit_due_outside_warn_window_is_silent() {
        // Due 11 days out: past the 10-day warn window, nothing to escalate.
        let ev = run(
            vec![rec(
                "O-P",
                ObligationType::Payment,
                Some(DateSpec::Explicit {
                    date: d(2026, 10, 3),
                }),
            )],
            &params(),
        );
        assert!(
            ev.findings.is_empty(),
            "expected no findings, got {severities:?}",
            severities = severities(&ev)
        );
    }

    #[test]
    fn due_exactly_at_warn_boundary_is_a_warn() {
        // 2026-10-02 is exactly warn_days_before_due (10) days out.
        let ev = run(
            vec![rec(
                "O-P",
                ObligationType::Payment,
                Some(DateSpec::Explicit {
                    date: d(2026, 10, 2),
                }),
            )],
            &params(),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Warn, rule_ids::DUE_UPCOMING)]
        );
        let res = ev.resolutions.first().expect("resolution present");
        assert_eq!(res.days_remaining, Some(10));
    }

    #[test]
    fn due_on_the_clock_itself_is_a_warn_with_zero_days() {
        let ev = run_at(
            vec![rec(
                "O-P",
                ObligationType::Payment,
                Some(DateSpec::Explicit {
                    date: d(2026, 9, 22),
                }),
            )],
            &params(),
            d(2026, 9, 22),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Warn, rule_ids::DUE_UPCOMING)]
        );
        assert_eq!(ev.resolutions.first().unwrap().days_remaining, Some(0));
    }

    #[test]
    fn overdue_due_is_a_breach_counting_days_past() {
        let ev = run(
            vec![rec(
                "O-P",
                ObligationType::Payment,
                Some(DateSpec::Explicit {
                    date: d(2026, 9, 21),
                }),
            )],
            &params(),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Breach, rule_ids::DUE_OVERDUE)]
        );
        assert_eq!(ev.resolutions.first().unwrap().days_remaining, Some(-1));
        assert!(
            ev.findings[0].message.contains("1 days past"),
            "message should count days past: {}",
            ev.findings[0].message
        );
    }

    #[test]
    fn satisfied_obligation_is_info_even_when_past_due() {
        let mut satisfied = rec(
            "O-P",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 21),
            }),
        );
        satisfied.satisfied_on = Some(d(2026, 9, 22));
        let ev = run(vec![satisfied], &params());
        assert_eq!(severities(&ev), vec![(Severity::Info, rule_ids::DUE_MET)]);
        // Satisfied on the clock date, well before the due date: the MET
        // info replaces any upcoming warn. (A satisfaction dated after the
        // clock is a future event — it cannot clear today's warn; see the
        // satisfaction_on_or_after_the_clock test.)
        let mut early = rec(
            "O-Q",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 10, 2),
            }),
        );
        early.satisfied_on = Some(d(2026, 9, 22));
        let ev2 = run(vec![early], &params());
        assert_eq!(severities(&ev2), vec![(Severity::Info, rule_ids::DUE_MET)]);
    }

    #[test]
    fn satisfaction_on_or_after_the_clock_does_not_clear_overdue() {
        // A satisfaction dated after the clock is a future event: the
        // obligation is still overdue today.
        let mut future = rec(
            "O-P",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 21),
            }),
        );
        future.satisfied_on = Some(d(2026, 9, 30));
        let ev = run(vec![future], &params());
        assert_eq!(
            severities(&ev),
            vec![(Severity::Breach, rule_ids::DUE_OVERDUE)]
        );
    }

    // --- dependent dates ----------------------------------------------------

    #[test]
    fn dependent_date_chains_from_anchor_due_with_offsets() {
        let anchor = rec(
            "O-ORDER",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 2, 1),
            }),
        );
        // Ship within 1 month and 5 days of the order's due date:
        // Feb 1 + 1 month (clamped ok) = Mar 1, + 5 days = Mar 6.
        let ship = rec(
            "O-SHIP",
            ObligationType::Delivery,
            Some(DateSpec::Dependent {
                anchor_id: "O-ORDER".to_string(),
                anchor_event: AnchorEvent::Due,
                offset_days: 5,
                offset_months: 1,
            }),
        );
        let ev = run(vec![anchor, ship], &params());
        let res = &ev.resolutions[1];
        assert_eq!(res.base_date, Some(d(2026, 2, 1)));
        assert_eq!(res.due_date, Some(d(2026, 3, 6)));
        // Both dues are in the past at the clock: two overdue breaches, in
        // id order (O-ORDER before O-SHIP).
        assert_eq!(
            severities(&ev),
            vec![
                (Severity::Breach, rule_ids::DUE_OVERDUE),
                (Severity::Breach, rule_ids::DUE_OVERDUE),
            ]
        );
    }

    #[test]
    fn dependent_date_on_completed_uses_completion_date() {
        let mut anchor = rec(
            "O-SHIP",
            ObligationType::Delivery,
            Some(DateSpec::Explicit {
                date: d(2026, 3, 1),
            }),
        );
        anchor.completed_on = Some(d(2026, 3, 10));
        // Pay net-10 after actual shipment, not after the promised date.
        let pay = rec(
            "O-PAY",
            ObligationType::Payment,
            Some(DateSpec::Dependent {
                anchor_id: "O-SHIP".to_string(),
                anchor_event: AnchorEvent::Completed,
                offset_days: 10,
                offset_months: 0,
            }),
        );
        let ev = run(vec![anchor, pay], &params());
        let pay_res = ev
            .resolutions
            .iter()
            .find(|r| r.obligation_id == "O-PAY")
            .expect("pay resolution");
        assert_eq!(pay_res.base_date, Some(d(2026, 3, 10)));
        assert_eq!(pay_res.due_date, Some(d(2026, 3, 20)));
    }

    #[test]
    fn unmet_anchor_event_is_pending_info_not_a_breach() {
        let anchor = rec(
            "O-SHIP",
            ObligationType::Delivery,
            Some(DateSpec::Explicit {
                date: d(2026, 3, 1),
            }),
        );
        // completed_on not yet recorded: the pay date is pending.
        let pay = rec(
            "O-PAY",
            ObligationType::Payment,
            Some(DateSpec::Dependent {
                anchor_id: "O-SHIP".to_string(),
                anchor_event: AnchorEvent::Completed,
                offset_days: 10,
                offset_months: 0,
            }),
        );
        let ev = run(vec![anchor, pay], &params());
        let pay_res = ev
            .resolutions
            .iter()
            .find(|r| r.obligation_id == "O-PAY")
            .expect("pay resolution");
        assert_eq!(pay_res.due_date, None);
        // The pending anchor event leaves O-PAY's date unfixed (info), while
        // the anchor O-SHIP itself is overdue at the clock (breach). Both
        // findings are real; findings come in obligation-id order.
        let sev = severities(&ev);
        assert_eq!(
            sev,
            vec![
                (Severity::Info, rule_ids::DEPENDENT_PENDING),
                (Severity::Breach, rule_ids::DUE_OVERDUE),
            ]
        );
        assert_eq!(ev.findings[0].subject, "O-PAY");
        assert_eq!(ev.findings[1].subject, "O-SHIP");
    }

    // --- business-day rolling ----------------------------------------------

    fn ny_calendar() -> (String, Calendar) {
        (
            "US-NY".to_string(),
            Calendar {
                weekend: vec!["sat".to_string(), "sun".to_string()],
                holidays: vec![d(2026, 9, 28)],
            },
        )
    }

    #[test]
    fn computed_due_dates_roll_forward_over_weekend_and_holiday() {
        // Anchor due Friday 2026-09-25; +1 day lands Saturday 09-26, which
        // rolls over the weekend onto Monday 09-28 — a configured holiday —
        // and lands Tuesday 09-29.
        let mut p = params();
        p.business_day_roll = RollMode::Forward;
        let (j, cal) = ny_calendar();
        p.calendars.insert(j, cal);

        let anchor = rec(
            "O-ANCHOR",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 25),
            }),
        );
        let mut rolled = rec(
            "O-ROLL",
            ObligationType::Payment,
            Some(DateSpec::Dependent {
                anchor_id: "O-ANCHOR".to_string(),
                anchor_event: AnchorEvent::Due,
                offset_days: 1,
                offset_months: 0,
            }),
        );
        rolled.jurisdiction = Some("US-NY".to_string());
        let ev = run(vec![anchor, rolled], &p);
        let res = ev
            .resolutions
            .iter()
            .find(|r| r.obligation_id == "O-ROLL")
            .expect("rolled resolution");
        assert_eq!(res.due_date, Some(d(2026, 9, 29)));
        assert!(res.roll_applied);
    }

    #[test]
    fn roll_mode_none_honors_the_raw_deadline() {
        // Same Saturday land, but no rolling: the spec-exact date stands.
        let mut p = params();
        p.business_day_roll = RollMode::None;
        let (j, cal) = ny_calendar();
        p.calendars.insert(j, cal);

        let anchor = rec(
            "O-ANCHOR",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 25),
            }),
        );
        let mut rolled = rec(
            "O-ROLL",
            ObligationType::Payment,
            Some(DateSpec::Dependent {
                anchor_id: "O-ANCHOR".to_string(),
                anchor_event: AnchorEvent::Due,
                offset_days: 1,
                offset_months: 0,
            }),
        );
        rolled.jurisdiction = Some("US-NY".to_string());
        let ev = run(vec![anchor, rolled], &p);
        let res = ev
            .resolutions
            .iter()
            .find(|r| r.obligation_id == "O-ROLL")
            .expect("rolled resolution");
        assert_eq!(res.due_date, Some(d(2026, 9, 26)));
        assert!(!res.roll_applied);
    }

    #[test]
    fn explicit_contract_dates_are_never_rolled() {
        let mut p = params();
        p.business_day_roll = RollMode::Forward;
        let (j, cal) = ny_calendar();
        p.calendars.insert(j, cal);

        let mut a = rec(
            "O-P",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 26), // a Saturday
            }),
        );
        a.jurisdiction = Some("US-NY".to_string());
        let ev = run(vec![a], &p);
        let res = ev.resolutions.first().expect("resolution");
        assert_eq!(res.due_date, Some(d(2026, 9, 26)));
        assert!(!res.roll_applied);
    }

    // --- renewals ------------------------------------------------------------

    fn renewal_obligation(auto_renew: bool, opted_out: bool) -> ObligationRecord {
        let mut r = rec("O-RENEW", ObligationType::RenewalOptOut, None);
        r.renewal = Some(RenewalTerms {
            renewal_date: d(2027, 1, 5),
            notice_days: 45, // deadline: 2026-11-21 (a Saturday)
            auto_renew,
            opted_out,
        });
        r
    }

    #[test]
    fn renewal_notice_deadline_is_exact_and_reported() {
        // 2027-01-05 minus 45 days = 2026-11-21 exactly.
        let ev = run(vec![renewal_obligation(true, false)], &params());
        let res = ev.resolutions.first().expect("resolution");
        assert_eq!(res.due_date, Some(d(2026, 11, 21)));
        assert_eq!(res.base_date, Some(d(2027, 1, 5)));
        // Open window at clock 2026-10-01: 51 days remaining, above the 14-day
        // warn window.
        let ev_open = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2026, 10, 1),
        );
        assert_eq!(
            severities(&ev_open),
            vec![(Severity::Info, rule_ids::OPTOUT_OPEN)]
        );
        assert_eq!(
            ev_open.resolutions.first().unwrap().days_remaining,
            Some(51)
        );
    }

    #[test]
    fn renewal_deadline_rolls_forward_per_jurisdiction() {
        let mut p = params();
        p.business_day_roll = RollMode::Forward;
        let (j, cal) = ny_calendar();
        p.calendars.insert(j, cal);
        let mut r = renewal_obligation(true, false);
        r.jurisdiction = Some("US-NY".to_string());
        let ev = run(vec![r], &p);
        let res = ev.resolutions.first().expect("resolution");
        // Saturday 2026-11-21 rolls to Monday 2026-11-23.
        assert_eq!(res.due_date, Some(d(2026, 11, 23)));
        assert!(res.roll_applied);
    }

    #[test]
    fn renewal_window_open_at_the_deadline_itself() {
        // Clock on the deadline date: the window is still open (due today).
        let ev = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2026, 11, 21),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Warn, rule_ids::OPTOUT_CLOSING)]
        );
        assert_eq!(ev.resolutions.first().unwrap().days_remaining, Some(0));
    }

    #[test]
    fn renewal_deadline_crossed_is_a_breach_when_auto_renew() {
        let ev = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2026, 11, 28),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Breach, rule_ids::OPTOUT_PASSED)]
        );
        // Breach findings demand human signoff.
        assert!(ev.findings[0].requires_signoff);
    }

    #[test]
    fn missed_optout_without_auto_renew_is_not_a_breach() {
        // Without auto-renew a missed opt-out simply lets the term end.
        let ev = run_at(
            vec![renewal_obligation(false, false)],
            &params(),
            d(2026, 11, 28),
        );
        assert!(
            ev.findings.is_empty(),
            "{severities:?}",
            severities = severities(&ev)
        );
    }

    #[test]
    fn renewed_contract_is_a_breach_unless_opt_out_is_on_file() {
        // At/after the renewal date with auto-renew and no opt-out: renewed.
        let ev = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2027, 1, 5),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Breach, rule_ids::AUTO_RENEWED)]
        );
        // Same date with an opt-out on file: clean info.
        let ev2 = run_at(
            vec![renewal_obligation(true, true)],
            &params(),
            d(2027, 1, 5),
        );
        assert_eq!(
            severities(&ev2),
            vec![(Severity::Info, rule_ids::OPTOUT_EXERCISED)]
        );
        // Without auto-renew, the term just ends.
        let ev3 = run_at(
            vec![renewal_obligation(false, false)],
            &params(),
            d(2027, 1, 5),
        );
        assert_eq!(
            severities(&ev3),
            vec![(Severity::Info, rule_ids::TERM_ENDED)]
        );
    }

    #[test]
    fn warn_window_at_optout_boundary() {
        // 14 days before the 2026-11-21 deadline is 2026-11-07: warn.
        let ev = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2026, 11, 7),
        );
        assert_eq!(
            severities(&ev),
            vec![(Severity::Warn, rule_ids::OPTOUT_CLOSING)]
        );
        // 15 days before (2026-11-06): still open, above the warn window.
        let ev2 = run_at(
            vec![renewal_obligation(true, false)],
            &params(),
            d(2026, 11, 6),
        );
        assert_eq!(
            severities(&ev2),
            vec![(Severity::Info, rule_ids::OPTOUT_OPEN)]
        );
    }

    // --- SLA credits ----------------------------------------------------------

    fn sla_obligation(measurements: Vec<SlaMeasurement>) -> ObligationRecord {
        let mut s = rec("O-SLA", ObligationType::Sla, None);
        s.sla = Some(SlaTerms { window_days: 90 });
        s.sla_measurements = measurements;
        s
    }

    fn measurement(
        start: NaiveDate,
        end: NaiveDate,
        uptime_bp: u64,
        charges: i128,
    ) -> SlaMeasurement {
        SlaMeasurement {
            period_start: start,
            period_end: end,
            achieved_uptime_bp: uptime_bp,
            charges_cents: charges,
        }
    }

    #[test]
    fn sla_measurement_below_every_tier_is_a_breach() {
        let s = sla_obligation(vec![measurement(
            d(2026, 4, 1),
            d(2026, 6, 30),
            9850,
            50_000_000,
        )]);
        let ev = run(vec![s], &params());
        assert_eq!(
            severities(&ev),
            vec![(Severity::Breach, rule_ids::SLA_BREACH)]
        );
        assert!(ev.findings[0].requires_signoff);
    }

    #[test]
    fn sla_tier_boundaries_pick_the_descending_table() {
        // 9950 bp sits in the 9900 tier (5% credit); 9990 exactly at the top
        // tier floor picks the 1% credit tier.
        let s = sla_obligation(vec![measurement(
            d(2026, 4, 1),
            d(2026, 6, 30),
            9950,
            50_000_000,
        )]);
        let ev = run(vec![s], &params());
        assert_eq!(
            severities(&ev),
            vec![(Severity::Warn, rule_ids::SLA_CREDIT_DUE)]
        );
        let res = ev.resolutions.first().expect("resolution");
        assert_eq!(res.tier_min_uptime_bp, Some(9900));
        // credit = 50_000_000 * 500 / 10_000 = 2_500_000 cents.
        assert_eq!(res.credit_cents, Some(2_500_000));

        let s2 = sla_obligation(vec![measurement(
            d(2026, 4, 1),
            d(2026, 6, 30),
            9990,
            50_000_000,
        )]);
        let ev2 = run(vec![s2], &params());
        let res2 = ev2.resolutions.first().expect("resolution");
        assert_eq!(res2.tier_min_uptime_bp, Some(9990));
        // credit = 50_000_000 * 100 / 10_000 = 500_000 cents.
        assert_eq!(res2.credit_cents, Some(500_000));
    }

    #[test]
    fn sla_credit_truncates_fractional_cents() {
        // 9_999_999 * 500 / 10_000 = 499_999.95 → 499_999 cents, floored.
        assert_eq!(credit_cents(9_999_999, 500), 499_999);
        assert_eq!(credit_cents(50_000_000, 500), 2_500_000);
        assert_eq!(credit_cents(0, 500), 0);
    }

    #[test]
    fn stale_measurement_is_a_warn() {
        // window 90 days: a measurement ending 2026-04-30 is stale at a
        // 2026-09-22 clock (cutoff 2026-06-24).
        let s = sla_obligation(vec![measurement(
            d(2026, 4, 1),
            d(2026, 4, 30),
            9950,
            50_000_000,
        )]);
        let ev = run(vec![s], &params());
        assert!(severities(&ev).contains(&(Severity::Warn, rule_ids::SLA_STALE)));

        // A recent measurement is not stale.
        let s2 = sla_obligation(vec![measurement(
            d(2026, 8, 1),
            d(2026, 9, 15),
            9950,
            50_000_000,
        )]);
        let ev2 = run(vec![s2], &params());
        assert!(!severities(&ev2).contains(&(Severity::Warn, rule_ids::SLA_STALE)));

        // No measurements at all: stale by definition.
        let ev3 = run(vec![sla_obligation(vec![])], &params());
        assert!(severities(&ev3).contains(&(Severity::Warn, rule_ids::SLA_STALE)));
    }

    #[test]
    fn latest_measurement_drives_the_resolution_snapshot() {
        let s = sla_obligation(vec![
            measurement(d(2026, 2, 1), d(2026, 3, 31), 9990, 10_000_000),
            measurement(d(2026, 4, 1), d(2026, 6, 30), 9950, 50_000_000),
        ]);
        let ev = run(vec![s], &params());
        let res = ev.resolutions.first().expect("resolution");
        // Latest period end (2026-06-30) picks its tier and credit.
        assert_eq!(res.tier_min_uptime_bp, Some(9900));
        assert_eq!(res.credit_cents, Some(2_500_000));
    }

    // --- corrections ------------------------------------------------------------

    #[test]
    fn findings_use_the_latest_version_of_a_corrected_obligation() {
        let v1 = rec(
            "O-PAY",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 9, 20), // overdue at the clock
            }),
        );
        let mut v2 = rec(
            "O-PAY",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 10, 20), // corrected to the future
            }),
        );
        v2.version = 2;
        v2.supersedes = Some(1);
        // v1 alone breaches.
        let ev1 = run(vec![v1.clone()], &params());
        assert_eq!(
            severities(&ev1),
            vec![(Severity::Breach, rule_ids::DUE_OVERDUE)]
        );
        // With the correction registered, the evaluation uses v2: no breach,
        // and a correction info finding is recorded.
        let ev2 = run(vec![v1, v2], &params());
        assert_eq!(
            severities(&ev2),
            vec![(Severity::Info, rule_ids::REGISTER_CORRECTION)]
        );
        let res = ev2
            .resolutions
            .iter()
            .find(|r| r.obligation_id == "O-PAY")
            .expect("resolution");
        assert_eq!(res.due_date, Some(d(2026, 10, 20)));
    }

    // --- fail-closed behavior ---------------------------------------------------

    #[test]
    fn out_of_window_clock_is_a_config_error_not_a_panic() {
        let inputs = RegisterInputs {
            obligations: vec![rec(
                "O-P",
                ObligationType::Payment,
                Some(DateSpec::Explicit {
                    date: d(2026, 9, 22),
                }),
            )],
        };
        assert!(evaluate(&inputs, &params(), d(1969, 12, 31)).is_err());
        assert!(evaluate(&inputs, &params(), d(3000, 1, 1)).is_err());
    }

    #[test]
    fn evaluation_is_deterministic_regardless_of_register_order() {
        let a = rec(
            "O-A",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 10, 1),
            }),
        );
        let b = rec(
            "O-B",
            ObligationType::Payment,
            Some(DateSpec::Explicit {
                date: d(2026, 10, 2),
            }),
        );
        let ev1 = run(vec![a.clone(), b.clone()], &params());
        let ev2 = run(vec![b, a], &params());
        // Resolutions come out in id order; findings in rule order.
        let ids1: Vec<&str> = ev1
            .resolutions
            .iter()
            .map(|r| r.obligation_id.as_str())
            .collect();
        let ids2: Vec<&str> = ev2
            .resolutions
            .iter()
            .map(|r| r.obligation_id.as_str())
            .collect();
        assert_eq!(ids1, ids2);
        assert_eq!(severities(&ev1), severities(&ev2));
    }
}
