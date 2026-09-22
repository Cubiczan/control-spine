//! Deterministic gross-to-net engine for the payroll control spine.
//!
//! Purity contract: no clock (the chrono `clock` feature is disabled at the
//! dependency level), no filesystem, no network, no randomness. Time is
//! caller input — the run's period dates; per-employee mid-period start and
//! end dates. Money is integer cents (i128); rates are micro-percent scaled
//! integers; every money division rounds half-up. Arithmetic that could
//! overflow returns [`PayrollError::ArithmeticOverflow`] instead of
//! panicking — fail-closed on absurd inputs.
//!
//! Wage-base mechanics (Section 125 and 401(k) treatment, SS cap,
//! additional Medicare threshold) are documented in the crate README and
//! asserted by the test anchors.

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use spine::{Finding, Severity};

use crate::config::{Bracket, PayrollConfig};

pub const RULE_SUMMARY: &str = "PAY-SUMMARY";
pub const RULE_RUN_SUMMARY: &str = "PAY-RUN-SUMMARY";
pub const RULE_REGISTER_VARIANCE: &str = "PAY-REGISTER-VARIANCE";
pub const RULE_NEGATIVE_NET: &str = "PAY-NEG-NET";
pub const RULE_TAX_YEAR_MISMATCH: &str = "PAY-TAX-YEAR";

/// Rates are micro-percent: 6_200_000 = 6.2%.
pub const RATE_SCALE: i128 = 1_000_000;
/// Divisor converting `cents * micro_percent` into cents.
pub const RATE_DENOM: i128 = RATE_SCALE * 100;
/// Ceiling on any configured rate: 100%.
pub const RATE_CAP: i128 = RATE_DENOM;

// ---------------------------------------------------------------------------
// Deterministic arithmetic helpers
// ---------------------------------------------------------------------------

/// Half-up division of a non-negative amount by a positive divisor — the
/// family rounding rule that replaces floats: `(2n + d) / (2d)` floors
/// `n/d + 1/2`.
pub fn half_up_div(n: i128, d: i128) -> i128 {
    debug_assert!(n >= 0, "half_up_div is defined for non-negative amounts");
    debug_assert!(d > 0, "half_up_div needs a positive divisor");
    (2 * n + d) / (2 * d)
}

fn half_up_div_checked(n: i128, d: i128, what: &str) -> Result<i128, PayrollError> {
    if d <= 0 || n < 0 {
        return Err(PayrollError::ArithmeticOverflow(what.to_string()));
    }
    // Same (2n + d) / (2d) rule as half_up_div — the numerator gains the
    // HALF divisor, not the full one (adding 2d rounds every exact quotient
    // up by one).
    let two_n = n
        .checked_mul(2)
        .ok_or_else(|| PayrollError::ArithmeticOverflow(what.to_string()))?;
    let numerator = two_n
        .checked_add(d)
        .ok_or_else(|| PayrollError::ArithmeticOverflow(what.to_string()))?;
    let two_d = d
        .checked_mul(2)
        .ok_or_else(|| PayrollError::ArithmeticOverflow(what.to_string()))?;
    numerator
        .checked_div(two_d)
        .ok_or_else(|| PayrollError::ArithmeticOverflow(what.to_string()))
}

/// Tax in cents on `taxable_cents` at `rate_micro` micro-percent, rounded
/// half-up per line. Zero on a zero base — never a negative tax.
pub fn tax_at(taxable_cents: i128, rate_micro: i128) -> Result<i128, PayrollError> {
    if taxable_cents <= 0 || rate_micro <= 0 {
        return Ok(0);
    }
    let scaled = taxable_cents
        .checked_mul(rate_micro)
        .ok_or_else(|| PayrollError::ArithmeticOverflow("tax computation".to_string()))?;
    Ok(half_up_div(scaled, RATE_DENOM))
}

/// Portion of `current` wages that still falls under `wage_base` after `ytd`
/// year-to-date wages: the cap-crossing rule — only the excess above the
/// base is taxable. Saturation keeps absurd inputs deterministic instead of
/// panicking.
pub fn capped_taxable(ytd: i128, current: i128, wage_base: i128) -> i128 {
    let running = ytd.saturating_add(current);
    (wage_base.min(running) - wage_base.min(ytd)).max(0)
}

fn add_cents(a: i128, b: i128, what: &str) -> Result<i128, PayrollError> {
    a.checked_add(b)
        .ok_or_else(|| PayrollError::ArithmeticOverflow(what.to_string()))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayrollError {
    #[error("invalid period: {0}")]
    InvalidPeriod(String),
    #[error("invalid date in field '{field}': '{value}' (expected YYYY-MM-DD)")]
    InvalidDate { field: &'static str, value: String },
    #[error("employee '{employee_id}': field '{field}' must not be negative")]
    NegativeAmount {
        employee_id: String,
        field: &'static str,
    },
    #[error("invalid employee: employee_id must not be empty")]
    InvalidEmployee,
    #[error("no SUTA schedule is configured for state '{state}' (employee '{employee_id}')")]
    MissingSutaSchedule { employee_id: String, state: String },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("arithmetic overflow while computing {0}")]
    ArithmeticOverflow(String),
    #[error("payroll run carries no employees — refusing to emit an empty evidence pack")]
    EmptyRun,
    #[error("serialization: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// Run inputs (run-specific; the config tables are the stable rule tables)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarKind {
    /// 24 periods a year: 1st–15th and 16th–end of month.
    SemiMonthly,
    /// 26 periods a year: 14-day periods.
    Biweekly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayrollInput {
    pub period: PeriodInput,
    pub employees: Vec<EmployeeInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeriodInput {
    pub calendar: CalendarKind,
    /// Period start, `YYYY-MM-DD`, caller-supplied.
    pub start: String,
    /// Period end, `YYYY-MM-DD`, inclusive.
    pub end: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmployeeInput {
    pub employee_id: String,
    pub filing_status: crate::config::FilingStatus,
    /// Work state — must exist in the config's SUTA schedule.
    pub state: String,
    /// Annual salary in cents; the period gross is derived from it.
    pub annual_salary_cents: i128,
    /// Mid-period hire date (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    /// Mid-period separation date (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    /// Employer-observed YTD Social Security taxable wages, cents.
    #[serde(default)]
    pub ytd_ss_taxable_cents: i128,
    /// Employer-observed YTD Medicare taxable wages, cents.
    #[serde(default)]
    pub ytd_medicare_taxable_cents: i128,
    /// Employer-observed YTD FUTA-taxable wages, cents.
    #[serde(default)]
    pub employer_ytd_futa_cents: i128,
    /// Employer-observed YTD SUTA-taxable wages (this state), cents.
    #[serde(default)]
    pub employer_ytd_suta_cents: i128,
    /// Section 125 cafeteria-plan deduction for the period, cents.
    #[serde(default)]
    pub section125_cents: i128,
    /// 401(k) deferral for the period, cents (pre/post tax per config).
    #[serde(default)]
    pub retirement_401k_cents: i128,
    /// Net pay per the payroll provider register, for variance detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_net_cents: Option<i128>,
}

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

struct ValidatedPeriod {
    start: NaiveDate,
    end: NaiveDate,
    calendar: CalendarKind,
}

impl ValidatedPeriod {
    fn total_days(&self) -> i64 {
        (self.end - self.start).num_days() + 1
    }

    fn periods_per_year(&self) -> i128 {
        match self.calendar {
            CalendarKind::SemiMonthly => 24,
            CalendarKind::Biweekly => 26,
        }
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    }
}

fn parse_date(field: &'static str, value: &str) -> Result<NaiveDate, PayrollError> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| PayrollError::InvalidDate {
        field,
        value: value.to_string(),
    })
}

fn validate_period(period: &PeriodInput) -> Result<ValidatedPeriod, PayrollError> {
    let start = parse_date("period.start", &period.start)?;
    let end = parse_date("period.end", &period.end)?;
    if end < start {
        return Err(PayrollError::InvalidPeriod(format!(
            "period end {end} precedes period start {start}"
        )));
    }
    let same_month = start.year() == end.year() && start.month() == end.month();
    let shape_ok = match period.calendar {
        CalendarKind::SemiMonthly => {
            (same_month && start.day() == 1 && end.day() == 15)
                || (same_month
                    && start.day() == 16
                    && end.day() == days_in_month(end.year(), end.month()))
        }
        CalendarKind::Biweekly => (end - start).num_days() == 13,
    };
    if !shape_ok {
        return Err(PayrollError::InvalidPeriod(match period.calendar {
            CalendarKind::SemiMonthly => {
                "semi-monthly periods must be the 1st-15th or the 16th through end of month"
                    .to_string()
            }
            CalendarKind::Biweekly => {
                "biweekly periods must span exactly 14 calendar days (start..=end)".to_string()
            }
        }));
    }
    Ok(ValidatedPeriod {
        start,
        end,
        calendar: period.calendar,
    })
}

fn validate_employee(e: &EmployeeInput, config: &PayrollConfig) -> Result<(), PayrollError> {
    if e.employee_id.trim().is_empty() {
        return Err(PayrollError::InvalidEmployee);
    }
    let fields: [(&'static str, i128); 7] = [
        ("annual_salary_cents", e.annual_salary_cents),
        ("ytd_ss_taxable_cents", e.ytd_ss_taxable_cents),
        ("ytd_medicare_taxable_cents", e.ytd_medicare_taxable_cents),
        ("employer_ytd_futa_cents", e.employer_ytd_futa_cents),
        ("employer_ytd_suta_cents", e.employer_ytd_suta_cents),
        ("section125_cents", e.section125_cents),
        ("retirement_401k_cents", e.retirement_401k_cents),
    ];
    for (field, value) in fields {
        if value < 0 {
            return Err(PayrollError::NegativeAmount {
                employee_id: e.employee_id.clone(),
                field,
            });
        }
    }
    if let Some(p) = e.provider_net_cents {
        if p < 0 {
            return Err(PayrollError::NegativeAmount {
                employee_id: e.employee_id.clone(),
                field: "provider_net_cents",
            });
        }
    }
    if let Some(s) = &e.start_date {
        parse_date("employee.start_date", s)?;
    }
    if let Some(s) = &e.end_date {
        parse_date("employee.end_date", s)?;
    }
    if !config.employer.suta.contains_key(e.state.as_str()) {
        return Err(PayrollError::MissingSutaSchedule {
            employee_id: e.employee_id.clone(),
            state: e.state.clone(),
        });
    }
    Ok(())
}

/// The computed gross-to-net breakdown for one employee — the numbers the
/// findings and the `explain` output report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmployeeSummary {
    pub employee_id: String,
    pub calendar: CalendarKind,
    pub period_days: i64,
    pub employed_days: i64,
    pub gross_cents: i128,
    pub section125_cents: i128,
    pub retirement_401k_cents: i128,
    pub retirement_401k_pre_tax: bool,
    pub fit_taxable_cents: i128,
    pub fit_cents: i128,
    /// Social Security taxable wages after the wage-base cap.
    pub ss_taxable_cents: i128,
    pub ss_cents: i128,
    pub medicare_taxable_cents: i128,
    pub medicare_cents: i128,
    pub additional_medicare_taxable_cents: i128,
    pub additional_medicare_cents: i128,
    pub net_cents: i128,
    pub register_net_cents: Option<i128>,
    /// computed net − provider register (signed).
    pub register_variance_cents: Option<i128>,
    pub employer_fica_match_cents: i128,
    pub employer_futa_cents: i128,
    pub employer_suta_cents: i128,
}

#[derive(Debug, Clone)]
pub struct PayrollOutcome {
    pub summaries: Vec<EmployeeSummary>,
    /// spine::Finding intentionally carries no PartialEq — compare findings
    /// field by field (see pack::findings_match).
    pub findings: Vec<Finding>,
}

/// Annual federal income tax on annualized wages over a progressive bracket
/// table: marginal, bracket by bracket. The bracket table must be validated
/// (starts at zero, strictly ascending) — `PayrollConfig::validate` enforces.
pub fn fit_annual_tax(
    annualized_wages_cents: i128,
    brackets: &[Bracket],
) -> Result<i128, PayrollError> {
    let mut tax = 0i128;
    for (i, bracket) in brackets.iter().enumerate() {
        if annualized_wages_cents <= bracket.lower_cents {
            break;
        }
        let upper = brackets
            .get(i + 1)
            .map(|next| next.lower_cents)
            .unwrap_or(i128::MAX);
        let span = annualized_wages_cents.min(upper) - bracket.lower_cents;
        tax = add_cents(tax, tax_at(span, bracket.rate_micro)?, "FIT brackets")?;
    }
    Ok(tax)
}

fn compute_employee(
    e: &EmployeeInput,
    config: &PayrollConfig,
    period: &ValidatedPeriod,
) -> Result<EmployeeSummary, PayrollError> {
    let total_days = period.total_days();
    let employed_days = {
        let lo = match &e.start_date {
            Some(s) => parse_date("employee.start_date", s)?,
            None => period.start,
        };
        let hi = match &e.end_date {
            Some(s) => parse_date("employee.end_date", s)?,
            None => period.end,
        };
        let lo = lo.max(period.start);
        let hi = hi.min(period.end);
        if lo > hi {
            0
        } else {
            (hi - lo).num_days() + 1
        }
    };
    let ppy = period.periods_per_year();

    // Gross: full-period salary rounded half-up, then calendar-day proration
    // rounded half-up again — two deterministic line roundings.
    let full_period_gross = half_up_div_checked(e.annual_salary_cents, ppy, "salary proration")?;
    let gross = half_up_div_checked(
        full_period_gross
            .checked_mul(i128::from(employed_days))
            .ok_or_else(|| PayrollError::ArithmeticOverflow("salary proration".to_string()))?,
        i128::from(total_days),
        "salary proration",
    )?;

    // Wage bases. Section 125 reduces both FIT and FICA/Medicare wages; a
    // pre-tax 401(k) reduces FIT wages only (deferrals stay FICA-taxable).
    let pre_tax_401k = config.retirement_401k_pre_tax;
    let gross_minus_125 = (gross - e.section125_cents).max(0);
    let fit_taxable = (gross_minus_125
        - if pre_tax_401k {
            e.retirement_401k_cents
        } else {
            0
        })
    .max(0);
    let ss_wages = gross_minus_125;
    let medi_wages = gross_minus_125;

    // Federal income tax: annualize, apply marginal brackets, de-annualize.
    let annualized_wages = fit_taxable
        .checked_mul(ppy)
        .ok_or_else(|| PayrollError::ArithmeticOverflow("FIT annualization".to_string()))?;
    let annual_tax = fit_annual_tax(annualized_wages, config.brackets.table(e.filing_status))?;
    let fit = half_up_div_checked(annual_tax, ppy, "FIT de-annualization")?;

    // Social Security: wage-base cap on YTD-cumulative wages — when the cap
    // crosses mid-period, only the excess above the cap is taxed.
    let ss_taxable = capped_taxable(
        e.ytd_ss_taxable_cents,
        ss_wages,
        config.fica.ss_wage_base_cents,
    );
    let ss = tax_at(ss_taxable, config.fica.ss_rate_micro)?;

    // Medicare: no cap; the additional rate applies only to the portion of
    // this period's wages above the YTD threshold.
    let medicare = tax_at(medi_wages, config.fica.medicare_rate_micro)?;
    let medi_running = e.ytd_medicare_taxable_cents.saturating_add(medi_wages);
    let excess_after = (medi_running - config.fica.additional_medicare_threshold_cents).max(0);
    let excess_before =
        (e.ytd_medicare_taxable_cents - config.fica.additional_medicare_threshold_cents).max(0);
    let additional_medicare_taxable = excess_after - excess_before;
    let additional_medicare = tax_at(
        additional_medicare_taxable,
        config.fica.additional_medicare_rate_micro,
    )?;

    // Employer side. The FICA match covers regular SS + Medicare only (the
    // additional Medicare rate is employee-only, not matched). FUTA uses the
    // credit-reduced rate on gross wages against its wage base; SUTA uses
    // the per-state schedule.
    let fica_match = add_cents(ss, medicare, "employer FICA match")?;
    let futa_effective_rate =
        config.employer.futa_rate_micro - config.employer.futa_credit_rate_micro;
    let futa_taxable = capped_taxable(
        e.employer_ytd_futa_cents,
        gross,
        config.employer.futa_wage_base_cents,
    );
    let futa = tax_at(futa_taxable, futa_effective_rate)?;
    let suta_schedule =
        config
            .employer
            .suta
            .get(&e.state)
            .ok_or_else(|| PayrollError::MissingSutaSchedule {
                employee_id: e.employee_id.clone(),
                state: e.state.clone(),
            })?;
    let suta_taxable = capped_taxable(
        e.employer_ytd_suta_cents,
        gross,
        suta_schedule.wage_base_cents,
    );
    let suta = tax_at(suta_taxable, suta_schedule.rate_micro)?;

    // Net pay: gross minus employee withholdings minus employee deductions.
    let employee_withholdings = add_cents(
        add_cents(add_cents(fit, ss, "net pay")?, medicare, "net pay")?,
        additional_medicare,
        "net pay",
    )?;
    let employee_deductions = add_cents(e.section125_cents, e.retirement_401k_cents, "net pay")?;
    let net = gross
        .checked_sub(employee_withholdings)
        .and_then(|v| v.checked_sub(employee_deductions))
        .ok_or_else(|| PayrollError::ArithmeticOverflow("net pay".to_string()))?;

    // Register variance: computed net vs the provider register.
    let register_variance = match e.provider_net_cents {
        Some(p) => Some(
            net.checked_sub(p)
                .ok_or_else(|| PayrollError::ArithmeticOverflow("register variance".to_string()))?,
        ),
        None => None,
    };

    Ok(EmployeeSummary {
        employee_id: e.employee_id.clone(),
        calendar: period.calendar,
        period_days: total_days,
        employed_days,
        gross_cents: gross,
        section125_cents: e.section125_cents,
        retirement_401k_cents: e.retirement_401k_cents,
        retirement_401k_pre_tax: pre_tax_401k,
        fit_taxable_cents: fit_taxable,
        fit_cents: fit,
        ss_taxable_cents: ss_taxable,
        ss_cents: ss,
        medicare_taxable_cents: medi_wages,
        medicare_cents: medicare,
        additional_medicare_taxable_cents: additional_medicare_taxable,
        additional_medicare_cents: additional_medicare,
        net_cents: net,
        register_net_cents: e.provider_net_cents,
        register_variance_cents: register_variance,
        employer_fica_match_cents: fica_match,
        employer_futa_cents: futa,
        employer_suta_cents: suta,
    })
}

/// Recompute gross-to-net for the whole run: validate config and inputs
/// fail-closed, compute every employee, and raise the run's findings.
///
/// Findings, in deterministic order: one `PAY-SUMMARY` (Info) per employee
/// carrying the computed breakdown; `PAY-REGISTER-VARIANCE` (Warn) where the
/// computed net differs from the provider register beyond tolerance;
/// `PAY-NEG-NET` (Breach) where net pay after deductions is negative — the
/// run is blocked pending a human signoff; and one `PAY-RUN-SUMMARY` (Info).
pub fn compute(
    inputs: &PayrollInput,
    config: &PayrollConfig,
) -> Result<PayrollOutcome, PayrollError> {
    config.validate()?;
    if inputs.employees.is_empty() {
        return Err(PayrollError::EmptyRun);
    }
    let period = validate_period(&inputs.period)?;

    let mut summaries = Vec::with_capacity(inputs.employees.len());
    let mut findings = Vec::new();

    // Declared tax-year staleness: tables are operator-maintained seed data
    // and the engine cannot know current law, so a run whose period starts in
    // a different year than the config declares warns instead of refusing.
    if let Some(tax_year) = config.valid_for_tax_year {
        let start_year = parse_date("period.start", &inputs.period.start)?.year();
        if start_year != i32::from(tax_year) {
            findings.push(Finding {
                rule_id: RULE_TAX_YEAR_MISMATCH.to_string(),
                severity: Severity::Warn,
                subject: format!("period:{}", inputs.period.start),
                message: format!(
                    "config declares valid_for_tax_year {tax_year}; period starts {start} — update the seed rate tables if the declared year is stale",
                    start = inputs.period.start
                ),
                requires_signoff: false,
            });
        }
    }

    let mut total_gross = 0i128;
    let mut total_withholdings = 0i128;
    let mut total_net = 0i128;
    let mut total_employer = 0i128;

    for e in &inputs.employees {
        validate_employee(e, config)?;
        let s = compute_employee(e, config, &period)?;

        // Per-employee evidence: the computed breakdown as an Info finding —
        // the pack's record of what the run computed.
        let mode = if s.retirement_401k_pre_tax {
            "pre-tax"
        } else {
            "post-tax"
        };
        findings.push(Finding {
            rule_id: RULE_SUMMARY.to_string(),
            severity: Severity::Info,
            subject: s.employee_id.clone(),
            message: format!(
                "gross {gross}c | fit {fit}c | ss {ss}c | medicare {medicare}c | additional medicare {addl}c | section125 {s125}c | 401k {k401}c ({mode}) | net {net}c | employer fica match {match_c}c futa {futa}c suta {suta}c",
                gross = s.gross_cents,
                fit = s.fit_cents,
                ss = s.ss_cents,
                medicare = s.medicare_cents,
                addl = s.additional_medicare_cents,
                s125 = s.section125_cents,
                k401 = s.retirement_401k_cents,
                net = s.net_cents,
                match_c = s.employer_fica_match_cents,
                futa = s.employer_futa_cents,
                suta = s.employer_suta_cents,
            ),
            requires_signoff: false,
        });

        // Register variance flag: any difference beyond tolerance, in either
        // direction — a one-cent variance is a flag, not a rounding artifact
        // to wave through.
        if let Some(variance) = s.register_variance_cents {
            let magnitude = variance
                .checked_abs()
                .ok_or_else(|| PayrollError::ArithmeticOverflow("register variance".to_string()))?;
            if magnitude > config.register_tolerance_cents {
                findings.push(Finding {
                    rule_id: RULE_REGISTER_VARIANCE.to_string(),
                    severity: Severity::Warn,
                    subject: s.employee_id.clone(),
                    message: format!(
                        "computed net {net}c differs from provider register {provider}c by {variance}c (tolerance {tolerance}c)",
                        net = s.net_cents,
                        provider = s.register_net_cents.unwrap_or_default(),
                        tolerance = config.register_tolerance_cents,
                    ),
                    requires_signoff: false,
                });
            }
        }

        // Negative net pay blocks the run: breach severity, resolvable only
        // by a human signoff receipt naming this employee.
        if s.net_cents < 0 {
            findings.push(Finding::breach(
                RULE_NEGATIVE_NET,
                s.employee_id.clone(),
                format!(
                    "net pay after deductions is negative ({net}c) — payroll run blocked pending signoff; the engine does not model garnishments or other provider-side deductions, so confirm the actual cause before re-running",
                    net = s.net_cents
                ),
            ));
        }

        total_gross = add_cents(total_gross, s.gross_cents, "run totals")?;
        total_withholdings = add_cents(
            total_withholdings,
            add_cents(
                add_cents(s.fit_cents, s.ss_cents, "run totals")?,
                add_cents(s.medicare_cents, s.additional_medicare_cents, "run totals")?,
                "run totals",
            )?,
            "run totals",
        )?;
        total_net = add_cents(total_net, s.net_cents, "run totals")?;
        total_employer = add_cents(
            total_employer,
            add_cents(
                add_cents(
                    s.employer_fica_match_cents,
                    s.employer_futa_cents,
                    "run totals",
                )?,
                s.employer_suta_cents,
                "run totals",
            )?,
            "run totals",
        )?;
        summaries.push(s);
    }

    findings.push(Finding {
        rule_id: RULE_RUN_SUMMARY.to_string(),
        severity: Severity::Info,
        subject: "run".to_string(),
        message: format!(
            "employees {n} | gross {total_gross}c | employee withholdings {total_withholdings}c | net {total_net}c | employer taxes {total_employer}c",
            n = summaries.len(),
        ),
        requires_signoff: false,
    });

    Ok(PayrollOutcome {
        summaries,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_up_rounds_midpoints_up() {
        assert_eq!(half_up_div(3, 2), 2); // 1.5 -> 2
        assert_eq!(half_up_div(5, 2), 3); // 2.5 -> 3
        assert_eq!(half_up_div(4, 2), 2); // exact
        assert_eq!(half_up_div(1, 3), 0); // 0.33 -> 0
        assert_eq!(half_up_div(3, 3), 1); // exact
    }

    #[test]
    fn half_up_div_checked_matches_half_up_div() {
        // Regression: the checked variant must use the same (2n + d) / (2d)
        // rule — an earlier version added the full divisor, rounding every
        // exact quotient up by one (12,000,000/24 -> 500,001).
        assert_eq!(half_up_div_checked(12_000_000, 24, "t").unwrap(), 500_000);
        assert_eq!(half_up_div_checked(7_500_000, 15, "t").unwrap(), 500_000);
        assert_eq!(half_up_div_checked(3, 2, "t").unwrap(), 2); // midpoint up
        assert_eq!(half_up_div_checked(5, 2, "t").unwrap(), 3);
        assert!(half_up_div_checked(1, 0, "t").is_err());
        assert!(half_up_div_checked(-1, 2, "t").is_err());
    }

    #[test]
    fn tax_at_rounds_half_up_in_cents() {
        // 400 cents at 6.2% = 24.8 cents -> 25 (truncation would give 24).
        assert_eq!(tax_at(400, 6_200_000).unwrap(), 25);
        assert_eq!(tax_at(0, 6_200_000).unwrap(), 0);
        assert_eq!(tax_at(100_000, 6_200_000).unwrap(), 6_200);
    }

    #[test]
    fn capped_taxable_taxes_only_the_excess_above_the_base() {
        // $168,600 cap; $165,000 YTD; $5,000 this period -> $3,600 taxable.
        assert_eq!(capped_taxable(16_500_000, 500_000, 16_860_000), 360_000);
        assert_eq!(capped_taxable(16_860_000, 500_000, 16_860_000), 0);
        assert_eq!(capped_taxable(0, 500_000, 16_860_000), 500_000);
    }
}
