//! Deterministic covenant evaluation. Pure functions over explicit inputs —
//! no clock, no filesystem, no network, no randomness.

use spine::{Finding, Severity};

use crate::config::{Basis, CovenantConfig, CovenantKind, CovenantRule, LTM_QUARTERS};
use crate::input::{Financials, PeriodFinancials};
use crate::units::{Cents, Ratio};

/// One covenant's measured outcome, typed for tests and explain output.
#[derive(Debug, Clone, PartialEq)]
pub struct CovenantResult {
    pub covenant_id: String,
    pub kind: CovenantKind,
    pub basis: Basis,
    /// `None` on a vacuous pass — no ratio is computable.
    pub ratio: Option<Ratio>,
    pub threshold: Ratio,
    /// `None` on a vacuous pass. Sign convention: positive means compliant,
    /// zero means exactly at the threshold, negative means in breach.
    pub headroom: Option<Ratio>,
    pub passed: bool,
}

/// Full evaluation: spine findings (the evidence) plus typed per-covenant
/// results (for tests, explain, and future surfaces).
#[derive(Debug, Clone, Default)]
pub struct Evaluation {
    pub findings: Vec<Finding>,
    pub results: Vec<CovenantResult>,
}

/// Outcome of one covenant measurement.
enum Measurement {
    Ratio(Ratio),
    /// Non-positive EBITDA under an EBITDA-based covenant: the coverage
    /// semantics degenerate — automatic breach, never a panic or a division.
    AutomaticBreach(String),
    /// Non-positive denominator with a positive numerator: the test is
    /// vacuous — pass with a visible warning, never a fabricated ratio.
    VacuousPass(String),
}

/// Evaluate every covenant in the config against the financials, at the
/// measurement date. Output order is config order (first occurrence of each
/// covenant id) — deterministic.
pub fn evaluate(config: &CovenantConfig, fin: &Financials) -> Evaluation {
    let mut ev = Evaluation::default();

    let periods = match prepare_periods(&fin.periods) {
        Ok(sorted) => sorted,
        Err(message) => {
            ev.findings
                .push(Finding::breach("input-data-error", "financials", message));
            return ev;
        }
    };

    let current_idx = match periods
        .iter()
        .rposition(|p| p.period_end <= fin.measurement_date)
    {
        Some(idx) => idx,
        None => {
            ev.findings.push(Finding::breach(
                "input-data-error",
                "financials",
                format!(
                    "no period ends on or before the measurement date {}",
                    fin.measurement_date
                ),
            ));
            return ev;
        }
    };

    // Covenant ids in first-seen config order — deterministic output order.
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
            .filter(|r| r.id == id && r.is_in_force(fin.measurement_date))
            .collect();
        match in_force.as_slice() {
            [] => ev.findings.push(Finding {
                rule_id: "covenant-test".to_string(),
                severity: Severity::Info,
                subject: id.to_string(),
                message: format!(
                    "no version in force at measurement date {}",
                    fin.measurement_date
                ),
                requires_signoff: false,
            }),
            [rule] => evaluate_rule(config, rule, fin, &periods, current_idx, &mut ev),
            _ => ev.findings.push(Finding::breach(
                "ambiguous-covenant-versions",
                id,
                format!(
                    "{} versions of the covenant are in force at {}; exactly one is required",
                    in_force.len(),
                    fin.measurement_date
                ),
            )),
        }
    }
    ev
}

fn evaluate_rule(
    config: &CovenantConfig,
    rule: &CovenantRule,
    fin: &Financials,
    periods: &[&PeriodFinancials],
    current_idx: usize,
    ev: &mut Evaluation,
) {
    let id = rule.id.as_str();
    let current = periods[current_idx];

    let window: Vec<&PeriodFinancials> = match rule.basis {
        Basis::Quarterly => vec![current],
        Basis::Ltm => {
            if current_idx + 1 < LTM_QUARTERS {
                ev.findings.push(Finding::breach(
                    "ltm-history-insufficient",
                    id,
                    format!(
                        "LTM basis needs {LTM_QUARTERS} quarterly periods; only {} end on or before the measurement date",
                        current_idx + 1
                    ),
                ));
                return;
            }
            periods[current_idx + 1 - LTM_QUARTERS..=current_idx].to_vec()
        }
    };

    let mut totals = totals_for_window(&window);
    // Equity cures anchored to the measurement date; matching cures sum in
    // config order. Cures apply to the measurement evaluation only — the
    // trend projection reads raw history.
    for cure in config
        .equity_cures
        .iter()
        .filter(|c| c.is_in_force(fin.measurement_date))
    {
        totals.ebitda = totals.ebitda + cure.add_to_ebitda_cents;
        totals.debt = totals.debt - cure.reduce_debt_cents;
    }

    let basis_note = format!("basis {}, period {}", rule.basis.label(), current.period_id);
    match measure(rule.kind, &totals) {
        Measurement::AutomaticBreach(reason) => {
            ev.findings.push(Finding::breach(
                "covenant-test",
                id,
                format!("automatic breach: {reason} ({basis_note})"),
            ));
            ev.results.push(CovenantResult {
                covenant_id: rule.id.clone(),
                kind: rule.kind,
                basis: rule.basis,
                ratio: None,
                threshold: rule.threshold,
                headroom: None,
                passed: false,
            });
        }
        Measurement::VacuousPass(reason) => {
            ev.findings.push(Finding {
                rule_id: "covenant-test".to_string(),
                severity: Severity::Warn,
                subject: rule.id.clone(),
                message: format!("vacuous pass: {reason} ({basis_note})"),
                requires_signoff: false,
            });
            ev.results.push(CovenantResult {
                covenant_id: rule.id.clone(),
                kind: rule.kind,
                basis: rule.basis,
                ratio: None,
                threshold: rule.threshold,
                headroom: None,
                passed: true,
            });
        }
        Measurement::Ratio(ratio) => {
            let headroom = if rule.kind.is_maximum() {
                rule.threshold - ratio
            } else {
                ratio - rule.threshold
            };
            let passed = if rule.kind.is_maximum() {
                ratio <= rule.threshold
            } else {
                ratio >= rule.threshold
            };
            let op = if rule.kind.is_maximum() { "max" } else { "min" };
            let comparison = if passed { "within" } else { "exceeds" };
            let message = format!(
                "{} ratio {}x {comparison} {op} {}x; headroom {}x ({basis_note})",
                rule.kind.label(),
                ratio,
                rule.threshold,
                signed(headroom)
            );
            if passed {
                ev.findings.push(Finding {
                    rule_id: "covenant-test".to_string(),
                    severity: Severity::Info,
                    subject: rule.id.clone(),
                    message,
                    requires_signoff: false,
                });
            } else {
                ev.findings
                    .push(Finding::breach("covenant-test", id, message));
            }
            ev.results.push(CovenantResult {
                covenant_id: rule.id.clone(),
                kind: rule.kind,
                basis: rule.basis,
                ratio: Some(ratio),
                threshold: rule.threshold,
                headroom: Some(headroom),
                passed,
            });
            if passed {
                project(rule, config, periods, current_idx, ev);
            }
        }
    }
}

/// Aggregated window values fed to a covenant measurement. Stock items are
/// quarter-end balances from the window's last period; flow items are
/// window sums.
#[derive(Debug, Clone, Copy)]
struct WindowTotals {
    debt: Cents,
    ebitda: Cents,
    interest: Cents,
    current_assets: Cents,
    current_liabilities: Cents,
    rent: Cents,
    maturities: Cents,
}

fn totals_for_window(window: &[&PeriodFinancials]) -> WindowTotals {
    let last = window[window.len() - 1];
    WindowTotals {
        debt: last.total_debt_cents,
        ebitda: sum_field(window, |p| p.ebitda_cents),
        interest: sum_field(window, |p| p.interest_expense_cents),
        current_assets: last.current_assets_cents,
        current_liabilities: last.current_liabilities_cents,
        rent: sum_field(window, |p| p.rent_expense_cents),
        maturities: sum_field(window, |p| p.current_maturities_cents),
    }
}

fn measure(kind: CovenantKind, t: &WindowTotals) -> Measurement {
    match kind {
        CovenantKind::MaxLeverage => {
            if t.ebitda.get() <= 0 {
                return Measurement::AutomaticBreach(
                    "non-positive EBITDA under leverage covenant".to_string(),
                );
            }
            scaled_ratio(t.debt.get(), t.ebitda.get())
        }
        CovenantKind::MinInterestCoverage => {
            if t.ebitda.get() <= 0 {
                return Measurement::AutomaticBreach(
                    "non-positive EBITDA under coverage covenant".to_string(),
                );
            }
            if t.interest.get() <= 0 {
                return Measurement::VacuousPass(
                    "non-positive interest expense; no coverage test is computable".to_string(),
                );
            }
            scaled_ratio(t.ebitda.get(), t.interest.get())
        }
        CovenantKind::MinCurrentRatio => {
            if t.current_liabilities.get() <= 0 {
                return Measurement::VacuousPass(
                    "non-positive current liabilities; no ratio test is computable".to_string(),
                );
            }
            scaled_ratio(t.current_assets.get(), t.current_liabilities.get())
        }
        CovenantKind::MinFixedChargeCoverage => {
            if t.ebitda.get() <= 0 {
                return Measurement::AutomaticBreach(
                    "non-positive EBITDA under coverage covenant".to_string(),
                );
            }
            let den = t.interest.get() + t.rent.get() + t.maturities.get();
            if den <= 0 {
                return Measurement::VacuousPass(
                    "non-positive fixed charges; no coverage test is computable".to_string(),
                );
            }
            scaled_ratio(t.ebitda.get() + t.rent.get(), den)
        }
    }
}

fn scaled_ratio(num: i128, den: i128) -> Measurement {
    match Ratio::scaled_div(num, den) {
        Some(r) => Measurement::Ratio(r),
        // den == 0 is excluded by the sign checks above; fail closed anyway.
        None => Measurement::VacuousPass("zero denominator; no ratio is computable".to_string()),
    }
}

/// Early-warning projection: fit a deterministic linear trend (ordinary
/// least squares in integer arithmetic) over the covenant's ratio series and
/// warn when the trend crosses the threshold within the horizon. Crossing
/// is strictly beyond the threshold — at-threshold is not a breach.
fn project(
    rule: &CovenantRule,
    config: &CovenantConfig,
    periods: &[&PeriodFinancials],
    current_idx: usize,
    ev: &mut Evaluation,
) {
    let horizon = config.projection.horizon_quarters;
    let min_history = usize::try_from(config.projection.min_history_points).unwrap_or(usize::MAX);

    // Trend series on the covenant's basis, cures excluded (they anchor to
    // the measurement date). Non-computable points (auto-breach or vacuous
    // windows) are skipped — the trend reads computable points only.
    let mut series: Vec<Ratio> = Vec::new();
    let series_window =
        |window: &[&PeriodFinancials]| measure(rule.kind, &totals_for_window(window));
    match rule.basis {
        Basis::Quarterly => {
            for p in &periods[..=current_idx] {
                if let Measurement::Ratio(r) = series_window(&[p]) {
                    series.push(r);
                }
            }
        }
        Basis::Ltm => {
            if current_idx + 1 >= LTM_QUARTERS {
                for end in LTM_QUARTERS - 1..=current_idx {
                    let window = &periods[end + 1 - LTM_QUARTERS..=end];
                    if let Measurement::Ratio(r) = series_window(window) {
                        series.push(r);
                    }
                }
            }
        }
    }

    if series.len() < min_history {
        ev.findings.push(Finding {
            rule_id: "covenant-projection".to_string(),
            severity: Severity::Info,
            subject: rule.id.clone(),
            message: format!(
                "projection skipped: {} computable ratio points, {} required",
                series.len(),
                config.projection.min_history_points
            ),
            requires_signoff: false,
        });
        return;
    }
    let slope = match ols_slope(&series) {
        Some(s) => s,
        None => return, // unreachable for series of length >= 2
    };
    let last = series[series.len() - 1];
    let op = if rule.kind.is_maximum() { "max" } else { "min" };
    for k in 1..=horizon {
        let projected = last + slope * i128::from(k);
        let crosses = if rule.kind.is_maximum() {
            projected > rule.threshold
        } else {
            projected < rule.threshold
        };
        if crosses {
            ev.findings.push(Finding {
                rule_id: "covenant-projection".to_string(),
                severity: Severity::Warn,
                subject: rule.id.clone(),
                message: format!(
                    "projected breach in quarter +{k} of horizon {horizon}: projected ratio {projected}x against {op} {}x",
                    rule.threshold
                ),
                requires_signoff: false,
            });
            return;
        }
    }
}

/// Least-squares slope over quarter-indexed points, in scaled ratio units
/// per quarter. Integer arithmetic with truncating division — same input,
/// same output, always.
fn ols_slope(series: &[Ratio]) -> Option<Ratio> {
    let n = i128::try_from(series.len()).ok()?;
    if n < 2 {
        return None;
    }
    let mut sx = 0i128;
    let mut sxx = 0i128;
    let mut sxy = 0i128;
    let mut sy = 0i128;
    for (x, y) in series.iter().enumerate() {
        let x = i128::try_from(x).ok()?;
        let y = y.scaled();
        sx += x;
        sxx += x * x;
        sxy += x * y;
        sy += y;
    }
    let den = n * sxx - sx * sx;
    if den == 0 {
        return None;
    }
    Some(Ratio::from_scaled((n * sxy - sx * sy) / den))
}

/// Deterministic period ordering plus uniqueness checks. Duplicate period
/// ids or quarter-end dates refuse to evaluate — fail-closed, no partial
/// results.
fn prepare_periods(periods: &[PeriodFinancials]) -> Result<Vec<&PeriodFinancials>, String> {
    let mut sorted: Vec<&PeriodFinancials> = periods.iter().collect();
    sorted.sort_by_key(|p| p.period_end);
    for (i, p) in sorted.iter().enumerate() {
        if sorted[..i].iter().any(|q| q.period_id == p.period_id) {
            return Err(format!("duplicate period_id {}", p.period_id));
        }
        if sorted[..i].iter().any(|q| q.period_end == p.period_end) {
            return Err(format!("duplicate period_end {}", p.period_end));
        }
    }
    Ok(sorted)
}

fn sum_field(window: &[&PeriodFinancials], field: impl Fn(&PeriodFinancials) -> Cents) -> Cents {
    window
        .iter()
        .fold(Cents::from_cents(0), |acc, p| acc + field(p))
}

/// Signed rendering for headroom in messages: positive gets an explicit `+`.
fn signed(r: Ratio) -> String {
    if r.scaled() > 0 {
        format!("+{r}")
    } else {
        r.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CovenantConfig, EquityCure, ProjectionConfig};
    use chrono::NaiveDate;

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn cents(v: i128) -> Cents {
        Cents::from_cents(v)
    }

    fn ratio(s: &str) -> Ratio {
        Ratio::from_decimal_str(s).unwrap()
    }

    fn period(id: &str, end: &str, ebitda: i128) -> PeriodFinancials {
        PeriodFinancials {
            period_id: id.to_string(),
            period_end: date(end),
            total_debt_cents: cents(3_500_000_000), // $35M
            ebitda_cents: cents(ebitda),
            interest_expense_cents: cents(250_000_000),
            current_assets_cents: cents(2_000_000_000),
            current_liabilities_cents: cents(1_000_000_000),
            rent_expense_cents: cents(50_000_000),
            current_maturities_cents: cents(25_000_000),
        }
    }

    /// Four quarters of $2.5M EBITDA each → $10M LTM EBITDA; $35M debt →
    /// 3.5x LTM leverage; $10M LTM interest → 1.0x coverage.
    fn base_periods() -> Vec<PeriodFinancials> {
        vec![
            period("2025-Q3", "2025-09-30", 250_000_000),
            period("2025-Q4", "2025-12-31", 250_000_000),
            period("2026-Q1", "2026-03-31", 250_000_000),
            period("2026-Q2", "2026-06-30", 250_000_000),
        ]
    }

    fn measured(p: Vec<PeriodFinancials>, m: &str) -> Financials {
        Financials {
            entity: "ACME".to_string(),
            measurement_date: date(m),
            periods: p,
        }
    }

    fn fin(p: Vec<PeriodFinancials>) -> Financials {
        measured(p, "2026-06-30")
    }

    fn rule(id: &str, kind: CovenantKind, threshold: &str, basis: Basis) -> CovenantRule {
        CovenantRule {
            id: id.to_string(),
            kind,
            threshold: ratio(threshold),
            basis,
            effective_from: date("2000-01-01"),
            effective_to: None,
        }
    }

    fn config_with(covenants: Vec<CovenantRule>) -> CovenantConfig {
        CovenantConfig {
            covenants,
            ..Default::default()
        }
    }

    fn result_for<'a>(ev: &'a Evaluation, id: &str) -> &'a CovenantResult {
        ev.results
            .iter()
            .find(|r| r.covenant_id == id)
            .unwrap_or_else(|| panic!("no result for {id}"))
    }

    fn finding_for<'a>(ev: &'a Evaluation, id: &str) -> &'a Finding {
        ev.findings
            .iter()
            .find(|f| f.subject == id)
            .unwrap_or_else(|| panic!("no finding for {id}"))
    }

    #[test]
    fn max_leverage_both_sides_of_threshold() {
        // $35M debt / $10M LTM EBITDA = 3.5x.
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "4.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "LEV");
        assert!(r.passed);
        assert_eq!(r.ratio, Some(ratio("3.5")));
        // Headroom sign: positive when compliant.
        assert_eq!(r.headroom, Some(ratio("0.5")));
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.severity, Severity::Info);
        assert!(!f.requires_signoff);

        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "3.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "LEV");
        assert!(!r.passed);
        // Headroom sign: negative when in breach.
        assert_eq!(r.headroom, Some(ratio("-0.5")));
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.severity, Severity::Breach);
        assert!(f.requires_signoff);
    }

    #[test]
    fn min_interest_coverage_both_sides_of_threshold() {
        // $10M LTM EBITDA / $10M LTM interest = 1.0x.
        let cfg = config_with(vec![rule(
            "IC",
            CovenantKind::MinInterestCoverage,
            "0.90",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "IC");
        assert!(r.passed);
        assert_eq!(r.ratio, Some(ratio("1")));
        assert_eq!(r.headroom, Some(ratio("0.1")));

        let cfg = config_with(vec![rule(
            "IC",
            CovenantKind::MinInterestCoverage,
            "1.50",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "IC");
        assert!(!r.passed);
        assert_eq!(r.headroom, Some(ratio("-0.5")));
        assert_eq!(finding_for(&ev, "IC").severity, Severity::Breach);
    }

    #[test]
    fn min_current_ratio_both_sides_of_threshold() {
        // $20M current assets / $10M current liabilities = 2.0x.
        let cfg = config_with(vec![rule(
            "CR",
            CovenantKind::MinCurrentRatio,
            "1.50",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "CR");
        assert!(r.passed);
        assert_eq!(r.ratio, Some(ratio("2")));
        assert_eq!(r.headroom, Some(ratio("0.5")));

        let cfg = config_with(vec![rule(
            "CR",
            CovenantKind::MinCurrentRatio,
            "2.50",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "CR");
        assert!(!r.passed);
        assert_eq!(r.headroom, Some(ratio("-0.5")));
        assert_eq!(finding_for(&ev, "CR").severity, Severity::Breach);
    }

    #[test]
    fn min_fixed_charge_coverage_both_sides_with_exact_truncation() {
        // numerator = $10M EBITDA + 4x$0.5M rent = $12M;
        // denominator = $10M interest + $2M rent + $1M maturities = $13M;
        // 12/13 = 0.9230769... -> truncated at millionths to 0.923076x.
        let cfg = config_with(vec![rule(
            "FCC",
            CovenantKind::MinFixedChargeCoverage,
            "0.90",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        let r = result_for(&ev, "FCC");
        assert!(r.passed);
        assert_eq!(r.ratio, Some(Ratio::from_scaled(923_076)));
        assert_eq!(r.headroom, Some(Ratio::from_scaled(23_076)));

        let cfg = config_with(vec![rule(
            "FCC",
            CovenantKind::MinFixedChargeCoverage,
            "1.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        assert!(!result_for(&ev, "FCC").passed);
        assert_eq!(finding_for(&ev, "FCC").severity, Severity::Breach);
    }

    #[test]
    fn threshold_boundary_is_inclusive() {
        // Exactly at the threshold: compliant for both directions.
        let cfg = config_with(vec![
            rule("LEV", CovenantKind::MaxLeverage, "3.50", Basis::Ltm),
            rule("IC", CovenantKind::MinInterestCoverage, "1.00", Basis::Ltm),
        ]);
        let ev = evaluate(&cfg, &fin(base_periods()));
        assert!(result_for(&ev, "LEV").passed);
        assert!(result_for(&ev, "IC").passed);
        assert_eq!(result_for(&ev, "LEV").headroom, Some(ratio("0")));
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.message.contains("headroom 0x"));
    }

    #[test]
    fn non_positive_ebitda_is_automatic_breach_not_panic() {
        let negative = base_periods()
            .into_iter()
            .map(|mut p| {
                p.ebitda_cents = cents(-100_000_000);
                p
            })
            .collect();
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "3.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(negative));
        let r = result_for(&ev, "LEV");
        assert!(!r.passed);
        assert_eq!(r.ratio, None);
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.severity, Severity::Breach);
        assert!(f.message.contains("automatic breach"));

        let zero = base_periods()
            .into_iter()
            .map(|mut p| {
                p.ebitda_cents = cents(0);
                p
            })
            .collect();
        let cfg = config_with(vec![rule(
            "IC",
            CovenantKind::MinInterestCoverage,
            "1.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(zero));
        let r = result_for(&ev, "IC");
        assert!(!r.passed);
        assert_eq!(r.ratio, None);
        assert!(finding_for(&ev, "IC").message.contains("automatic breach"));
    }

    #[test]
    fn ltm_sums_only_the_trailing_four_quarters() {
        let mut periods = vec![period("2025-Q2", "2025-06-30", 2_500_000_000)]; // $25M spike quarter
        periods.extend(base_periods());
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "4.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        // Trailing four quarters are $2.5M each -> $10M LTM EBITDA -> 3.5x,
        // not the all-history sum ($35M) which would read 1.0x.
        assert_eq!(result_for(&ev, "LEV").ratio, Some(ratio("3.5")));
    }

    #[test]
    fn ltm_basis_with_insufficient_history_fails_closed() {
        let periods = vec![
            period("2026-Q1", "2026-03-31", 250_000_000),
            period("2026-Q2", "2026-06-30", 250_000_000),
        ];
        let cfg = config_with(vec![
            rule("LEV-L", CovenantKind::MaxLeverage, "3.50", Basis::Ltm),
            rule(
                "LEV-Q",
                CovenantKind::MaxLeverage,
                "20.00",
                Basis::Quarterly,
            ),
        ]);
        let ev = evaluate(&cfg, &fin(periods));
        let f = finding_for(&ev, "LEV-L");
        assert_eq!(f.rule_id, "ltm-history-insufficient");
        assert_eq!(f.severity, Severity::Breach);
        // The quarterly covenant still evaluates: the refusal is scoped to
        // the covenant that lacks history, not a blanket stop.
        assert!(result_for(&ev, "LEV-Q").passed);
        assert!(ev.results.iter().all(|r| r.covenant_id != "LEV-L"));
    }

    #[test]
    fn effective_dated_amendment_tests_the_text_in_force() {
        let amended = |from: &str, to: Option<&str>, threshold: &str| CovenantRule {
            id: "LEV".to_string(),
            kind: CovenantKind::MaxLeverage,
            threshold: ratio(threshold),
            basis: Basis::Quarterly,
            effective_from: date(from),
            effective_to: to.map(date),
        };
        let config = CovenantConfig {
            covenants: vec![
                amended("2000-01-01", Some("2026-01-01"), "15.00"),
                amended("2026-01-01", None, "13.00"),
            ],
            ..Default::default()
        };

        // Before the amendment date the old text (15x) is in force: 14x passes.
        let old = evaluate(&config, &measured(base_periods(), "2025-12-31"));
        assert!(result_for(&old, "LEV").passed);
        assert_eq!(result_for(&old, "LEV").threshold, ratio("15.00"));

        // On/after the amendment date the new text (13x) is in force: 14x breaches.
        let new = evaluate(&config, &measured(base_periods(), "2026-06-30"));
        assert!(!result_for(&new, "LEV").passed);
        assert_eq!(result_for(&new, "LEV").threshold, ratio("13.00"));
        assert_eq!(finding_for(&new, "LEV").severity, Severity::Breach);
    }

    #[test]
    fn overlapping_versions_fail_closed() {
        let config = config_with(vec![
            rule("LEV", CovenantKind::MaxLeverage, "15.00", Basis::Quarterly),
            rule("LEV", CovenantKind::MaxLeverage, "13.00", Basis::Quarterly),
        ]);
        let ev = evaluate(&config, &fin(base_periods()));
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.rule_id, "ambiguous-covenant-versions");
        assert_eq!(f.severity, Severity::Breach);
        assert!(ev.results.iter().all(|r| r.covenant_id != "LEV"));
    }

    #[test]
    fn covenant_not_yet_in_force_is_reported_and_skipped() {
        let future = CovenantRule {
            effective_from: date("2027-01-01"),
            ..rule("LEV", CovenantKind::MaxLeverage, "3.50", Basis::Ltm)
        };
        let ev = evaluate(&config_with(vec![future]), &fin(base_periods()));
        let f = finding_for(&ev, "LEV");
        assert_eq!(f.severity, Severity::Info);
        assert!(!f.requires_signoff);
        assert!(ev.results.is_empty());
    }

    #[test]
    fn equity_cure_debt_reduction_flips_breach_to_pass() {
        let cure = EquityCure {
            description: "Q2 cure".to_string(),
            effective_from: date("2026-01-01"),
            effective_to: None,
            add_to_ebitda_cents: cents(0),
            reduce_debt_cents: cents(1_000_000_000),
        };
        let cfg = CovenantConfig {
            covenants: vec![rule("LEV", CovenantKind::MaxLeverage, "3.00", Basis::Ltm)],
            equity_cures: vec![cure],
            ..Default::default()
        };
        let ev = evaluate(&cfg, &fin(base_periods()));
        // $25M adjusted debt / $10M LTM EBITDA = 2.5x -> pass.
        assert_eq!(result_for(&ev, "LEV").ratio, Some(ratio("2.5")));
        assert!(result_for(&ev, "LEV").passed);
    }

    #[test]
    fn equity_cure_outside_its_window_is_not_applied() {
        let cure = EquityCure {
            description: "future cure".to_string(),
            effective_from: date("2026-07-01"),
            effective_to: None,
            add_to_ebitda_cents: cents(0),
            reduce_debt_cents: cents(1_000_000_000),
        };
        let cfg = CovenantConfig {
            covenants: vec![rule("LEV", CovenantKind::MaxLeverage, "3.00", Basis::Ltm)],
            equity_cures: vec![cure],
            ..Default::default()
        };
        let ev = evaluate(&cfg, &fin(base_periods()));
        assert!(!result_for(&ev, "LEV").passed); // still 3.5x vs 3.0x
    }

    #[test]
    fn equity_cure_ebitda_addition_applies_to_coverage() {
        // 1.0x coverage vs a 1.5x minimum breaches; +$7.5M cure EBITDA
        // lifts it to 1.75x.
        let cure = EquityCure {
            description: "ebitda cure".to_string(),
            effective_from: date("2026-01-01"),
            effective_to: None,
            add_to_ebitda_cents: cents(750_000_000),
            reduce_debt_cents: cents(0),
        };
        let cfg = CovenantConfig {
            covenants: vec![rule(
                "IC",
                CovenantKind::MinInterestCoverage,
                "1.50",
                Basis::Ltm,
            )],
            equity_cures: vec![cure],
            ..Default::default()
        };
        let ev = evaluate(&cfg, &fin(base_periods()));
        assert_eq!(result_for(&ev, "IC").ratio, Some(ratio("1.75")));
        assert!(result_for(&ev, "IC").passed);
    }

    #[test]
    fn projection_warns_when_trend_crosses_within_horizon() {
        let ids = [
            ("2025-Q3", "2025-09-30"),
            ("2025-Q4", "2025-12-31"),
            ("2026-Q1", "2026-03-31"),
            ("2026-Q2", "2026-06-30"),
        ];
        let ebitda = [300_000_000i128, 280_000_000, 260_000_000, 240_000_000];
        let periods: Vec<PeriodFinancials> = ids
            .iter()
            .zip(ebitda)
            .map(|((id, end), e)| {
                let mut p = period(id, end, e);
                // $10M debt — the helper's $35M would already be in breach.
                p.total_debt_cents = cents(1_000_000_000);
                p
            })
            .collect();
        let cfg = CovenantConfig {
            covenants: vec![rule(
                "LEV",
                CovenantKind::MaxLeverage,
                "4.20",
                Basis::Quarterly,
            )],
            projection: ProjectionConfig {
                horizon_quarters: 4,
                min_history_points: 2,
            },
            ..Default::default()
        };
        let ev = evaluate(&cfg, &fin(periods));
        // Measurement: $10M / $2.4M = 4.166666x — passes 4.2x.
        let r = result_for(&ev, "LEV");
        assert!(r.passed);
        let proj = ev
            .findings
            .iter()
            .find(|f| f.rule_id == "covenant-projection")
            .expect("projection finding");
        assert_eq!(proj.severity, Severity::Warn);
        assert_eq!(proj.subject, "LEV");
        assert!(
            proj.message.contains("quarter +1"),
            "message: {}",
            proj.message
        );
    }

    #[test]
    fn projection_stays_silent_when_improving_or_already_breached() {
        let ids = [
            ("2025-Q3", "2025-09-30"),
            ("2025-Q4", "2025-12-31"),
            ("2026-Q1", "2026-03-31"),
            ("2026-Q2", "2026-06-30"),
        ];
        // Improving EBITDA -> leverage falls -> no crossing.
        let ebitda = [240_000_000i128, 260_000_000, 280_000_000, 300_000_000];
        let periods: Vec<PeriodFinancials> = ids
            .iter()
            .zip(ebitda)
            .map(|((id, end), e)| {
                let mut p = period(id, end, e);
                // $10M debt — the helper's $35M would already be in breach.
                p.total_debt_cents = cents(1_000_000_000);
                p
            })
            .collect();
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "4.20",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        assert!(result_for(&ev, "LEV").passed);
        assert!(ev
            .findings
            .iter()
            .all(|f| f.rule_id != "covenant-projection"));

        // Already in breach: the breach finding covers it; no projection on top.
        let ebitda = [300_000_000i128, 280_000_000, 260_000_000, 240_000_000];
        let periods: Vec<PeriodFinancials> = ids
            .iter()
            .zip(ebitda)
            .map(|((id, end), e)| {
                let mut p = period(id, end, e);
                // $10M debt — 10/2.4 ≈ 4.167x breaches the 4.00x threshold.
                p.total_debt_cents = cents(1_000_000_000);
                p
            })
            .collect();
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "4.00",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        assert!(!result_for(&ev, "LEV").passed);
        assert!(ev
            .findings
            .iter()
            .all(|f| f.rule_id != "covenant-projection"));
    }

    #[test]
    fn projection_without_enough_computable_points_is_skipped_visibly() {
        let periods = vec![period("2026-Q2", "2026-06-30", 250_000_000)];
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "20.00",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        let proj = ev
            .findings
            .iter()
            .find(|f| f.rule_id == "covenant-projection")
            .expect("projection-skip finding");
        assert_eq!(proj.severity, Severity::Info);
        assert!(proj.message.contains("projection skipped"));
    }

    #[test]
    fn non_positive_denominators_pass_vacuously_with_warning() {
        // Interest coverage with zero interest.
        let mut periods = base_periods();
        for p in &mut periods {
            p.interest_expense_cents = cents(0);
        }
        let cfg = config_with(vec![rule(
            "IC",
            CovenantKind::MinInterestCoverage,
            "0.50",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        let r = result_for(&ev, "IC");
        assert!(r.passed);
        assert_eq!(r.ratio, None);
        let f = finding_for(&ev, "IC");
        assert_eq!(f.severity, Severity::Warn);
        assert!(!f.requires_signoff);
        assert!(f.message.contains("vacuous pass"));

        // Current ratio with zero liabilities.
        let mut periods = base_periods();
        for p in &mut periods {
            p.current_liabilities_cents = cents(0);
        }
        let cfg = config_with(vec![rule(
            "CR",
            CovenantKind::MinCurrentRatio,
            "1.00",
            Basis::Quarterly,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        let r = result_for(&ev, "CR");
        assert!(r.passed && r.ratio.is_none());
        assert_eq!(finding_for(&ev, "CR").severity, Severity::Warn);

        // Fixed-charge coverage with zero fixed charges.
        let mut periods = base_periods();
        for p in &mut periods {
            p.interest_expense_cents = cents(0);
            p.rent_expense_cents = cents(0);
            p.current_maturities_cents = cents(0);
        }
        let cfg = config_with(vec![rule(
            "FCC",
            CovenantKind::MinFixedChargeCoverage,
            "1.00",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &fin(periods));
        let r = result_for(&ev, "FCC");
        assert!(r.passed && r.ratio.is_none());
        assert_eq!(finding_for(&ev, "FCC").severity, Severity::Warn);
    }

    #[test]
    fn duplicate_period_data_fails_closed() {
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "3.50",
            Basis::Ltm,
        )]);

        let mut periods = base_periods();
        periods.push(period("2025-Q3", "2026-09-30", 250_000_000)); // duplicate id
        let ev = evaluate(&cfg, &fin(periods));
        let f = ev
            .findings
            .iter()
            .find(|f| f.rule_id == "input-data-error")
            .expect("data-error finding");
        assert_eq!(f.severity, Severity::Breach);
        assert_eq!(f.subject, "financials");
        assert!(ev.results.is_empty()); // nothing evaluated — no partial results

        let mut periods = base_periods();
        periods.push(period("2026-Q3", "2025-09-30", 250_000_000)); // duplicate end, unique id
        let ev = evaluate(&cfg, &fin(periods));
        assert!(
            ev.findings
                .iter()
                .any(|f| f.rule_id == "input-data-error"
                    && f.message.contains("duplicate period_end"))
        );
    }

    #[test]
    fn measurement_before_all_periods_fails_closed() {
        let cfg = config_with(vec![rule(
            "LEV",
            CovenantKind::MaxLeverage,
            "3.50",
            Basis::Ltm,
        )]);
        let ev = evaluate(&cfg, &measured(base_periods(), "2025-01-01"));
        let f = ev
            .findings
            .iter()
            .find(|f| f.rule_id == "input-data-error")
            .expect("data-error finding");
        assert_eq!(f.severity, Severity::Breach);
        assert!(f.message.contains("no period ends on or before"));
        assert!(ev.results.is_empty());
    }

    #[test]
    fn unsorted_input_periods_evaluate_identically() {
        let cfg = config_with(vec![
            rule("LEV", CovenantKind::MaxLeverage, "4.00", Basis::Ltm),
            rule("IC", CovenantKind::MinInterestCoverage, "0.90", Basis::Ltm),
        ]);
        let sorted = evaluate(&cfg, &fin(base_periods()));
        let mut shuffled = base_periods();
        shuffled.reverse();
        let reversed = evaluate(&cfg, &fin(shuffled));
        assert_eq!(sorted.results, reversed.results);
        let subjects = |ev: &Evaluation| {
            ev.findings
                .iter()
                .map(|f| (f.rule_id.clone(), f.subject.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(subjects(&sorted), subjects(&reversed));
    }

    #[test]
    fn ols_slope_is_deterministic_integer_arithmetic() {
        let two_point =
            ols_slope(&[Ratio::from_scaled(1_000_000), Ratio::from_scaled(2_000_000)]).unwrap();
        assert_eq!(two_point.scaled(), 1_000_000);
        // Truncating division: same input -> same output, always.
        let flat = ols_slope(&[
            Ratio::from_scaled(5),
            Ratio::from_scaled(7),
            Ratio::from_scaled(9),
        ])
        .unwrap();
        assert_eq!(flat.scaled(), 2);
        assert_eq!(ols_slope(&[Ratio::from_scaled(3)]), None);
    }
}
