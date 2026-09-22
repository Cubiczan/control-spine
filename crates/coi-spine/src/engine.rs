//! The pure COI gap engine.
//!
//! Deterministic arithmetic over (typed certificate × requirements matrix ×
//! clock date). No clock, filesystem, or network access; no RNG. Every
//! finding is a pure function of its inputs, so the same bytes always
//! reproduce the same evidence.
//!
//! Rule inventory (rule_id → severity):
//! * `missing_coverage` — breach: a required coverage has no policy line.
//! * `coverage_expired` — breach: every line for a required coverage expired
//!   before the clock date.
//! * `coverage_expiring_soon` — warn: the selected line expires within the
//!   configured window (inclusive) — the renewal-chase queue.
//! * `limit_below_requirement` — breach: the selected line's per-occurrence
//!   or aggregate limit is under the matrix requirement.
//! * `missing_endorsement` — breach: a required endorsement is absent from
//!   the selected line.
//! * `carrier_rating_below_floor` — breach: the selected carrier is under
//!   the configured floor.
//! * `unknown_category` — breach: the vendor's category is absent from the
//!   matrix, so requirements cannot be determined (fail-closed).
//! * `lockout_recommendation` — warn: breach-severity gap on a critical
//!   category recommends a hold on new POs — advisory only; a human executes
//!   any hold outside this engine.

use chrono::{Duration, NaiveDate};
use spine::{Finding, Severity};

use crate::cert::{Certificate, PolicyLine};
use crate::config::{Coverage, CoverageRequirement, RequirementsConfig};

pub const RULE_MISSING_COVERAGE: &str = "missing_coverage";
pub const RULE_COVERAGE_EXPIRED: &str = "coverage_expired";
pub const RULE_EXPIRING_SOON: &str = "coverage_expiring_soon";
pub const RULE_LIMIT_BELOW: &str = "limit_below_requirement";
pub const RULE_MISSING_ENDORSEMENT: &str = "missing_endorsement";
pub const RULE_RATING_BELOW_FLOOR: &str = "carrier_rating_below_floor";
pub const RULE_UNKNOWN_CATEGORY: &str = "unknown_category";
pub const RULE_LOCKOUT: &str = "lockout_recommendation";

/// Result of one evaluation: findings in deterministic order plus the
/// advisory lockout flag.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub findings: Vec<Finding>,
    pub lockout_recommended: bool,
}

/// Evaluate a certificate against the matrix as of the clock date.
pub fn evaluate(cert: &Certificate, cfg: &RequirementsConfig, as_of: NaiveDate) -> Evaluation {
    let subject = cert.vendor_id.as_str();
    let mut findings = Vec::new();

    let Some(requirement) = cfg.categories.get(cert.vendor_category.as_str()) else {
        findings.push(Finding::breach(
            RULE_UNKNOWN_CATEGORY,
            subject,
            format!(
                "vendor category '{}' is not in the requirements matrix; required coverages cannot be determined — fail-closed",
                cert.vendor_category
            ),
        ));
        return Evaluation {
            findings,
            lockout_recommended: false,
        };
    };

    for (coverage, needed) in &requirement.coverages {
        let lines: Vec<&PolicyLine> = cert
            .policies
            .iter()
            .filter(|policy| policy.coverage == *coverage)
            .collect();
        evaluate_coverage(
            subject,
            *coverage,
            needed,
            &lines,
            cfg,
            as_of,
            &mut findings,
        );
    }

    let has_breach = findings
        .iter()
        .any(|finding| finding.severity == Severity::Breach);
    let lockout_recommended = requirement.critical && has_breach;
    if lockout_recommended {
        findings.push(Finding {
            rule_id: RULE_LOCKOUT.to_string(),
            severity: Severity::Warn,
            subject: subject.to_string(),
            message: "critical vendor category carries breach-severity coverage gaps: a hold on new purchase orders is recommended — advisory only, a human executes any hold outside this engine".to_string(),
            requires_signoff: false,
        });
    }

    Evaluation {
        findings,
        lockout_recommended,
    }
}

/// Evaluate one required coverage against its candidate policy lines and
/// append findings in a deterministic order. `lines` are all certificate
/// lines typed as `coverage`.
fn evaluate_coverage(
    subject: &str,
    coverage: Coverage,
    needed: &CoverageRequirement,
    lines: &[&PolicyLine],
    cfg: &RequirementsConfig,
    as_of: NaiveDate,
    findings: &mut Vec<Finding>,
) {
    let current: Vec<&PolicyLine> = lines
        .iter()
        .copied()
        .filter(|policy| policy.expiration_date >= as_of)
        .collect();
    if lines.is_empty() {
        findings.push(Finding::breach(
            RULE_MISSING_COVERAGE,
            subject,
            format!(
                "required coverage {} is absent from the certificate: no policy line of this type was presented",
                coverage.as_label()
            ),
        ));
        return;
    }
    let Some(selected) = select_line(&current) else {
        // Nothing current: expired gap. Name every expired policy for the
        // reviewer so the renewal chase is actionable.
        let mut numbers: Vec<&str> = lines
            .iter()
            .map(|policy| policy.policy_number.as_str())
            .collect();
        numbers.sort_unstable();
        numbers.dedup();
        findings.push(Finding::breach(
            RULE_COVERAGE_EXPIRED,
            subject,
            format!(
                "required coverage {} has no policy valid as of {}: every line is expired ({})",
                coverage.as_label(),
                as_of,
                numbers.join(", ")
            ),
        ));
        return;
    };

    if selected.per_occurrence_limit_cents < needed.per_occurrence_cents {
        findings.push(Finding::breach(
            RULE_LIMIT_BELOW,
            subject,
            format!(
                "coverage {}: per-occurrence limit {} is below the required {}",
                coverage.as_label(),
                format_cents(selected.per_occurrence_limit_cents),
                format_cents(needed.per_occurrence_cents)
            ),
        ));
    }
    if selected.aggregate_limit_cents < needed.aggregate_cents {
        findings.push(Finding::breach(
            RULE_LIMIT_BELOW,
            subject,
            format!(
                "coverage {}: aggregate limit {} is below the required {}",
                coverage.as_label(),
                format_cents(selected.aggregate_limit_cents),
                format_cents(needed.aggregate_cents)
            ),
        ));
    }
    for endorsement in &needed.endorsements {
        if !selected.endorsements.contains(endorsement) {
            findings.push(Finding::breach(
                RULE_MISSING_ENDORSEMENT,
                subject,
                format!(
                    "coverage {}: required endorsement {} is missing from policy {}",
                    coverage.as_label(),
                    endorsement.as_str(),
                    selected.policy_number
                ),
            ));
        }
    }
    if selected.carrier_rating > cfg.min_carrier_rating {
        findings.push(Finding::breach(
            RULE_RATING_BELOW_FLOOR,
            subject,
            format!(
                "coverage {}: carrier {} rating {} is below the required floor {}",
                coverage.as_label(),
                selected.carrier_name,
                selected.carrier_rating.label(),
                cfg.min_carrier_rating.label()
            ),
        ));
    }
    // Warning window boundary is inclusive: a policy expiring exactly on the
    // cutoff date is already inside the renewal-chase queue.
    if let Some(cutoff) = as_of.checked_add_signed(Duration::days(cfg.expiry_warning_days)) {
        if selected.expiration_date <= cutoff {
            findings.push(Finding {
                rule_id: RULE_EXPIRING_SOON.to_string(),
                severity: Severity::Warn,
                subject: subject.to_string(),
                message: format!(
                    "coverage {}: policy {} expires {}, within {} day(s) of {}",
                    coverage.as_label(),
                    selected.policy_number,
                    selected.expiration_date,
                    cfg.expiry_warning_days,
                    as_of
                ),
                requires_signoff: false,
            });
        }
    }
    // Expired lines beside a current line are deliberately not flagged: the
    // coverage stands on the selected line, and flagging the stale row would
    // be noise (see README, severity decisions).
}

/// Deterministic selection among current lines: latest expiration wins, then
/// the higher per-occurrence limit, then the lexicographically lowest policy
/// number. Tests pin this ordering.
fn select_line<'a>(current: &[&'a PolicyLine]) -> Option<&'a PolicyLine> {
    let mut ranked: Vec<&PolicyLine> = current.to_vec();
    ranked.sort_by(|a, b| {
        b.expiration_date
            .cmp(&a.expiration_date)
            .then_with(|| {
                b.per_occurrence_limit_cents
                    .cmp(&a.per_occurrence_limit_cents)
            })
            .then_with(|| a.policy_number.cmp(&b.policy_number))
    });
    ranked.first().copied()
}

/// Integer-only money formatting (never floats): 123456789 cents →
/// `$1,234,567.89`.
pub fn format_cents(cents: i128) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let abs = cents.unsigned_abs();
    let dollars = abs / 100;
    let remainder = abs % 100;
    format!("{sign}${}.{remainder:02}", group_thousands(dollars))
}

fn group_thousands(n: u128) -> String {
    let digits = n.to_string();
    let head = digits.len() % 3;
    let head_len = if head == 0 { 3 } else { head };
    if digits.len() <= 3 {
        return digits;
    }
    let mut out = digits[..head_len].to_string();
    let mut rest = &digits[head_len..];
    while !rest.is_empty() {
        out.push(',');
        out.push_str(&rest[..3]);
        rest = &rest[3..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CarrierRating, CategoryRequirement, Endorsement};
    use std::collections::BTreeMap;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    fn as_of() -> NaiveDate {
        date(2026, 9, 22)
    }

    fn future() -> NaiveDate {
        date(2027, 6, 30)
    }

    fn requirement(
        per_occ: i128,
        agg: i128,
        endorsements: Vec<Endorsement>,
    ) -> CoverageRequirement {
        CoverageRequirement {
            per_occurrence_cents: per_occ,
            aggregate_cents: agg,
            endorsements,
        }
    }

    fn config(critical: bool) -> RequirementsConfig {
        let gl = requirement(
            100_000_000,
            200_000_000,
            vec![Endorsement::AdditionalInsured],
        );
        let wc = requirement(50_000_000, 50_000_000, vec![]);
        RequirementsConfig {
            categories: BTreeMap::from([(
                "electrical_contractor".to_string(),
                CategoryRequirement {
                    critical,
                    coverages: BTreeMap::from([
                        (Coverage::GeneralLiability, gl),
                        (Coverage::WorkersComp, wc),
                    ]),
                },
            )]),
            expiry_warning_days: 30,
            min_carrier_rating: CarrierRating::AMinus,
        }
    }

    fn line(coverage: Coverage, expiration: NaiveDate) -> PolicyLine {
        PolicyLine {
            policy_number: format!("P-{}", coverage.as_str()),
            carrier_name: "Seed Mutual".to_string(),
            carrier_rating: CarrierRating::AMinus,
            coverage,
            per_occurrence_limit_cents: 100_000_000,
            aggregate_limit_cents: 200_000_000,
            effective_date: date(2026, 1, 1),
            expiration_date: expiration,
            endorsements: vec![Endorsement::AdditionalInsured],
        }
    }

    fn cert(policies: Vec<PolicyLine>) -> Certificate {
        Certificate {
            vendor_id: "V-1001".to_string(),
            vendor_category: "electrical_contractor".to_string(),
            policies,
        }
    }

    fn finding_with_rule<'a>(evaluation: &'a Evaluation, rule: &str) -> Vec<&'a Finding> {
        evaluation
            .findings
            .iter()
            .filter(|f| f.rule_id == rule)
            .collect()
    }

    #[test]
    fn clean_certificate_produces_no_findings() {
        let evaluation = evaluate(
            &cert(vec![
                line(Coverage::GeneralLiability, future()),
                line(Coverage::WorkersComp, future()),
            ]),
            &config(true),
            as_of(),
        );
        assert!(evaluation.findings.is_empty());
        assert!(!evaluation.lockout_recommended);
    }

    #[test]
    fn missing_coverage_breach_when_no_policy_line() {
        let evaluation = evaluate(
            &cert(vec![line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let missing = finding_with_rule(&evaluation, RULE_MISSING_COVERAGE);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].severity, Severity::Breach);
        assert!(missing[0].requires_signoff);
        assert!(missing[0].message.contains("GL"));
        // Critical category + breach → advisory lockout fires too.
        assert!(evaluation.lockout_recommended);
    }

    #[test]
    fn expiry_boundary_is_inclusive_and_expired_is_breach() {
        // Expiring exactly on the clock date is still valid (inclusive).
        let today = line(Coverage::GeneralLiability, as_of());
        let wc = line(Coverage::WorkersComp, future());
        let evaluation = evaluate(&cert(vec![today, wc.clone()]), &config(true), as_of());
        assert!(finding_with_rule(&evaluation, RULE_COVERAGE_EXPIRED).is_empty());
        assert_eq!(finding_with_rule(&evaluation, RULE_EXPIRING_SOON).len(), 1);

        // One day earlier: expired — a breach naming the stale policy.
        let yesterday = line(Coverage::GeneralLiability, as_of() - Duration::days(1));
        let evaluation = evaluate(&cert(vec![yesterday, wc]), &config(true), as_of());
        let expired = finding_with_rule(&evaluation, RULE_COVERAGE_EXPIRED);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].severity, Severity::Breach);
        assert!(expired[0].message.contains("P-general_liability"));
        assert!(expired[0].message.contains("2026-09-22"));
    }

    #[test]
    fn expiring_soon_window_boundary_is_inclusive() {
        // Exactly on the cutoff (as_of + 30) → warned; one day later → silent.
        let edge = line(Coverage::GeneralLiability, as_of() + Duration::days(30));
        let evaluation = evaluate(
            &cert(vec![edge, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        assert_eq!(finding_with_rule(&evaluation, RULE_EXPIRING_SOON).len(), 1);

        let beyond = line(Coverage::GeneralLiability, as_of() + Duration::days(31));
        let evaluation = evaluate(
            &cert(vec![beyond, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn limit_boundaries_equal_passes_one_cent_below_breaches() {
        let mut short_per_occ = line(Coverage::GeneralLiability, future());
        short_per_occ.per_occurrence_limit_cents = 99_999_999;
        let evaluation = evaluate(
            &cert(vec![short_per_occ, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let breaches = finding_with_rule(&evaluation, RULE_LIMIT_BELOW);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].message.contains("per-occurrence"));
        assert!(breaches[0].message.contains("$999,999.99"));
        assert!(breaches[0].message.contains("$1,000,000.00"));

        let mut short_aggregate = line(Coverage::GeneralLiability, future());
        short_aggregate.aggregate_limit_cents = 199_999_999;
        let evaluation = evaluate(
            &cert(vec![short_aggregate, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let breaches = finding_with_rule(&evaluation, RULE_LIMIT_BELOW);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].message.contains("aggregate"));

        // Exactly at the requirement is not a breach (covered by the clean
        // baseline): line() defaults meet both limits exactly.
        let evaluation = evaluate(
            &cert(vec![
                line(Coverage::GeneralLiability, future()),
                line(Coverage::WorkersComp, future()),
            ]),
            &config(true),
            as_of(),
        );
        assert!(finding_with_rule(&evaluation, RULE_LIMIT_BELOW).is_empty());
    }

    #[test]
    fn missing_endorsement_breach_names_the_selected_policy() {
        let mut no_ai = line(Coverage::GeneralLiability, future());
        no_ai.endorsements.clear();
        let evaluation = evaluate(
            &cert(vec![no_ai, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let missing = finding_with_rule(&evaluation, RULE_MISSING_ENDORSEMENT);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].severity, Severity::Breach);
        assert!(missing[0].message.contains("additional_insured"));
        assert!(missing[0].message.contains("P-general_liability"));
    }

    #[test]
    fn endorsement_on_non_selected_line_does_not_satisfy() {
        // The selected (latest) GL line lacks the AI endorsement; an older
        // current GL line carries it — the requirement is still unmet.
        let mut latest = line(Coverage::GeneralLiability, future());
        latest.policy_number = "P-LATEST".to_string();
        latest.endorsements.clear();
        let older = line(Coverage::GeneralLiability, future() - Duration::days(1));
        let evaluation = evaluate(
            &cert(vec![latest, older, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let missing = finding_with_rule(&evaluation, RULE_MISSING_ENDORSEMENT);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].message.contains("P-LATEST"));
    }

    #[test]
    fn carrier_rating_floor_boundary() {
        // Exactly at the floor passes (baseline uses AMinus); one notch
        // below breaches, naming both ratings.
        let mut low = line(Coverage::GeneralLiability, future());
        low.carrier_rating = CarrierRating::BPlus;
        let evaluation = evaluate(
            &cert(vec![low, line(Coverage::WorkersComp, future())]),
            &config(true),
            as_of(),
        );
        let breaches = finding_with_rule(&evaluation, RULE_RATING_BELOW_FLOOR);
        assert_eq!(breaches.len(), 1);
        assert!(breaches[0].message.contains("B+"));
        assert!(breaches[0].message.contains("A-"));
    }

    #[test]
    fn unknown_category_fails_closed_without_lockout() {
        let mut unknown = cert(vec![]);
        unknown.vendor_category = "interior_designer".to_string();
        let evaluation = evaluate(&unknown, &config(true), as_of());
        assert_eq!(evaluation.findings.len(), 1);
        assert_eq!(evaluation.findings[0].rule_id, RULE_UNKNOWN_CATEGORY);
        assert_eq!(evaluation.findings[0].severity, Severity::Breach);
        assert!(!evaluation.lockout_recommended);
    }

    #[test]
    fn multipolicy_selects_latest_expiration_deterministically() {
        // An expired line beside a current one does not trigger the expired
        // gap — the coverage stands on the current line.
        let expired = line(Coverage::GeneralLiability, as_of() - Duration::days(1));
        let evaluation = evaluate(
            &cert(vec![
                expired,
                line(Coverage::GeneralLiability, future()),
                line(Coverage::WorkersComp, future()),
            ]),
            &config(true),
            as_of(),
        );
        assert!(evaluation.findings.is_empty());

        // Expiration tie → the higher per-occurrence limit wins: the
        // deficient line is not selected and raises nothing.
        let mut deficient = line(Coverage::GeneralLiability, future());
        deficient.per_occurrence_limit_cents = 10_000_000;
        deficient.policy_number = "P-A".to_string();
        let mut adequate = line(Coverage::GeneralLiability, future());
        adequate.policy_number = "P-B".to_string();
        let evaluation = evaluate(
            &cert(vec![
                deficient,
                adequate,
                line(Coverage::WorkersComp, future()),
            ]),
            &config(true),
            as_of(),
        );
        assert!(finding_with_rule(&evaluation, RULE_LIMIT_BELOW).is_empty());

        // Full tie → the lexicographically lowest policy number wins: the
        // compliant P-A is selected over the endorsement-less P-B.
        let mut compliant = line(Coverage::GeneralLiability, future());
        compliant.policy_number = "P-A".to_string();
        let mut noncompliant = line(Coverage::GeneralLiability, future());
        noncompliant.policy_number = "P-B".to_string();
        noncompliant.endorsements.clear();
        let evaluation = evaluate(
            &cert(vec![
                noncompliant,
                compliant,
                line(Coverage::WorkersComp, future()),
            ]),
            &config(true),
            as_of(),
        );
        assert!(finding_with_rule(&evaluation, RULE_MISSING_ENDORSEMENT).is_empty());
    }

    #[test]
    fn lockout_requires_critical_category_and_breach() {
        let expired_gl = line(Coverage::GeneralLiability, as_of() - Duration::days(1));
        let wc = line(Coverage::WorkersComp, future());

        // Critical + breach → advisory lockout finding, warn severity, no
        // signoff required of its own.
        let evaluation = evaluate(
            &cert(vec![expired_gl.clone(), wc.clone()]),
            &config(true),
            as_of(),
        );
        assert!(evaluation.lockout_recommended);
        let lockout = finding_with_rule(&evaluation, RULE_LOCKOUT);
        assert_eq!(lockout.len(), 1);
        assert_eq!(lockout[0].severity, Severity::Warn);
        assert!(!lockout[0].requires_signoff);

        // Critical + warnings only → no lockout.
        let expiring = line(Coverage::GeneralLiability, as_of() + Duration::days(10));
        let evaluation = evaluate(&cert(vec![expiring, wc.clone()]), &config(true), as_of());
        assert!(!evaluation.lockout_recommended);
        assert!(finding_with_rule(&evaluation, RULE_LOCKOUT).is_empty());

        // Non-critical + breach → findings stand, but no lockout.
        let evaluation = evaluate(&cert(vec![expired_gl, wc]), &config(false), as_of());
        assert_eq!(
            finding_with_rule(&evaluation, RULE_COVERAGE_EXPIRED).len(),
            1
        );
        assert!(!evaluation.lockout_recommended);
        assert!(finding_with_rule(&evaluation, RULE_LOCKOUT).is_empty());
    }

    #[test]
    fn evaluation_is_deterministic_under_policy_reordering() {
        let gl = line(Coverage::GeneralLiability, future());
        let wc = line(Coverage::WorkersComp, future());
        let ordered = evaluate(&cert(vec![gl.clone(), wc.clone()]), &config(true), as_of());
        let reordered = evaluate(&cert(vec![wc, gl]), &config(true), as_of());
        // Evaluation does not implement PartialEq (spine::Finding does not);
        // structural equality via Debug rendering is exact for these types.
        assert_eq!(
            format!("{:?}", ordered.findings),
            format!("{:?}", reordered.findings)
        );
        assert_eq!(ordered.lockout_recommended, reordered.lockout_recommended);
    }

    #[test]
    fn money_formats_without_floats() {
        assert_eq!(format_cents(123_456_789), "$1,234,567.89");
        assert_eq!(format_cents(50), "$0.50");
        assert_eq!(format_cents(0), "$0.00");
        assert_eq!(format_cents(-25), "-$0.25");
        assert_eq!(format_cents(100_000_000_000_000), "$1,000,000,000,000.00");
    }
}
