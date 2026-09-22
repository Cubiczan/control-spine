//! Test anchors for the payroll-spine product block (spec rev 2):
//! cap-crossing period, mid-period proration, bracket boundary exactly at
//! threshold, negative-net block, register variance detection at ±$0.01,
//! plus every rule branch and the fail-closed paths.

use payroll_spine::config::{
    Bracket, BracketTables, EmployerConfig, FicaConfig, FilingStatus, PayrollConfig, SutaConfig,
};
use payroll_spine::engine::{
    compute, fit_annual_tax, CalendarKind, EmployeeInput, EmployeeSummary, PayrollError,
    PayrollInput, PayrollOutcome, PeriodInput, RULE_NEGATIVE_NET, RULE_REGISTER_VARIANCE,
    RULE_TAX_YEAR_MISMATCH,
};
use payroll_spine::pack::{build_pack, canonical_input_bytes, canonical_param_bytes, ENGINE_ID};
use spine::{Finding, Severity, Signoff, SignoffDecision, VerifyError};

// ---------------------------------------------------------------------------
// Fixtures — seed config and input builders (values documented in README)
// ---------------------------------------------------------------------------

fn bracket(lower_cents: i128, rate_micro: i128) -> Bracket {
    Bracket {
        lower_cents,
        rate_micro,
    }
}

fn seed_config() -> PayrollConfig {
    PayrollConfig {
        fica: FicaConfig {
            ss_rate_micro: 6_200_000,                        // 6.2%
            ss_wage_base_cents: 16_860_000,                  // $168,600.00
            medicare_rate_micro: 1_450_000,                  // 1.45%
            additional_medicare_rate_micro: 900_000,         // 0.9%
            additional_medicare_threshold_cents: 20_000_000, // $200,000.00
        },
        employer: EmployerConfig {
            futa_rate_micro: 6_000_000,        // 6.0%
            futa_credit_rate_micro: 5_400_000, // 5.4%
            futa_wage_base_cents: 700_000,     // $7,000.00
            suta: [
                (
                    "CA".to_string(),
                    SutaConfig {
                        rate_micro: 3_400_000,      // 3.4%
                        wage_base_cents: 7_000_000, // $70,000.00
                    },
                ),
                (
                    "TX".to_string(),
                    SutaConfig {
                        rate_micro: 2_700_000,    // 2.7%
                        wage_base_cents: 900_000, // $9,000.00
                    },
                ),
            ]
            .into_iter()
            .collect(),
        },
        brackets: BracketTables {
            single: vec![
                bracket(0, 10_000_000),
                bracket(1_160_000, 12_000_000),
                bracket(4_715_000, 22_000_000),
                bracket(10_052_500, 24_000_000),
                bracket(19_195_000, 32_000_000),
                bracket(24_372_500, 35_000_000),
                bracket(60_935_000, 37_000_000),
            ],
            married: vec![
                bracket(0, 10_000_000),
                bracket(2_320_000, 12_000_000),
                bracket(9_430_000, 22_000_000),
                bracket(20_105_000, 24_000_000),
                bracket(38_390_000, 32_000_000),
                bracket(48_745_000, 35_000_000),
                bracket(73_120_000, 37_000_000),
            ],
        },
        retirement_401k_pre_tax: true,
        register_tolerance_cents: 0,
        valid_for_tax_year: None,
    }
}

fn employee(id: &str) -> EmployeeInput {
    EmployeeInput {
        employee_id: id.to_string(),
        filing_status: FilingStatus::Single,
        state: "TX".to_string(),
        annual_salary_cents: 12_000_000, // $120,000.00/year
        start_date: None,
        end_date: None,
        ytd_ss_taxable_cents: 0,
        ytd_medicare_taxable_cents: 0,
        employer_ytd_futa_cents: 0,
        employer_ytd_suta_cents: 0,
        section125_cents: 0,
        retirement_401k_cents: 0,
        provider_net_cents: None,
    }
}

fn semi_march_period() -> PeriodInput {
    PeriodInput {
        calendar: CalendarKind::SemiMonthly,
        start: "2026-03-01".to_string(),
        end: "2026-03-15".to_string(),
    }
}

fn inputs(period: PeriodInput, employees: Vec<EmployeeInput>) -> PayrollInput {
    PayrollInput { period, employees }
}

fn one(emp: EmployeeInput) -> PayrollInput {
    inputs(semi_march_period(), vec![emp])
}

fn first_summary(outcome: &PayrollOutcome) -> &EmployeeSummary {
    &outcome.summaries[0]
}

fn find_rule<'a>(outcome: &'a PayrollOutcome, rule: &str) -> Option<&'a Finding> {
    outcome.findings.iter().find(|f| f.rule_id == rule)
}

fn breach_employee() -> EmployeeInput {
    let mut e = employee("E1");
    e.annual_salary_cents = 120_000; // $5,000.00 per period at 24 periods
    e.section125_cents = 100_000;
    e.retirement_401k_cents = 100_000;
    e
}

fn approve(actor: &str, subject: &str) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "payroll manager".to_string(),
        subject: subject.to_string(),
        decision: SignoffDecision::Approve,
        at: "2026-03-16T00:00:00Z".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Declared tax-year staleness
// ---------------------------------------------------------------------------

#[test]
fn tax_year_mismatch_emits_a_warn_not_a_refusal() {
    let mut config = seed_config();
    config.valid_for_tax_year = Some(2025);
    let inputs = one(employee("E1"));
    let outcome = compute(&inputs, &config).unwrap();
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.rule_id == RULE_TAX_YEAR_MISMATCH
            && f.severity == Severity::Warn
            && f.subject == "period:2026-03-01"
            && !f.requires_signoff));
    // The pack still builds and verifies — a warning never blocks.
    let pack = build_pack(&inputs, &config, &outcome).unwrap();
    let input_bytes = canonical_input_bytes(&inputs).unwrap();
    let param_bytes = canonical_param_bytes(&config).unwrap();
    assert!(pack.verify(&input_bytes, &param_bytes).is_ok());
}

#[test]
fn tax_year_match_or_absent_is_silent() {
    let mut matching = seed_config();
    matching.valid_for_tax_year = Some(2026);
    assert!(compute(&one(employee("E1")), &matching)
        .unwrap()
        .findings
        .iter()
        .all(|f| f.rule_id != RULE_TAX_YEAR_MISMATCH));

    let absent = seed_config();
    assert!(compute(&one(employee("E1")), &absent)
        .unwrap()
        .findings
        .iter()
        .all(|f| f.rule_id != RULE_TAX_YEAR_MISMATCH));
}

// ---------------------------------------------------------------------------
// Period calendars and proration
// ---------------------------------------------------------------------------

#[test]
fn semi_monthly_full_period_pays_annual_over_24() {
    let config = seed_config();
    let outcome = compute(&one(employee("E1")), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.gross_cents, 500_000); // $5,000.00
    assert_eq!(s.employed_days, 15);
    // Withholdings: FIT $910.10, SS $310.00, Medicare $72.50.
    assert_eq!(s.fit_cents, 91_010);
    assert_eq!(s.ss_cents, 31_000);
    assert_eq!(s.medicare_cents, 7_250);
    assert_eq!(s.net_cents, 370_740);
    assert!(find_rule(&outcome, RULE_NEGATIVE_NET).is_none());
}

#[test]
fn biweekly_full_period_pays_annual_over_26() {
    let config = seed_config();
    let period = PeriodInput {
        calendar: CalendarKind::Biweekly,
        start: "2026-03-01".to_string(),
        end: "2026-03-14".to_string(),
    };
    let outcome = compute(&inputs(period, vec![employee("E1")]), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.employed_days, 14);
    // 12,000,000 / 26 = 461,538.46 -> 461,538 half-up (truncation would
    // give the same here; the half-up engine tests below pin the rounding).
    assert_eq!(s.gross_cents, 461_538);
}

#[test]
fn mid_period_start_prorates_by_calendar_days() {
    let config = seed_config();
    let mut e = employee("E1");
    e.start_date = Some("2026-03-08".to_string()); // 8 of 15 calendar days
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.employed_days, 8);
    // 500,000 * 8 / 15 = 266,666.67 -> 266,667 half-up.
    assert_eq!(s.gross_cents, 266_667);
}

#[test]
fn mid_period_separation_prorates_by_calendar_days() {
    let config = seed_config();
    let mut e = employee("E1");
    e.end_date = Some("2026-03-10".to_string()); // 10 of 15 calendar days
    let outcome = compute(&one(e), &config).unwrap();
    // 500,000 * 10 / 15 = 333,333.33 -> 333,333 half-up.
    assert_eq!(first_summary(&outcome).gross_cents, 333_333);
}

#[test]
fn employee_outside_period_earns_nothing() {
    let config = seed_config();
    let mut e = employee("E1");
    e.start_date = Some("2026-04-01".to_string()); // hired after the period
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.employed_days, 0);
    assert_eq!(s.gross_cents, 0);
    assert_eq!(s.net_cents, 0);
}

#[test]
fn invalid_semi_monthly_period_is_refused() {
    let config = seed_config();
    let period = PeriodInput {
        calendar: CalendarKind::SemiMonthly,
        start: "2026-03-05".to_string(),
        end: "2026-03-19".to_string(),
    };
    let err = compute(&inputs(period, vec![employee("E1")]), &config).unwrap_err();
    assert!(matches!(err, PayrollError::InvalidPeriod(_)));
}

#[test]
fn invalid_biweekly_period_is_refused() {
    let config = seed_config();
    let period = PeriodInput {
        calendar: CalendarKind::Biweekly,
        start: "2026-03-01".to_string(),
        end: "2026-03-13".to_string(), // 13 days, not 14
    };
    let err = compute(&inputs(period, vec![employee("E1")]), &config).unwrap_err();
    assert!(matches!(err, PayrollError::InvalidPeriod(_)));
}

// ---------------------------------------------------------------------------
// Social Security wage-base cap
// ---------------------------------------------------------------------------

#[test]
fn ss_applies_below_the_wage_base() {
    let config = seed_config();
    let outcome = compute(&one(employee("E1")), &config).unwrap();
    assert_eq!(first_summary(&outcome).ss_cents, 31_000); // 500,000 * 6.2%
}

#[test]
fn ss_cap_crossing_taxes_only_the_excess_above_the_base() {
    let config = seed_config();
    let mut e = employee("E1");
    e.ytd_ss_taxable_cents = 16_500_000; // $168,600 cap; $165,000 YTD
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.ss_taxable_cents, 360_000); // only the excess is taxable
    assert_eq!(s.ss_cents, 22_320); // $223.20
}

#[test]
fn ss_fully_above_the_cap_taxes_nothing() {
    let config = seed_config();
    let mut e = employee("E1");
    e.ytd_ss_taxable_cents = 17_000_000;
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.ss_taxable_cents, 0);
    assert_eq!(s.ss_cents, 0);
}

// ---------------------------------------------------------------------------
// Medicare and the additional rate
// ---------------------------------------------------------------------------

#[test]
fn additional_medicare_applies_only_to_the_excess_over_the_threshold() {
    let config = seed_config();
    let mut crosser = employee("E1");
    crosser.ytd_medicare_taxable_cents = 19_800_000; // $200,000 threshold
    let outcome = compute(&one(crosser), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.medicare_cents, 7_250);
    assert_eq!(s.additional_medicare_taxable_cents, 300_000);
    assert_eq!(s.additional_medicare_cents, 2_700);

    // Already past the threshold: every dollar of this period's wages is
    // above it, so the full period wage is additionally taxable.
    let mut past = employee("E2");
    past.ytd_medicare_taxable_cents = 20_500_000;
    let outcome = compute(&one(past), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.additional_medicare_taxable_cents, 500_000);
    assert_eq!(s.additional_medicare_cents, 4_500);
}

// ---------------------------------------------------------------------------
// Pre-tax ordering: Section 125, then 401(k) per config flag
// ---------------------------------------------------------------------------

#[test]
fn section_125_reduces_fit_and_fica_wage_bases() {
    let config = seed_config();
    let mut e = employee("E1");
    e.section125_cents = 20_833;
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.fit_taxable_cents, 479_167); // 500,000 - 20,833
    assert_eq!(s.ss_taxable_cents, 479_167); // Section 125 reduces FICA wages too
    assert_eq!(s.ss_cents, 29_708);
    assert_eq!(s.fit_cents, 86_011);
}

#[test]
fn pre_tax_401k_reduces_fit_but_not_fica() {
    let config = seed_config(); // retirement_401k_pre_tax = true
    let mut e = employee("E1");
    e.retirement_401k_cents = 50_000;
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.fit_taxable_cents, 450_000);
    assert_eq!(s.fit_cents, 79_010);
    // FICA/Medicare wages are untouched by the deferral.
    assert_eq!(s.ss_taxable_cents, 500_000);
    assert_eq!(s.ss_cents, 31_000);
}

#[test]
fn post_tax_401k_reduces_neither_fit_nor_fica() {
    let mut config = seed_config();
    config.retirement_401k_pre_tax = false;
    let mut e = employee("E1");
    e.retirement_401k_cents = 50_000;
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    assert_eq!(s.fit_taxable_cents, 500_000);
    assert_eq!(s.fit_cents, 91_010);
    assert_eq!(s.ss_taxable_cents, 500_000);
    // The deferral still leaves net pay.
    assert_eq!(s.net_cents, 320_740);
}

// ---------------------------------------------------------------------------
// Progressive bracket withholding
// ---------------------------------------------------------------------------

#[test]
fn bracket_boundary_exactly_at_threshold_is_taxed_in_the_lower_bracket() {
    let config = seed_config();
    let single = config.brackets.table(FilingStatus::Single);
    // Annualized wages exactly at the 12% boundary: every cent is 10%.
    assert_eq!(fit_annual_tax(1_160_000, single).unwrap(), 116_000);
    // 50,000 cents of annualized wages above the boundary are marginal at 12%.
    assert_eq!(fit_annual_tax(1_210_000, single).unwrap(), 122_000);
}

#[test]
fn fit_is_marginal_across_brackets_and_deannualized_half_up() {
    let config = seed_config();
    let mut e = employee("E1");
    e.annual_salary_cents = 1_200_000; // $50,000.00 per semi-monthly period
    let outcome = compute(&one(e), &config).unwrap();
    // Annualized 1,200,000 -> 116,000 + 40,000 * 12% = 120,800
    // -> 120,800 / 24 = 5,033.33 -> 5,033 half-up.
    assert_eq!(first_summary(&outcome).fit_cents, 5_033);
}

// ---------------------------------------------------------------------------
// Employer-side taxes
// ---------------------------------------------------------------------------

#[test]
fn employer_fica_match_covers_regular_ss_and_medicare_only() {
    let config = seed_config();
    let mut e = employee("E1");
    e.ytd_medicare_taxable_cents = 19_800_000; // drags in the additional rate
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    // 31,000 SS + 7,250 Medicare = 38,250 — the 2,700 additional Medicare
    // is employee-only and is not matched.
    assert_eq!(s.employer_fica_match_cents, 38_250);
}

#[test]
fn futa_uses_credit_reduced_rate_and_wage_base_cap() {
    let config = seed_config(); // 6.0% - 5.4% credit = 0.6% effective
    let mut e = employee("E1");
    e.employer_ytd_futa_cents = 650_000;
    e.annual_salary_cents = 24_000_000; // $1,000,000... i.e. $10,000.00 per period
    let outcome = compute(&one(e), &config).unwrap();
    let s = first_summary(&outcome);
    // $7,000 base; $6,500 YTD -> $500.00 taxable at 0.6% = $3.00.
    assert_eq!(s.employer_futa_cents, 300);
}

#[test]
fn suta_uses_the_state_schedule() {
    let config = seed_config();
    let mut tx = employee("TX-1");
    tx.state = "TX".to_string();
    let mut ca = employee("CA-1");
    ca.state = "CA".to_string();
    let outcome = compute(&inputs(semi_march_period(), vec![tx, ca]), &config).unwrap();
    // 500,000 gross: TX 2.7% -> 13,500; CA 3.4% -> 17,000.
    assert_eq!(outcome.summaries[0].employer_suta_cents, 13_500);
    assert_eq!(outcome.summaries[1].employer_suta_cents, 17_000);
}

// ---------------------------------------------------------------------------
// Negative net pay blocks the run (breach + human lock)
// ---------------------------------------------------------------------------

#[test]
fn negative_net_blocks_the_run_as_a_breach() {
    let config = seed_config();
    let outcome = compute(&one(breach_employee()), &config).unwrap();
    let s = first_summary(&outcome);
    // Wage bases clamp at zero — deductions never generate negative taxes.
    assert_eq!(s.fit_cents, 0);
    assert_eq!(s.ss_cents, 0);
    assert_eq!(s.medicare_cents, 0);
    assert_eq!(s.net_cents, -195_000);
    let finding =
        find_rule(&outcome, RULE_NEGATIVE_NET).expect("negative net must raise a breach finding");
    assert_eq!(finding.severity, Severity::Breach);
    assert!(finding.requires_signoff);
    assert_eq!(finding.subject, "E1");
}

#[test]
fn breach_pack_refuses_verify_without_signoff() {
    let config = seed_config();
    let inputs = one(breach_employee());
    let outcome = compute(&inputs, &config).unwrap();
    let pack = build_pack(&inputs, &config, &outcome).unwrap();
    let input_bytes = canonical_input_bytes(&inputs).unwrap();
    let param_bytes = canonical_param_bytes(&config).unwrap();
    assert_eq!(
        pack.verify(&input_bytes, &param_bytes),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_NEGATIVE_NET.to_string()
        })
    );
}

#[test]
fn subject_scoped_signoff_resolves_breach_and_wrong_subject_does_not() {
    let config = seed_config();
    let inputs = one(breach_employee());
    let outcome = compute(&inputs, &config).unwrap();
    let input_bytes = canonical_input_bytes(&inputs).unwrap();
    let param_bytes = canonical_param_bytes(&config).unwrap();

    // An approval naming another subject cannot resolve E1's breach.
    let mut wrong = build_pack(&inputs, &config, &outcome).unwrap();
    wrong.signoffs.push(approve("sam", "E2"));
    assert_eq!(
        wrong.sealed().verify(&input_bytes, &param_bytes),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_NEGATIVE_NET.to_string()
        })
    );

    // An approval naming E1 resolves it; re-sealing makes the body verify.
    let mut right = build_pack(&inputs, &config, &outcome).unwrap();
    right.signoffs.push(approve("sam", "E1"));
    assert_eq!(right.sealed().verify(&input_bytes, &param_bytes), Ok(()));
}

#[test]
fn engine_cannot_countersign_its_own_pack() {
    let config = seed_config();
    let inputs = one(breach_employee());
    let outcome = compute(&inputs, &config).unwrap();
    let input_bytes = canonical_input_bytes(&inputs).unwrap();
    let param_bytes = canonical_param_bytes(&config).unwrap();

    let mut self_signed = build_pack(&inputs, &config, &outcome).unwrap();
    self_signed.signoffs.push(approve(ENGINE_ID, "E1"));
    // The void receipt cannot resolve the breach — a human must sign.
    assert!(self_signed
        .sealed()
        .verify(&input_bytes, &param_bytes)
        .is_err());
}

// ---------------------------------------------------------------------------
// Register variance detection
// ---------------------------------------------------------------------------

#[test]
fn register_variance_is_flagged_at_one_cent() {
    let config = seed_config();
    let clean = compute(&one(employee("E1")), &config).unwrap();
    let computed = clean.summaries[0].net_cents;

    let mut e = employee("E1");
    e.provider_net_cents = Some(computed - 1); // one cent short
    let outcome = compute(&one(e), &config).unwrap();
    let finding =
        find_rule(&outcome, RULE_REGISTER_VARIANCE).expect("a one-cent variance must flag");
    assert_eq!(finding.severity, Severity::Warn);
    assert!(!finding.requires_signoff);
    assert_eq!(finding.subject, "E1");
}

#[test]
fn register_within_tolerance_produces_no_finding() {
    let config = seed_config();
    let clean = compute(&one(employee("E1")), &config).unwrap();
    let computed = clean.summaries[0].net_cents;

    let mut e = employee("E1");
    e.provider_net_cents = Some(computed); // exact match
    let outcome = compute(&one(e), &config).unwrap();
    assert!(find_rule(&outcome, RULE_REGISTER_VARIANCE).is_none());
}

// ---------------------------------------------------------------------------
// Fail-closed evidence packs and determinism
// ---------------------------------------------------------------------------

#[test]
fn tampered_pack_fails_verify() {
    let config = seed_config();
    let run_inputs = one(employee("E1"));
    let outcome = compute(&run_inputs, &config).unwrap();
    let pack = build_pack(&run_inputs, &config, &outcome).unwrap();
    let input_bytes = canonical_input_bytes(&run_inputs).unwrap();
    let param_bytes = canonical_param_bytes(&config).unwrap();
    assert_eq!(pack.verify(&input_bytes, &param_bytes), Ok(()));

    // Body tampering (a "cleaner" summary) breaks the seal.
    let mut tampered = pack.clone();
    tampered.findings[0].message = "gross 1c".to_string();
    assert_eq!(
        tampered.verify(&input_bytes, &param_bytes),
        Err(VerifyError::BodyHashMismatch)
    );

    // Different inputs (a second employee joins) fail the provenance hash.
    let other = inputs(semi_march_period(), vec![employee("E1"), employee("E2")]);
    let other_outcome = compute(&other, &config).unwrap();
    let other_pack = build_pack(&other, &config, &other_outcome).unwrap();
    assert_eq!(
        other_pack.verify(&input_bytes, &param_bytes),
        Err(VerifyError::HashMismatch { field: "inputs" })
    );
}

#[test]
fn canonical_hashes_are_stable_across_json_formatting() {
    let config = seed_config();
    let raw_pretty = r#"{
        "period": {"calendar": "semi_monthly", "start": "2026-03-01", "end": "2026-03-15"},
        "employees": [
            {"employee_id": "E1", "filing_status": "single", "state": "TX",
             "annual_salary_cents": 12000000,
             "ytd_ss_taxable_cents": 0, "ytd_medicare_taxable_cents": 0,
             "employer_ytd_futa_cents": 0, "employer_ytd_suta_cents": 0,
             "section125_cents": 0, "retirement_401k_cents": 0}
        ]
    }"#;
    let raw_compact = r#"{"employees":[{"retirement_401k_cents":0,"section125_cents":0,"employer_ytd_suta_cents":0,"employer_ytd_futa_cents":0,"ytd_medicare_taxable_cents":0,"ytd_ss_taxable_cents":0,"annual_salary_cents":12000000,"state":"TX","filing_status":"single","employee_id":"E1"}],"period":{"end":"2026-03-15","start":"2026-03-01","calendar":"semi_monthly"}}"#;
    let a: PayrollInput = serde_json::from_str(raw_pretty).unwrap();
    let b: PayrollInput = serde_json::from_str(raw_compact).unwrap();
    assert_eq!(
        canonical_input_bytes(&a).unwrap(),
        canonical_input_bytes(&b).unwrap()
    );

    let outcome = compute(&a, &config).unwrap();
    let pack_a = build_pack(&a, &config, &outcome).unwrap();
    let pack_b = build_pack(&b, &config, &outcome).unwrap();
    assert_eq!(pack_a.inputs_hash, pack_b.inputs_hash);
    assert_eq!(pack_a.body_hash, pack_b.body_hash);
    // A pack produced from either formatting verifies against both.
    assert_eq!(
        pack_a.verify(
            &canonical_input_bytes(&b).unwrap(),
            &canonical_param_bytes(&config).unwrap()
        ),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Fail-closed input and config validation
// ---------------------------------------------------------------------------

#[test]
fn unknown_state_is_refused_fail_closed() {
    let config = seed_config();
    let mut e = employee("E1");
    e.state = "ZZ".to_string();
    let err = compute(&one(e), &config).unwrap_err();
    assert!(matches!(err, PayrollError::MissingSutaSchedule { .. }));
}

#[test]
fn empty_run_is_refused() {
    let config = seed_config();
    let err = compute(&inputs(semi_march_period(), vec![]), &config).unwrap_err();
    assert_eq!(err, PayrollError::EmptyRun);
}

#[test]
fn invalid_config_is_refused() {
    let mut config = seed_config();
    config.employer.futa_credit_rate_micro = 7_000_000; // credit above federal rate
    let err = compute(&one(employee("E1")), &config).unwrap_err();
    assert!(matches!(err, PayrollError::InvalidConfig(_)));
}

#[test]
fn unknown_input_field_is_refused() {
    let raw = r#"{"period":{"calendar":"semi_monthly","start":"2026-03-01","end":"2026-03-15"},"employees":[],"bogus":1}"#;
    let parsed: Result<PayrollInput, _> = serde_json::from_str(raw);
    assert!(parsed.is_err()); // deny_unknown_fields — schema-checked inputs
}

#[test]
fn negative_input_amount_is_refused() {
    let config = seed_config();
    let mut e = employee("E1");
    e.section125_cents = -1;
    let err = compute(&one(e), &config).unwrap_err();
    assert!(matches!(err, PayrollError::NegativeAmount { .. }));
}

// ---------------------------------------------------------------------------
// CLI end-to-end (compute | verify) against real files
// ---------------------------------------------------------------------------

mod cli_tests {
    use super::seed_config;
    use payroll_spine::cli::{run, Cli, Command};
    use payroll_spine::pack::ENGINE_ID;
    use std::fs;
    use std::path::PathBuf;

    const INPUTS_JSON: &str = r#"{
        "period": {"calendar": "semi_monthly", "start": "2026-03-01", "end": "2026-03-15"},
        "employees": [
            {"employee_id": "E1", "filing_status": "single", "state": "TX",
             "annual_salary_cents": 12000000}
        ]
    }"#;

    fn write_fixture(tag: &str, name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("payroll-spine-tests-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{tag}-{name}"));
        fs::write(&path, contents).unwrap();
        path
    }

    fn config_path(tag: &str) -> PathBuf {
        let config_json = serde_json::to_string(&seed_config()).unwrap();
        write_fixture(tag, "config.json", &config_json)
    }

    #[test]
    fn cli_compute_writes_pack_and_verify_accepts_it() {
        let inputs_path = write_fixture("happy", "inputs.json", INPUTS_JSON);
        let config = config_path("happy");
        let pack_path = write_fixture("happy", "pack.json", "");

        run(Cli {
            command: Command::Compute {
                inputs: inputs_path.clone(),
                config: config.clone(),
                out: Some(pack_path.clone()),
            },
        })
        .expect("compute must succeed");

        let written = fs::read_to_string(&pack_path).unwrap();
        assert!(written.contains("\"inputs_hash\""));
        assert!(written.contains("\"body_hash\""));
        assert!(written.contains(&format!("\"engine_id\": \"{ENGINE_ID}\"")));

        // verify accepts the pack against the same inputs and config.
        run(Cli {
            command: Command::Verify {
                pack: pack_path,
                inputs: inputs_path,
                config,
            },
        })
        .expect("verify must accept the computed pack");
    }

    #[test]
    fn cli_verify_refuses_a_tampered_pack() {
        let inputs_path = write_fixture("tamper", "inputs.json", INPUTS_JSON);
        let config = config_path("tamper");
        let pack_path = write_fixture("tamper", "pack.json", "");

        run(Cli {
            command: Command::Compute {
                inputs: inputs_path.clone(),
                config: config.clone(),
                out: Some(pack_path.clone()),
            },
        })
        .unwrap();

        let mut pack: spine::EvidencePack =
            serde_json::from_str(&fs::read_to_string(&pack_path).unwrap()).unwrap();
        pack.findings[0].message = "tampered".to_string();
        fs::write(&pack_path, serde_json::to_string_pretty(&pack).unwrap()).unwrap();

        let err = run(Cli {
            command: Command::Verify {
                pack: pack_path,
                inputs: inputs_path,
                config,
            },
        })
        .unwrap_err();
        assert!(err.contains("REFUSED"), "expected refusal, got: {err}");
    }

    #[test]
    fn cli_explain_succeeds_on_valid_inputs() {
        let inputs_path = write_fixture("explain", "inputs.json", INPUTS_JSON);
        let config = config_path("explain");
        run(Cli {
            command: Command::Explain {
                inputs: inputs_path,
                config,
            },
        })
        .expect("explain must succeed");
    }
}
