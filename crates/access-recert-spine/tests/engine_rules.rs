//! Rule-branch, boundary, and quarantine tests for the pure engine.
//!
//! Covers every test anchor named in the product block: leaver-with-active-
//! entitlement breach, recycled-email non-match, quarantine path, four-eyes
//! on privileged retention — plus every rule branch, the threshold and
//! grace-window boundaries, schema validation, and determinism.

mod common;

use spine::{Finding, Severity, SignoffDecision};

use access_recert_spine::engine::{
    self, RULE_LEAVER_ACTIVE, RULE_ORPHAN_MANAGER, RULE_ORPHAN_SYSTEM, RULE_PRIVILEGED_FOUR_EYES,
    RULE_QUARANTINE, RULE_STALE_AUTH,
};
use access_recert_spine::model::validate;

use common::{approval, campaign, config, d, entitlement, identity, CAMPAIGN_DATE, ENGINE};

fn rule_ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

// ---- Leaver rule ---------------------------------------------------------

#[test]
fn leaver_with_active_entitlement_is_breach() {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2026-03-01"));
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), leaver], vec![entitlement("ENT-1")]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_LEAVER_ACTIVE);
    assert_eq!(findings[0].severity, Severity::Breach);
    assert_eq!(findings[0].subject, "ENT-1");
    assert!(findings[0].requires_signoff);
}

#[test]
fn separation_day_before_campaign_is_leaver() {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2026-09-21"));
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), leaver], vec![entitlement("ENT-1")]),
        &config(),
        ENGINE,
    );
    assert_eq!(rule_ids(&findings), vec![RULE_LEAVER_ACTIVE]);
}

#[test]
fn separation_on_campaign_date_is_not_yet_leaver() {
    let mut departing = identity("E-1");
    departing.separation_date = Some(d(CAMPAIGN_DATE));
    let findings = engine::evaluate(
        &campaign(
            vec![identity("E-MGR"), departing],
            vec![entitlement("ENT-1")],
        ),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

#[test]
fn separation_after_campaign_is_not_leaver() {
    let mut departing = identity("E-1");
    departing.separation_date = Some(d("2026-10-01"));
    let findings = engine::evaluate(
        &campaign(
            vec![identity("E-MGR"), departing],
            vec![entitlement("ENT-1")],
        ),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

#[test]
fn separated_identity_without_entitlements_is_silent() {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2026-01-01"));
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), leaver], vec![]),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

// ---- Identity matching: employee_id, never email -------------------------

#[test]
fn recycled_email_is_never_used_to_match_identities() {
    // The leaver's mailbox is recycled to a new hire. Matching by email
    // would misattribute; matching by employee_id must not.
    let mut leaver = identity("E-OLD");
    leaver.email = "shared@corp.example".to_string();
    leaver.separation_date = Some(d("2026-01-01"));

    let mut hire = identity("E-NEW");
    hire.email = "shared@corp.example".to_string();
    hire.hire_date = d("2026-06-01");

    let mut new_hire_entitlement = entitlement("ENT-NEW");
    new_hire_entitlement.employee_id = "E-NEW".to_string();
    new_hire_entitlement.email = "shared@corp.example".to_string();
    let mut leaver_entitlement = entitlement("ENT-OLD");
    leaver_entitlement.employee_id = "E-OLD".to_string();
    leaver_entitlement.email = "shared@corp.example".to_string();

    let findings = engine::evaluate(
        &campaign(
            vec![identity("E-MGR"), leaver, hire],
            vec![new_hire_entitlement, leaver_entitlement],
        ),
        &config(),
        ENGINE,
    );
    // Only the leaver's own entitlement is flagged; the new hire's is not.
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].subject, "ENT-OLD");
    assert_eq!(findings[0].rule_id, RULE_LEAVER_ACTIVE);
}

#[test]
fn entitlement_email_field_is_ignored_even_when_it_collides() {
    // The entitlement reports the HR email of an active identity but is
    // keyed to an unresolvable employee_id: quarantine, not attribution.
    let mut unmatched = entitlement("ENT-Q");
    unmatched.employee_id = "E-404".to_string();
    unmatched.email = "one@corp.example".to_string(); // E-1's email
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), identity("E-1")], vec![unmatched]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_QUARANTINE);
    assert_eq!(findings[0].subject, "ENT-Q");
}

// ---- Quarantine (fail-closed) ---------------------------------------------

#[test]
fn unmatched_employee_id_is_quarantined_never_dropped() {
    let mut unmatched = entitlement("ENT-Q");
    unmatched.employee_id = "E-404".to_string();
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR")], vec![unmatched]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_QUARANTINE);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(findings[0].requires_signoff);
    assert_eq!(findings[0].subject, "ENT-Q");
}

#[test]
fn blank_employee_id_is_quarantined() {
    let mut unmatched = entitlement("ENT-Q");
    unmatched.employee_id = String::new();
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR")], vec![unmatched]),
        &config(),
        ENGINE,
    );
    assert_eq!(rule_ids(&findings), vec![RULE_QUARANTINE]);
}

// ---- Orphan-system rule ----------------------------------------------------

#[test]
fn entitlement_on_unknown_system_is_breach() {
    let mut shadow = entitlement("ENT-S");
    shadow.system_id = "shadow-saas".to_string();
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), identity("E-1")], vec![shadow]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_ORPHAN_SYSTEM);
    assert_eq!(findings[0].severity, Severity::Breach);
}

// ---- Orphan-manager rule ---------------------------------------------------

#[test]
fn missing_manager_record_is_warn() {
    let mut orphan = identity("E-1");
    orphan.manager_id = None;
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), orphan], vec![entitlement("ENT-1")]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_ORPHAN_MANAGER);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(!findings[0].requires_signoff);
}

#[test]
fn dangling_manager_id_is_warn() {
    let mut orphan = identity("E-1");
    orphan.manager_id = Some("E-GONE".to_string());
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), orphan], vec![entitlement("ENT-1")]),
        &config(),
        ENGINE,
    );
    assert_eq!(rule_ids(&findings), vec![RULE_ORPHAN_MANAGER]);
    assert!(findings[0].message.contains("E-GONE"));
}

// ---- New-hire grace window -------------------------------------------------

#[test]
fn new_hire_grace_exempts_stale_and_manager_rules() {
    let mut hire = identity("E-NEW");
    hire.hire_date = d("2026-09-12"); // 10 days before campaign
    hire.manager_id = None;
    let mut granted = entitlement("ENT-N");
    granted.employee_id = "E-NEW".to_string();
    granted.last_authenticated_at = None; // would be stale without grace
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), hire], vec![granted]),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

#[test]
fn grace_window_boundary_is_inclusive_then_expires() {
    // Hired exactly new_hire_grace_days (30) before the campaign: exempt.
    let mut at_edge = identity("E-NEW");
    at_edge.hire_date = d("2026-08-23");
    at_edge.manager_id = None;
    let mut granted = entitlement("ENT-N");
    granted.employee_id = "E-NEW".to_string();
    granted.last_authenticated_at = None;
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), at_edge], vec![granted]),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());

    // Hired 31 days before the campaign: grace has expired, stale fires.
    let mut expired = identity("E-NEW");
    expired.hire_date = d("2026-08-22");
    expired.manager_id = None;
    let mut granted = entitlement("ENT-N");
    granted.employee_id = "E-NEW".to_string();
    granted.last_authenticated_at = None;
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), expired], vec![granted]),
        &config(),
        ENGINE,
    );
    assert_eq!(
        rule_ids(&findings),
        // Sorted by (subject, rule_id) per the family determinism contract.
        vec![RULE_ORPHAN_MANAGER, RULE_STALE_AUTH]
    );
}

#[test]
fn grace_does_not_exempt_leaver_or_unknown_system_rules() {
    let mut hire = identity("E-NEW");
    hire.hire_date = d("2026-09-12"); // inside grace
    hire.separation_date = Some(d("2026-09-15")); // separated after hire
    let mut shadow = entitlement("ENT-S");
    shadow.employee_id = "E-NEW".to_string();
    shadow.system_id = "shadow-saas".to_string();
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), hire], vec![shadow]),
        &config(),
        ENGINE,
    );
    assert_eq!(
        rule_ids(&findings),
        vec![RULE_LEAVER_ACTIVE, RULE_ORPHAN_SYSTEM]
    );
}

// ---- Stale rule ------------------------------------------------------------

#[test]
fn auth_exactly_stale_days_ago_is_within_window() {
    // 2026-06-24 is exactly 90 days before the campaign — inside.
    let mut recent = entitlement("ENT-1");
    recent.last_authenticated_at = Some(d("2026-06-24"));
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), identity("E-1")], vec![recent]),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

#[test]
fn auth_one_day_past_window_is_stale() {
    let mut stale = entitlement("ENT-1");
    stale.last_authenticated_at = Some(d("2026-06-23")); // 91 days
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), identity("E-1")], vec![stale]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_STALE_AUTH);
    assert_eq!(findings[0].severity, Severity::Warn);
}

#[test]
fn never_authenticated_is_stale() {
    let mut unused = entitlement("ENT-1");
    unused.last_authenticated_at = None;
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), identity("E-1")], vec![unused]),
        &config(),
        ENGINE,
    );
    assert_eq!(rule_ids(&findings), vec![RULE_STALE_AUTH]);
}

// ---- Privileged four-eyes rule ----------------------------------------------

#[test]
fn privileged_retained_with_two_distinct_approvers() {
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    input.retention_approvals = vec![
        approval("alice", "ENT-P", SignoffDecision::Approve),
        approval("bob", "ENT-P", SignoffDecision::Approve),
    ];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert!(findings.is_empty());
}

#[test]
fn privileged_with_one_approver_finds_four_eyes_gap() {
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    input.retention_approvals = vec![approval("alice", "ENT-P", SignoffDecision::Approve)];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, RULE_PRIVILEGED_FOUR_EYES);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(findings[0].requires_signoff);
}

#[test]
fn four_eyes_counts_signers_case_insensitively() {
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    // Same signer in different cases: one distinct signer, not two.
    input.retention_approvals = vec![
        approval("alice", "ENT-P", SignoffDecision::Approve),
        approval("Alice", "ENT-P", SignoffDecision::Approve),
    ];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert_eq!(rule_ids(&findings), vec![RULE_PRIVILEGED_FOUR_EYES]);
}

#[test]
fn rejected_approval_does_not_count_toward_four_eyes() {
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    input.retention_approvals = vec![
        approval("alice", "ENT-P", SignoffDecision::Approve),
        approval("bob", "ENT-P", SignoffDecision::Reject),
    ];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert_eq!(rule_ids(&findings), vec![RULE_PRIVILEGED_FOUR_EYES]);
}

#[test]
fn engine_actor_approval_is_void_for_four_eyes() {
    // Separation of duties: the producing engine cannot count as an
    // approver of its own campaign.
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    input.retention_approvals = vec![
        approval(ENGINE, "ENT-P", SignoffDecision::Approve),
        approval("alice", "ENT-P", SignoffDecision::Approve),
    ];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert_eq!(rule_ids(&findings), vec![RULE_PRIVILEGED_FOUR_EYES]);
}

#[test]
fn four_eyes_approvals_are_subject_scoped() {
    let mut privileged = entitlement("ENT-P");
    privileged.privileged = true;
    let mut input = campaign(vec![identity("E-MGR"), identity("E-1")], vec![privileged]);
    input.retention_approvals = vec![
        approval("alice", "ENT-OTHER", SignoffDecision::Approve),
        approval("bob", "ENT-OTHER", SignoffDecision::Approve),
    ];
    let findings = engine::evaluate(&input, &config(), ENGINE);
    assert_eq!(rule_ids(&findings), vec![RULE_PRIVILEGED_FOUR_EYES]);
}

#[test]
fn non_privileged_entitlement_needs_no_approvals() {
    let findings = engine::evaluate(
        &campaign(
            vec![identity("E-MGR"), identity("E-1")],
            vec![entitlement("ENT-1")],
        ),
        &config(),
        ENGINE,
    );
    assert!(findings.is_empty());
}

// ---- Composition, determinism, validation -----------------------------------

#[test]
fn multiple_findings_compose_on_one_entitlement() {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2026-03-01"));
    leaver.manager_id = None;
    let mut flagged = entitlement("ENT-X");
    flagged.system_id = "shadow-saas".to_string();
    flagged.privileged = true;
    flagged.last_authenticated_at = None;
    let findings = engine::evaluate(
        &campaign(vec![identity("E-MGR"), leaver], vec![flagged]),
        &config(),
        ENGINE,
    );
    assert_eq!(findings.len(), 5);
    // Sorted by (subject, rule_id).
    assert_eq!(
        rule_ids(&findings),
        vec![
            RULE_LEAVER_ACTIVE,
            RULE_ORPHAN_MANAGER,
            RULE_ORPHAN_SYSTEM,
            RULE_PRIVILEGED_FOUR_EYES,
            RULE_STALE_AUTH,
        ]
    );
    assert!(findings.iter().all(|f| f.subject == "ENT-X"));
}

#[test]
fn findings_are_deterministic_and_sorted() {
    let mut leaver = identity("E-2");
    leaver.separation_date = Some(d("2026-03-01"));
    let mut stale = entitlement("ENT-A");
    stale.employee_id = "E-2".to_string();
    stale.last_authenticated_at = None;
    let mut shadow = entitlement("ENT-B");
    shadow.system_id = "shadow-saas".to_string();
    let input = campaign(
        vec![identity("E-MGR"), identity("E-1"), leaver],
        vec![shadow, stale],
    );

    let first = engine::evaluate(&input, &config(), ENGINE);
    let second = engine::evaluate(&input, &config(), ENGINE);
    let first_json = serde_json::to_value(&first).unwrap();
    let second_json = serde_json::to_value(&second).unwrap();
    assert_eq!(first_json, second_json);

    let mut sorted = first.clone();
    sorted.sort_by(|a, b| (&a.subject, &a.rule_id).cmp(&(&b.subject, &b.rule_id)));
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&sorted).unwrap()
    );
}

#[test]
fn validate_accepts_clean_campaign() {
    let input = campaign(
        vec![identity("E-MGR"), identity("E-1")],
        vec![entitlement("ENT-1")],
    );
    assert_eq!(validate(&input), Ok(()));
}

#[test]
fn validate_rejects_duplicate_identity_employee_id() {
    let input = campaign(
        vec![identity("E-MGR"), identity("E-1"), identity("E-1")],
        vec![],
    );
    let message = validate(&input).unwrap_err();
    assert!(
        message.contains("duplicate identity employee_id"),
        "{message}"
    );
}

#[test]
fn validate_rejects_duplicate_entitlement_id() {
    let input = campaign(
        vec![identity("E-MGR"), identity("E-1")],
        vec![entitlement("ENT-1"), entitlement("ENT-1")],
    );
    let message = validate(&input).unwrap_err();
    assert!(message.contains("duplicate entitlement_id"), "{message}");
}

#[test]
fn validate_rejects_dates_after_campaign() {
    let mut hire = identity("E-2");
    hire.hire_date = d("2026-12-01"); // future hire
    let mut granted = entitlement("ENT-1");
    granted.granted_at = d("2026-12-01"); // future grant
    granted.last_authenticated_at = Some(d("2026-12-02")); // future auth
    let input = campaign(vec![identity("E-MGR"), hire], vec![granted]);
    let message = validate(&input).unwrap_err();
    assert!(message.contains("after campaign date"), "{message}");
}

#[test]
fn validate_rejects_separation_before_hire() {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2019-01-01")); // before 2020 hire
    let input = campaign(vec![identity("E-MGR"), leaver], vec![]);
    let message = validate(&input).unwrap_err();
    assert!(message.contains("before hire_date"), "{message}");
}
