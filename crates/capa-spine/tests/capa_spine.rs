//! Integration tests for capa-spine: every rule branch, every threshold
//! boundary, and the fail-closed paths — tampered packs included — driven
//! through the public API.

use capa_spine::{
    build_pack, evaluate, normalize_description, CapaConfig, CapaEvaluation, CapaRecord, Category,
    Detectability, EffectivenessCheck, Status, ENGINE_ID, RULE_AGING_BREACH, RULE_AGING_WARN,
    RULE_BROKEN_REOPEN_LINK, RULE_CLOSURE_BLOCKED, RULE_CONTAINMENT_LATE,
    RULE_CONTAINMENT_OVERDUE, RULE_DUPLICATE_DESCRIPTION, RULE_EFFECTIVENESS_OVERDUE,
};
use chrono::{DateTime, Duration, Utc};
use spine::{sha256_hex, Severity, Signoff, SignoffDecision, SPINE_VERSION, VerifyError};

const SEED_CONFIG: &str = r#"{
  "severity_matrix": [
    {"category": "safety", "detectability": "high", "severity": "warn"},
    {"category": "safety", "detectability": "medium", "severity": "breach"},
    {"category": "safety", "detectability": "low", "severity": "breach"},
    {"category": "regulatory", "detectability": "high", "severity": "warn"},
    {"category": "regulatory", "detectability": "medium", "severity": "warn"},
    {"category": "regulatory", "detectability": "low", "severity": "breach"},
    {"category": "quality", "detectability": "high", "severity": "info"},
    {"category": "quality", "detectability": "medium", "severity": "warn"},
    {"category": "quality", "detectability": "low", "severity": "breach"}
  ],
  "containment_hours": {"breach": 24, "warn": 72, "info": null},
  "aging": {"warn_after_days": 30, "breach_after_days": 90},
  "effectiveness_window_days": 60
}"#;

fn seed_config() -> CapaConfig {
    CapaConfig::parse(SEED_CONFIG.as_bytes()).expect("seed config parses")
}

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .unwrap()
        .with_timezone(&Utc)
}

fn base_capa(id: &str) -> CapaRecord {
    CapaRecord {
        id: id.to_string(),
        description: "Test nonconformance".to_string(),
        category: Category::Quality,
        detectability: Detectability::Low,
        opened_at: ts("2026-09-20T00:00:00Z"),
        containment_recorded_at: None,
        status: Status::Open,
        closed_at: None,
        root_cause: None,
        effectiveness_check: None,
        parent_id: None,
    }
}

/// Containment recorded exactly at opening — never late, never overdue.
fn contained(record: &mut CapaRecord) {
    record.containment_recorded_at = Some(record.opened_at);
}

fn has_rule(evaluation: &CapaEvaluation, rule: &str) -> bool {
    evaluation.findings.iter().any(|f| f.rule_id == rule)
}

fn finding_of<'a>(evaluation: &'a CapaEvaluation, rule: &str) -> &'a spine::Finding {
    evaluation
        .findings
        .iter()
        .find(|f| f.rule_id == rule)
        .unwrap_or_else(|| panic!("expected finding {rule}"))
}

fn approve(actor: &str, subject: &str) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "quality-manager".to_string(),
        subject: subject.to_string(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T12:00:00Z".to_string(),
    }
}

/// Flatten an evaluation set the way build_pack receives it.
fn flattened(evaluations: &[CapaEvaluation]) -> Vec<spine::Finding> {
    evaluations
        .iter()
        .flat_map(|e| e.findings.iter().cloned())
        .collect()
}

// --- Severity matrix -------------------------------------------------------

#[test]
fn severity_matrix_seed_boundaries() {
    let config = seed_config();
    let expected = [
        (Category::Safety, Detectability::High, Severity::Warn),
        (Category::Safety, Detectability::Medium, Severity::Breach),
        (Category::Safety, Detectability::Low, Severity::Breach),
        (Category::Regulatory, Detectability::High, Severity::Warn),
        (Category::Regulatory, Detectability::Medium, Severity::Warn),
        (Category::Regulatory, Detectability::Low, Severity::Breach),
        (Category::Quality, Detectability::High, Severity::Info),
        (Category::Quality, Detectability::Medium, Severity::Warn),
        (Category::Quality, Detectability::Low, Severity::Breach),
    ];
    for (category, detectability, severity) in expected {
        assert_eq!(
            config.severity_for(category, detectability),
            Some(severity),
            "{category:?} × {detectability:?}"
        );
    }
}

// --- Config schema checks (fail-closed) ------------------------------------

#[test]
fn config_refuses_incomplete_matrix() {
    let mut config = seed_config();
    config.severity_matrix.pop();
    let bytes = serde_json::to_vec(&config).unwrap();
    let err = CapaConfig::parse(&bytes).unwrap_err();
    assert!(err.to_string().contains("incomplete"), "{err}");
}

#[test]
fn config_refuses_duplicate_matrix_cell() {
    let mut config = seed_config();
    config.severity_matrix.push(config.severity_matrix[0]);
    let bytes = serde_json::to_vec(&config).unwrap();
    let err = CapaConfig::parse(&bytes).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
}

#[test]
fn config_refuses_unknown_fields() {
    let raw = r#"{
        "severity_matrix": [],
        "containment_hours": {},
        "aging": {"warn_after_days": 30, "breach_after_days": 90},
        "effectiveness_window_days": 60,
        "surprise": 1
    }"#;
    let err = CapaConfig::parse(raw.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("schema violation"), "{err}");
}

#[test]
fn config_refuses_inverted_aging_thresholds() {
    for (warn, breach) in [(90u64, 30u64), (30, 30), (0, 30)] {
        let raw = format!(
            r#"{{"severity_matrix": [], "containment_hours": {{}}, "aging": {{"warn_after_days": {warn}, "breach_after_days": {breach}}}, "effectiveness_window_days": 60}}"#
        );
        let err = CapaConfig::parse(raw.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("aging thresholds invalid"), "{err}");
    }
}

#[test]
fn config_refuses_degenerate_windows() {
    let zero_containment = r#"{
        "severity_matrix": [],
        "containment_hours": {"breach": 0, "warn": 72},
        "aging": {"warn_after_days": 30, "breach_after_days": 90},
        "effectiveness_window_days": 60
    }"#;
    let err = CapaConfig::parse(zero_containment.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("at least one hour"), "{err}");

    let zero_effectiveness = r#"{
        "severity_matrix": [],
        "containment_hours": {},
        "aging": {"warn_after_days": 30, "breach_after_days": 90},
        "effectiveness_window_days": 0
    }"#;
    let err = CapaConfig::parse(zero_effectiveness.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("must be positive"), "{err}");
}

// --- Containment -----------------------------------------------------------

#[test]
fn containment_overdue_is_a_breach() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    // quality × low → breach severity → 24h containment window; opened
    // 2026-09-20, due 2026-09-21 — overdue as of 2026-09-22.
    let record = base_capa("CAPA-1");
    let evaluations = evaluate(&[record.clone()], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_CONTAINMENT_OVERDUE));
    let finding = finding_of(&evaluations[0], RULE_CONTAINMENT_OVERDUE);
    assert_eq!(finding.severity, Severity::Breach);
    assert!(finding.requires_signoff);
    assert_eq!(finding.subject, "CAPA-1");
    // Purity: evaluation leaves the record untouched.
    assert!(record.containment_recorded_at.is_none());
}

#[test]
fn containment_due_boundary_is_exact() {
    let config = seed_config();
    let opened = ts("2026-09-20T00:00:00Z");
    let due = opened + Duration::hours(24);

    let mut at_due = base_capa("CAPA-1");
    at_due.opened_at = opened;
    let evaluations = evaluate(&[at_due], &config, due).unwrap();
    assert!(!has_rule(&evaluations[0], RULE_CONTAINMENT_OVERDUE));

    let mut past_due = base_capa("CAPA-1");
    past_due.opened_at = opened;
    let evaluations = evaluate(&[past_due], &config, due + Duration::hours(1)).unwrap();
    assert!(has_rule(&evaluations[0], RULE_CONTAINMENT_OVERDUE));
}

#[test]
fn containment_late_is_a_warn_not_a_breach() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.containment_recorded_at = Some(record.opened_at + Duration::hours(25));
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_CONTAINMENT_LATE));
    assert!(!has_rule(&evaluations[0], RULE_CONTAINMENT_OVERDUE));
    let finding = finding_of(&evaluations[0], RULE_CONTAINMENT_LATE);
    assert_eq!(finding.severity, Severity::Warn);
    assert!(!finding.requires_signoff);
}

#[test]
fn containment_on_time_produces_no_finding() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    contained(&mut record);
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    assert!(
        evaluations[0].findings.is_empty(),
        "{:?}",
        evaluations[0].findings
    );
}

#[test]
fn containment_not_required_without_a_configured_window() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.detectability = Detectability::High; // quality × high → info → no window
    record.opened_at = ts("2025-09-01T00:00:00Z"); // a year old, still no containment rule
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    assert!(!has_rule(&evaluations[0], RULE_CONTAINMENT_OVERDUE));
    assert!(!evaluations[0].containment_required);
    assert!(evaluations[0].containment_due.is_none());
    // Aging still applies to the year-old open CAPA.
    assert!(has_rule(&evaluations[0], RULE_AGING_BREACH));
}

// --- Aging -----------------------------------------------------------------

#[test]
fn aging_thresholds_and_boundaries() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");

    let cases = [
        (30u64, false, false), // exactly at the warn threshold — not yet
        (31, true, false),     // one day past — warn
        (90, true, false),     // exactly at the breach threshold — still warn
        (91, false, true),     // one day past — breach supersedes warn
    ];
    for (age_days, expect_warn, expect_breach) in cases {
        let mut record = base_capa("CAPA-1");
        contained(&mut record);
        record.opened_at = as_of - Duration::days(age_days as i64);
        let evaluations = evaluate(&[record], &config, as_of).unwrap();
        assert_eq!(
            has_rule(&evaluations[0], RULE_AGING_WARN),
            expect_warn,
            "age {age_days}d"
        );
        assert_eq!(
            has_rule(&evaluations[0], RULE_AGING_BREACH),
            expect_breach,
            "age {age_days}d"
        );
    }
}

// --- Closure ---------------------------------------------------------------

#[test]
fn closure_blocked_without_root_cause_treated_as_open() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.opened_at = as_of - Duration::days(120); // old enough to age
    record.status = Status::Closed;
    record.closed_at = Some(record.opened_at + Duration::hours(2));
    record.root_cause = None;
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    let evaluation = &evaluations[0];
    assert!(has_rule(evaluation, RULE_CLOSURE_BLOCKED));
    assert!(evaluation.treated_as_open);
    // Fail-closed: the refused closure ages as an open item...
    assert!(has_rule(evaluation, RULE_AGING_BREACH));
    // ...but a blocked closure never runs the effectiveness clock.
    assert!(!has_rule(evaluation, RULE_EFFECTIVENESS_OVERDUE));
    let finding = finding_of(evaluation, RULE_CLOSURE_BLOCKED);
    assert_eq!(finding.severity, Severity::Breach);
    assert_eq!(finding.subject, "CAPA-1");
}

#[test]
fn closure_blocked_without_closed_at_or_on_blank_root_cause() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");

    let mut no_date = base_capa("CAPA-1");
    no_date.status = Status::Closed;
    no_date.root_cause = Some("narrative".to_string());
    no_date.closed_at = None;
    let evaluations = evaluate(&[no_date], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_CLOSURE_BLOCKED));
    assert!(evaluations[0].treated_as_open);

    let mut blank_cause = base_capa("CAPA-1");
    blank_cause.status = Status::Closed;
    blank_cause.root_cause = Some("   ".to_string()); // whitespace-only: not recorded
    blank_cause.closed_at = Some(as_of - Duration::days(1));
    let evaluations = evaluate(&[blank_cause], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_CLOSURE_BLOCKED));
    assert!(evaluations[0].treated_as_open);
}

// --- Effectiveness ---------------------------------------------------------

#[test]
fn effectiveness_overdue_after_window() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.status = Status::Closed;
    record.closed_at = Some(as_of - Duration::days(61));
    record.root_cause = Some("root cause narrative".to_string());
    record.effectiveness_check = Some(EffectivenessCheck {
        completed: false,
        completed_at: None,
    });
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    let evaluation = &evaluations[0];
    assert!(has_rule(evaluation, RULE_EFFECTIVENESS_OVERDUE));
    // Honored closure: not blocked, and aging does not apply.
    assert!(!evaluation.treated_as_open);
    assert!(!has_rule(evaluation, RULE_CLOSURE_BLOCKED));
    let finding = finding_of(evaluation, RULE_EFFECTIVENESS_OVERDUE);
    assert_eq!(finding.severity, Severity::Breach);
    assert_eq!(finding.subject, "CAPA-1");
}

#[test]
fn effectiveness_due_boundary_is_exact() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let closed = as_of - Duration::days(60); // due == as_of exactly

    let mut at_due = base_capa("CAPA-1");
    at_due.status = Status::Closed;
    at_due.closed_at = Some(closed);
    at_due.root_cause = Some("narrative".to_string());
    at_due.effectiveness_check = Some(EffectivenessCheck {
        completed: false,
        completed_at: None,
    });
    let evaluations = evaluate(&[at_due], &config, as_of).unwrap();
    assert!(!has_rule(&evaluations[0], RULE_EFFECTIVENESS_OVERDUE));

    let mut past_due = base_capa("CAPA-1");
    past_due.status = Status::Closed;
    past_due.closed_at = Some(closed - Duration::hours(1)); // due one hour before the clock
    past_due.root_cause = Some("narrative".to_string());
    past_due.effectiveness_check = Some(EffectivenessCheck {
        completed: false,
        completed_at: None,
    });
    let evaluations = evaluate(&[past_due], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_EFFECTIVENESS_OVERDUE));
}

#[test]
fn effectiveness_completed_produces_no_finding() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.status = Status::Closed;
    record.closed_at = Some(as_of - Duration::days(120));
    record.root_cause = Some("root cause narrative".to_string());
    record.effectiveness_check = Some(EffectivenessCheck {
        completed: true,
        completed_at: Some(record.closed_at.unwrap() + Duration::days(10)),
    });
    let evaluations = evaluate(&[record], &config, as_of).unwrap();
    assert!(
        evaluations[0].findings.is_empty(),
        "{:?}",
        evaluations[0].findings
    );
}

// --- Duplicate detection ---------------------------------------------------

#[test]
fn duplicate_description_normalization_warns() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut a = base_capa("CAPA-1");
    contained(&mut a);
    a.description = "Pallet   Stacking FAILURE".to_string();
    let mut b = base_capa("CAPA-2");
    contained(&mut b);
    b.description = "pallet stacking failure".to_string();
    let evaluations = evaluate(&[a, b], &config, as_of).unwrap();
    // The lexicographically smallest id is canonical; the other carrier warns.
    assert!(!has_rule(&evaluations[0], RULE_DUPLICATE_DESCRIPTION));
    assert!(has_rule(&evaluations[1], RULE_DUPLICATE_DESCRIPTION));
    let finding = finding_of(&evaluations[1], RULE_DUPLICATE_DESCRIPTION);
    assert_eq!(finding.severity, Severity::Warn);
    assert!(!finding.requires_signoff);
    assert!(finding.message.contains("CAPA-1"), "{finding:?}");
}

#[test]
fn distinct_descriptions_never_warn() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut a = base_capa("CAPA-1");
    contained(&mut a);
    a.description = "Pallet stacking failure".to_string();
    let mut b = base_capa("CAPA-2");
    contained(&mut b);
    b.description = "Forklift near miss in aisle 4".to_string();
    let evaluations = evaluate(&[a, b], &config, as_of).unwrap();
    assert!(!has_rule(&evaluations[0], RULE_DUPLICATE_DESCRIPTION));
    assert!(!has_rule(&evaluations[1], RULE_DUPLICATE_DESCRIPTION));
}

#[test]
fn description_normalization_is_case_and_whitespace_insensitive() {
    assert_eq!(
        normalize_description("Pallet  Stacking\tFAILURE"),
        normalize_description("pallet stacking failure")
    );
    assert_ne!(
        normalize_description("pallet stacking"),
        normalize_description("crate stacking")
    );
}

// --- Reopen linkage --------------------------------------------------------

#[test]
fn reopen_cycle_uses_fresh_clocks_and_links_parent() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");

    let mut parent = base_capa("CAPA-1");
    contained(&mut parent);
    parent.opened_at = as_of - Duration::days(200);
    parent.status = Status::Closed;
    parent.closed_at = Some(parent.opened_at + Duration::days(3));
    parent.root_cause = Some("fixed long ago".to_string());
    parent.effectiveness_check = Some(EffectivenessCheck {
        completed: true,
        completed_at: Some(parent.closed_at.unwrap() + Duration::days(10)),
    });

    let mut child = base_capa("CAPA-2");
    contained(&mut child);
    child.opened_at = as_of - Duration::hours(2); // fresh clock on the new cycle
    child.parent_id = Some("CAPA-1".to_string());

    let evaluations = evaluate(&[parent, child], &config, as_of).unwrap();
    let child_eval = &evaluations[1];
    // Fresh clocks: had the engine anchored at the parent's opening, this
    // containment would read as 200 days overdue.
    assert!(!has_rule(child_eval, RULE_CONTAINMENT_OVERDUE));
    assert!(!has_rule(child_eval, RULE_AGING_WARN));
    assert!(child_eval.parent_present);
    assert_eq!(child_eval.parent_id.as_deref(), Some("CAPA-1"));
    assert!(
        child_eval.findings.is_empty(),
        "{:?}",
        child_eval.findings
    );
    // Parent stays clean and closed.
    assert!(!evaluations[0].treated_as_open);
    assert!(evaluations[0].findings.is_empty());
}

#[test]
fn broken_reopen_link_is_a_breach() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");

    let mut orphan = base_capa("CAPA-1");
    contained(&mut orphan);
    orphan.parent_id = Some("GHOST".to_string());
    let evaluations = evaluate(&[orphan], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_BROKEN_REOPEN_LINK));
    assert!(!evaluations[0].parent_present);
    let finding = finding_of(&evaluations[0], RULE_BROKEN_REOPEN_LINK);
    assert_eq!(finding.severity, Severity::Breach);

    // Self-parent is also broken — a cycle cannot reopen itself.
    let mut self_parent = base_capa("CAPA-1");
    contained(&mut self_parent);
    self_parent.parent_id = Some("CAPA-1".to_string());
    let evaluations = evaluate(&[self_parent], &config, as_of).unwrap();
    assert!(has_rule(&evaluations[0], RULE_BROKEN_REOPEN_LINK));
}

// --- Determinism and evidence packs ----------------------------------------

#[test]
fn evaluation_is_deterministic() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");

    let mut overdue = base_capa("CAPA-1");
    overdue.opened_at = as_of - Duration::days(2); // containment overdue
    let mut duplicate = base_capa("CAPA-2");
    contained(&mut duplicate);
    duplicate.description = "TEST NONCONFORMANCE".to_string(); // normalizes onto CAPA-1
    let mut clean = base_capa("CAPA-3");
    contained(&mut clean);
    let capas = vec![overdue, duplicate, clean];

    let first = evaluate(&capas, &config, as_of).unwrap();
    let second = evaluate(&capas, &config, as_of).unwrap();
    assert_eq!(first, second);
}

#[test]
fn pack_carries_provenance_and_seal() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1"); // containment overdue
    record.opened_at = as_of - Duration::days(2);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());

    assert_eq!(pack.inputs_hash, sha256_hex(&capas_bytes));
    assert_eq!(pack.params_hash, sha256_hex(SEED_CONFIG.as_bytes()));
    assert_eq!(pack.spine_version, SPINE_VERSION);
    assert!(!pack.tool_version.is_empty());
    assert_eq!(pack.engine_id, ENGINE_ID);
    assert!(!pack.body_hash.is_empty(), "pack is sealed at build");
}

#[test]
fn pack_orders_findings_by_subject_then_rule() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    // Input order CAPA-2, CAPA-10; lexicographic subject order is CAPA-10
    // first — the pack must sort, not follow input order.
    let mut a = base_capa("CAPA-2");
    a.opened_at = as_of - Duration::days(2);
    let mut b = base_capa("CAPA-10");
    b.opened_at = as_of - Duration::days(2);
    let capas = vec![a, b];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());
    let subjects: Vec<&str> = pack.findings.iter().map(|f| f.subject.as_str()).collect();
    assert_eq!(subjects, vec!["CAPA-10", "CAPA-2"]);
}

#[test]
fn verify_accepts_signed_pack_with_per_subject_signoffs() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut a = base_capa("CAPA-1"); // containment overdue → breach
    a.opened_at = as_of - Duration::days(2);
    let mut b = base_capa("CAPA-2"); // second subject, same rule
    b.opened_at = as_of - Duration::days(3);
    let capas = vec![a, b];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());

    // Unsigned: refused, naming the first unresolved rule.
    assert_eq!(
        pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_CONTAINMENT_OVERDUE.to_string()
        })
    );

    // One subject's approval leaves the other unresolved.
    let mut half_signed = pack.clone();
    half_signed.signoffs.push(approve("sam", "CAPA-1"));
    let half_signed = half_signed.sealed();
    assert!(half_signed
        .verify(&capas_bytes, SEED_CONFIG.as_bytes())
        .is_err());

    // Per-subject approvals resolve the pack.
    let mut signed = half_signed;
    signed.signoffs.push(approve("quinn", "CAPA-2"));
    let signed = signed.sealed();
    assert_eq!(signed.verify(&capas_bytes, SEED_CONFIG.as_bytes()), Ok(()));
}

#[test]
fn verify_refuses_signoff_for_the_wrong_subject() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.opened_at = as_of - Duration::days(2);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let mut pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());
    pack.signoffs.push(approve("sam", "CAPA-9"));
    let pack = pack.sealed();
    assert!(pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()).is_err());
}

#[test]
fn verify_refuses_engine_self_signoff() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.opened_at = as_of - Duration::days(2);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let mut pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());
    // Separation of duties: the engine's own receipt — exact or case-variant
    // — is void.
    pack.signoffs.push(approve(ENGINE_ID, "CAPA-1"));
    let pack = pack.sealed();
    assert!(pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()).is_err());

    let mut case_variant = pack.clone();
    case_variant.signoffs[0].actor = "CAPA-Spine".to_string();
    let case_variant = case_variant.sealed();
    assert!(case_variant
        .verify(&capas_bytes, SEED_CONFIG.as_bytes())
        .is_err());

    // A distinct human approval resolves it.
    let mut human_signed = pack;
    human_signed.signoffs.push(approve("sam", "CAPA-1"));
    let human_signed = human_signed.sealed();
    assert_eq!(
        human_signed.verify(&capas_bytes, SEED_CONFIG.as_bytes()),
        Ok(())
    );
}

#[test]
fn verify_refuses_tampered_pack_body() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.opened_at = as_of - Duration::days(2);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let mut pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());
    pack.signoffs.push(approve("sam", "CAPA-1"));
    let pack = pack.sealed();
    assert_eq!(pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()), Ok(()));

    // Tamper: downgrade the breach after the fact — the seal refuses.
    pack.findings[0].severity = Severity::Warn;
    pack.findings[0].requires_signoff = false;
    assert_eq!(
        pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()),
        Err(VerifyError::BodyHashMismatch)
    );
}

#[test]
fn verify_refuses_tampered_inputs_and_params() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    contained(&mut record); // clean capa → clean pack
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();
    let pack = build_pack(ENGINE_ID, vec![], &capas_bytes, SEED_CONFIG.as_bytes());

    assert_eq!(
        pack.verify(b"tampered inputs", SEED_CONFIG.as_bytes()),
        Err(VerifyError::HashMismatch { field: "inputs" })
    );
    assert_eq!(
        pack.verify(&capas_bytes, b"tampered params"),
        Err(VerifyError::HashMismatch { field: "params" })
    );
}

#[test]
fn verify_refuses_unsealed_pack() {
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    contained(&mut record);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();
    let mut pack = build_pack(ENGINE_ID, vec![], &capas_bytes, SEED_CONFIG.as_bytes());
    pack.body_hash = String::new();
    assert_eq!(
        pack.verify(&capas_bytes, SEED_CONFIG.as_bytes()),
        Err(VerifyError::BodyHashMismatch)
    );
}

#[test]
fn signed_pack_json_roundtrip_verifies() {
    // The file-based CLI flow: serialize the signed pack, read it back, and
    // verify against the original bytes.
    let config = seed_config();
    let as_of = ts("2026-09-22T00:00:00Z");
    let mut record = base_capa("CAPA-1");
    record.opened_at = as_of - Duration::days(2);
    let capas = vec![record];
    let capas_bytes = serde_json::to_vec(&capas).unwrap();

    let evaluations = evaluate(&capas, &config, as_of).unwrap();
    let mut pack = build_pack(ENGINE_ID, flattened(&evaluations), &capas_bytes, SEED_CONFIG.as_bytes());
    pack.signoffs.push(approve("sam", "CAPA-1"));
    let pack = pack.sealed();

    let json = serde_json::to_string_pretty(&pack).unwrap();
    let back: spine::EvidencePack = serde_json::from_str(&json).unwrap();
    assert_eq!(back.verify(&capas_bytes, SEED_CONFIG.as_bytes()), Ok(()));
}
