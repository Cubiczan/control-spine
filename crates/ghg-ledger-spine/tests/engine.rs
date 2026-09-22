//! Rule and governance tests for ghg-ledger-spine. Coverage follows the
//! product block: factor lineage, unit conversion at the boundary, dual-method
//! Scope 2 with divergence warnings, Scope 3 category tagging boundaries,
//! DQ-tier boundaries, missing-factor fail-closed gaps, input breaches,
//! half-up rounding, determinism under input reordering, and the full
//! restatement lifecycle — plus the fail-closed evidence-pack path: tampered
//! packs must fail `verify`.

use ghg_ledger_spine::spine::{
    self, LockState, Signoff, SignoffDecision, VerifyError as SpineVerifyError, SPINE_VERSION,
};
use ghg_ledger_spine::{
    compute, verify, ComputeError, GhgEvidencePack, VerifyRefusal, MARKET_SCOPE2_DISCLOSURE,
};
use serde_json::{json, Value};

fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn record(id: &str, scope: &str, activity: &str, value: i64, unit: &str) -> Value {
    json!({
        "record_id": id,
        "scope": scope,
        "activity": activity,
        "quantity": { "value": value, "scale": 0 },
        "unit": unit,
        "region": "US",
        "year": 2025
    })
}

fn scope3_record(id: &str, activity: &str, value: i64, unit: &str) -> Value {
    let mut r = record(id, "scope3", activity, value, unit);
    r["region"] = json!("GLOBAL");
    r
}

/// Seed-data factor table matching the shipped config template. Values are
/// illustrative seed values, not authoritative emission factors.
fn base_config() -> Value {
    json!({
        "period": "2025-FY",
        "conversions": [
            { "from_unit": "MWh", "to_unit": "kWh", "factor": { "value": 1000, "scale": 0 } }
        ],
        "factors": [
            { "activity": "natural_gas", "unit": "kWh", "region": "US", "year": 2025, "method": null,
              "factor": { "value": 200, "scale": 0 }, "factor_version": "seed-stationary-v1", "source": "seed:epa-style" },
            { "activity": "grid_electricity", "unit": "kWh", "region": "US", "year": 2025, "method": "location",
              "factor": { "value": 400, "scale": 0 }, "factor_version": "seed-grid-v1", "source": "seed:epa-style" },
            { "activity": "grid_electricity", "unit": "kWh", "region": "US", "year": 2025, "method": "market",
              "factor": { "value": 500, "scale": 0 }, "factor_version": "seed-grid-v1", "source": "seed:epa-style" },
            { "activity": "business_travel_air", "unit": "passenger_km", "region": "GLOBAL", "year": 2025, "method": null,
              "factor": { "value": 150, "scale": 0 }, "factor_version": "seed-aviation-v1", "source": "seed:epa-style" },
            { "activity": "purchased_goods", "unit": "kg", "region": "GLOBAL", "year": 2025, "method": null,
              "factor": { "value": 500, "scale": 0 }, "factor_version": "seed-upstream-v1", "source": "seed:epa-style" },
            { "activity": "investments", "unit": "usd", "region": "GLOBAL", "year": 2025, "method": null,
              "factor": { "value": 2, "scale": 1 }, "factor_version": "seed-cat15-v1", "source": "seed:epa-style" }
        ],
        "scope3_categories": [
            { "category": 1, "activities": ["purchased_goods"] },
            { "category": 6, "activities": ["business_travel_air"] },
            { "category": 15, "activities": ["investments"] }
        ],
        "dq_tiers": [
            { "min_score": 90, "label": "high" },
            { "min_score": 50, "label": "medium" },
            { "min_score": 0, "label": "low" }
        ],
        "scope2_divergence_warn_bps": 1000
    })
}

fn inputs_of(records: Vec<Value>) -> Value {
    json!({ "records": records })
}

fn compute_pack(inputs: &Value, config: &Value) -> Result<GhgEvidencePack, ComputeError> {
    compute(&to_bytes(inputs), &to_bytes(config), None)
}

fn compute_ok(inputs: &Value, config: &Value) -> GhgEvidencePack {
    compute_pack(inputs, config).expect("compute must succeed")
}

fn config_with_location_factor(value: i64, scale: i32, version: &str) -> Value {
    let mut config = base_config();
    for row in config["factors"].as_array_mut().unwrap() {
        if row["activity"] == "grid_electricity" && row["method"] == "location" {
            row["factor"] = json!({ "value": value, "scale": scale });
            row["factor_version"] = json!(version);
        }
    }
    config
}

fn verify_ok(pack: &GhgEvidencePack, inputs: &Value, config: &Value) {
    verify(pack, &to_bytes(inputs), &to_bytes(config), None).expect("pack must verify");
}

// --- Scope 1: factor lineage and boundary-only conversion ---

/// Test anchor: factor-version lineage in output.
#[test]
fn scope1_line_carries_factor_lineage() {
    let pack = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &base_config(),
    );
    assert_eq!(pack.lines.len(), 1);
    let line = &pack.lines[0];
    assert_eq!(line.record_id, "rec-1");
    assert_eq!(line.scope, 1);
    assert_eq!(line.canonical_unit, "kWh");
    assert_eq!(line.canonical_quantity.value, 2000); // 2 MWh → 2000 kWh, once
    assert_eq!(line.factor_version, "seed-stationary-v1");
    assert_eq!(line.factor.value, 200);
    assert_eq!(line.emission_grams, 400_000); // 2000 kWh × 200 g/kWh
    assert!(line.method.is_none());
    verify_ok(
        &pack,
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &base_config(),
    );
}

/// Edge case: conversion happens once at the boundary, never on the canonical
/// unit inside. A double conversion would show up as a 1000× error here.
#[test]
fn unit_conversion_applied_exactly_once() {
    let pack = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &base_config(),
    );
    let line = &pack.lines[0];
    assert_eq!(line.canonical_quantity.value, 2000);
    assert_eq!(line.canonical_quantity.scale, 0);
    assert_eq!(line.emission_grams, 400_000);
}

/// Edge case: a factor-version bump changes the recorded lineage — the line
/// must name the exact factor row used.
#[test]
fn factor_lineage_tracks_version_bump() {
    let config = config_with_location_factor(440, 0, "seed-grid-v2");
    let pack = compute_ok(
        &inputs_of(vec![record(
            "rec-1",
            "scope2",
            "grid_electricity",
            1000,
            "kWh",
        )]),
        &config,
    );
    let location = pack
        .lines
        .iter()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Location))
        .expect("location line must exist");
    assert_eq!(location.factor_version, "seed-grid-v2");
    assert_eq!(location.factor.value, 440);
    assert_eq!(location.emission_grams, 440_000);
}

// --- Fail-closed: missing factor is a gap, never a zero ---

/// Test anchor: missing-factor gap. The line is not computed and never zeroed.
#[test]
fn missing_factor_is_breach_gap_never_zero() {
    let pack = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "unknown_fuel", 10, "kg")]),
        &base_config(),
    );
    assert!(
        pack.lines.is_empty(),
        "no line must be produced without a factor"
    );
    let f = &pack.pack.findings[0];
    assert_eq!(f.rule_id, "GHG-FACTOR-MISSING");
    assert_eq!(f.subject, "rec-1");
    assert!(f.message.contains("unknown_fuel"));
    assert!(f.message.contains("never zeroed"));
}

/// Test anchor + family rule: the pack with a missing-factor breach refuses
/// verification until a subject-scoped human signoff resolves it.
#[test]
fn missing_factor_pack_refuses_until_subject_signoff() {
    let inputs = inputs_of(vec![record("rec-1", "scope1", "unknown_fuel", 10, "kg")]);
    let mut pack = compute_ok(&inputs, &base_config());
    let config = base_config();

    match verify(&pack, &to_bytes(&inputs), &to_bytes(&config), None) {
        Err(VerifyRefusal::Spine(SpineVerifyError::UnresolvedBreach { .. })) => {}
        other => panic!("expected UnresolvedBreach refusal, got {other:?}"),
    }

    // Wrong-subject approval: subject-scoped signoff matching must refuse.
    // Receipts are part of the sealed body — the sign flow re-seals when a
    // receipt lands; verify must then still refuse on the unmet breach.
    pack.pack.signoffs.push(Signoff {
        actor: "sam".into(),
        role: "controller".into(),
        subject: "rec-other".into(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T00:00:00Z".into(),
    });
    pack.pack = pack.pack.clone().sealed();
    assert!(matches!(
        verify(&pack, &to_bytes(&inputs), &to_bytes(&config), None),
        Err(VerifyRefusal::Spine(
            SpineVerifyError::UnresolvedBreach { .. }
        ))
    ));

    // Correct subject, human signoff, lock advanced to Signed → verifies.
    pack.pack.signoffs.push(Signoff {
        actor: "shyam".into(),
        role: "controller".into(),
        subject: "rec-1".into(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T00:00:00Z".into(),
    });
    assert_eq!(
        spine::advance_lock(LockState::Draft, &mut pack.pack).unwrap(),
        LockState::AwaitingSignoff
    );
    assert_eq!(
        spine::advance_lock(LockState::AwaitingSignoff, &mut pack.pack).unwrap(),
        LockState::Signed
    );
    verify(&pack, &to_bytes(&inputs), &to_bytes(&config), None).expect("signed pack must verify");
}

// --- Scope 2: dual method, divergence, partial coverage ---

/// Test anchor: Scope 2 dual-method divergence. REC-covered market-based
/// electricity diverges from location-based; both lines are computed and
/// reported separately, and the divergence warn fires.
#[test]
fn scope2_dual_method_divergence_warns() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 800, "scale": 0 });
    let pack = compute_ok(&inputs_of(vec![rec]), &base_config());

    let location = pack
        .lines
        .iter()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Location))
        .unwrap();
    let market = pack
        .lines
        .iter()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Market))
        .unwrap();
    assert_eq!(location.emission_grams, 400_000);
    assert_eq!(market.emission_grams, 100_000); // 200 uncovered kWh × 500 g/kWh

    // |400000-100000| = 300000; 300000/400000 = 7500 bps > 1000 → warn.
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-SCOPE2-DIVERGENCE" && f.severity == spine::Severity::Warn));
}

/// Test anchor: market-based Scope 2 lines carry the in-pack disclosure
/// label — the figure covers contractual instruments only and excludes
/// residual-mix factors — while the location-based twin carries none.
#[test]
fn market_based_scope2_lines_carry_disclosure() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 800, "scale": 0 });
    let pack = compute_ok(&inputs_of(vec![rec]), &base_config());
    assert_eq!(pack.lines.len(), 2);

    let market = pack
        .lines
        .iter()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Market))
        .unwrap();
    assert_eq!(market.disclosure.as_deref(), Some(MARKET_SCOPE2_DISCLOSURE));

    let location = pack
        .lines
        .iter()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Location))
        .unwrap();
    assert!(location.disclosure.is_none());
}

/// The disclosure rides the serialized pack: the market-based line's JSON
/// carries the label verbatim — stating contractual-instrument-only coverage
/// and the residual-mix exclusion — and other lines serialize without one.
#[test]
fn serialized_pack_carries_disclosure_only_on_market_lines() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 800, "scale": 0 });
    let pack = compute_ok(&inputs_of(vec![rec]), &base_config());

    let lines = serde_json::to_value(&pack).unwrap()["lines"]
        .as_array()
        .unwrap()
        .clone();
    let market: Vec<&Value> = lines.iter().filter(|l| l["method"] == "market").collect();
    assert_eq!(market.len(), 1);
    let label = market[0]["disclosure"].as_str().unwrap();
    assert!(label.contains("contractual instruments only"));
    assert!(label.contains("excludes residual-mix factors"));

    let location: Vec<&Value> = lines.iter().filter(|l| l["method"] == "location").collect();
    assert_eq!(location.len(), 1);
    assert!(location[0]["disclosure"].is_null());
}

/// The label is exclusive to market-based Scope 2: scope 1, scope 2
/// location, and scope 3 lines carry no disclosure — nothing on other
/// methods that could read as a market-based disclaimer.
#[test]
fn non_market_lines_carry_no_disclosure() {
    let pack = compute_ok(
        &inputs_of(vec![
            record("rec-s1", "scope1", "natural_gas", 2, "MWh"),
            record("rec-s2", "scope2", "grid_electricity", 500, "kWh"),
            scope3_record("rec-s3", "purchased_goods", 10, "kg"),
        ]),
        &base_config(),
    );
    assert!(pack.lines.iter().all(|l| match l.method {
        Some(ghg_ledger_spine::Method::Market) => l.disclosure.is_some(),
        _ => l.disclosure.is_none(),
    }));
}

/// Fail-closed: editing a disclosure label post-production breaks the body
/// recompute — verify refuses, like any other tampered line.
#[test]
fn verify_refuses_tampered_disclosure() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 800, "scale": 0 });
    let inputs = inputs_of(vec![rec]);
    let mut pack = compute_ok(&inputs, &base_config());
    let market = pack
        .lines
        .iter_mut()
        .find(|l| l.method == Some(ghg_ledger_spine::Method::Market))
        .unwrap();
    market.disclosure = Some("residual mix not involved".to_string());
    match verify(&pack, &to_bytes(&inputs), &to_bytes(&base_config()), None) {
        Err(VerifyRefusal::BodyMismatch { what: "lines" }) => {}
        other => panic!("expected body mismatch on lines, got {other:?}"),
    }
}

/// Boundary: divergence exactly at the threshold does not warn (strictly
/// greater than).
#[test]
fn scope2_divergence_at_threshold_does_not_warn() {
    // 1000 kWh: loc 400000, mkt 200000 → exactly 5000 bps.
    let mut config = base_config();
    config["scope2_divergence_warn_bps"] = json!(5000);
    let pack = compute_ok(
        &inputs_of(vec![record(
            "rec-1",
            "scope2",
            "grid_electricity",
            1000,
            "kWh",
        )]),
        &config,
    );
    assert_eq!(pack.lines.len(), 2);
    assert!(!pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-SCOPE2-DIVERGENCE"));
}

/// Edge case: a missing market factor blocks market-based reporting (gap
/// finding, no line, no divergence number — fail-closed, never a zero).
#[test]
fn scope2_missing_market_factor_blocks_market_only() {
    let mut config = base_config();
    config["factors"]
        .as_array_mut()
        .unwrap()
        .retain(|row| !(row["activity"] == "grid_electricity" && row["method"] == "market"));
    let pack = compute_ok(
        &inputs_of(vec![record(
            "rec-1",
            "scope2",
            "grid_electricity",
            1000,
            "kWh",
        )]),
        &config,
    );
    assert!(pack
        .lines
        .iter()
        .any(|l| l.method == Some(ghg_ledger_spine::Method::Location)));
    assert!(!pack
        .lines
        .iter()
        .any(|l| l.method == Some(ghg_ledger_spine::Method::Market)));
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-FACTOR-MISSING" && f.message.contains("market")));
    assert!(!pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-SCOPE2-DIVERGENCE"));
}

/// Edge case: market coverage above the activity quantity is an input breach
/// — fail closed.
#[test]
fn scope2_overcoverage_is_input_breach() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 1200, "scale": 0 });
    let pack = compute_ok(&inputs_of(vec![rec]), &base_config());
    assert!(pack.lines.is_empty());
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-INPUT-INVALID" && f.severity == spine::Severity::Breach));
}

/// Edge case: market_coverage on a non-scope-2 record is an input breach.
#[test]
fn market_coverage_on_scope1_is_input_breach() {
    let mut rec = record("rec-1", "scope1", "natural_gas", 2, "MWh");
    rec["market_covered"] = json!({ "value": 1, "scale": 0 });
    let pack = compute_ok(&inputs_of(vec![rec]), &base_config());
    assert!(pack.lines.is_empty());
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-INPUT-INVALID"));
}

// --- Scope 3: category tagging boundaries ---

/// Test anchor: Scope 3 category tagging (categories 1–15 as config).
#[test]
fn scope3_category_tagging_boundaries() {
    let pack = compute_ok(
        &inputs_of(vec![
            scope3_record("rec-1", "purchased_goods", 10, "kg"),
            scope3_record("rec-2", "business_travel_air", 10, "passenger_km"),
            scope3_record("rec-3", "investments", 1000, "usd"),
        ]),
        &base_config(),
    );
    assert_eq!(pack.lines.len(), 3);
    assert!(pack.lines.iter().all(|l| l.scope3_category.is_some()));
    assert_eq!(pack.lines[0].scope3_category, Some(1));
    assert_eq!(pack.lines[1].scope3_category, Some(6));
    assert_eq!(pack.lines[2].scope3_category, Some(15));
    assert_eq!(pack.lines[2].emission_grams, 200); // 1000 usd × 0.2 g/usd, half-up
}

/// Edge case: an activity with no configured category mapping is a gap
/// finding — never silently dropped, never defaulted.
#[test]
fn scope3_unmapped_activity_is_gap() {
    let pack = compute_ok(
        &inputs_of(vec![scope3_record("rec-1", "waste", 5, "kg")]),
        &base_config(),
    );
    assert!(pack.lines.is_empty());
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-SCOPE3-UNMAPPED" && f.subject == "rec-1"));
}

/// Config validation: category boundaries (1–15), no duplicate category
/// numbers, and no activity mapped to two categories.
#[test]
fn scope3_invalid_category_config_rejected() {
    let mut config = base_config();
    config["scope3_categories"][0]["category"] = json!(0);
    let inputs = inputs_of(vec![scope3_record("rec-1", "purchased_goods", 1, "kg")]);
    assert!(matches!(
        compute_pack(&inputs, &config),
        Err(ComputeError::ConfigSchema(_))
    ));

    let mut config = base_config();
    config["scope3_categories"][2]["category"] = json!(16);
    assert!(matches!(
        compute_pack(&inputs, &config),
        Err(ComputeError::ConfigSchema(_))
    ));

    let mut config = base_config();
    config["scope3_categories"][2]["activities"] = json!(["investments", "purchased_goods"]);
    assert!(matches!(
        compute_pack(&inputs, &config),
        Err(ComputeError::ConfigSchema(_))
    ));
}

// --- Data quality: tier boundaries flow through to lines ---

/// Test anchor: data-quality scores flow through to line-level confidence
/// labels — boundaries included.
#[test]
fn dq_confidence_labels_at_tier_boundaries() {
    let label = |dq: Option<i64>| {
        let mut r = record("rec-1", "scope1", "natural_gas", 1, "kWh");
        r["dq_score"] = json!(dq);
        let pack = compute_ok(&inputs_of(vec![r]), &base_config());
        pack.lines[0].confidence.clone()
    };
    assert_eq!(label(Some(90)), "high"); // ≥ 90 first tier
    assert_eq!(label(Some(89)), "medium");
    assert_eq!(label(Some(50)), "medium"); // ≥ 50 second tier
    assert_eq!(label(Some(49)), "low");
    assert_eq!(label(Some(0)), "low");
    assert_eq!(label(None), "not_reported");
}

/// Config validation: DQ tiers must cover 0 and descend strictly.
#[test]
fn dq_tier_config_must_cover_zero_and_descend() {
    let mut config = base_config();
    config["dq_tiers"] = json!([{ "min_score": 90, "label": "high" }]);
    assert!(matches!(
        compute_pack(&inputs_of(vec![]), &config),
        Err(ComputeError::ConfigSchema(_))
    ));

    let mut config = base_config();
    config["dq_tiers"] = json!([
        { "min_score": 90, "label": "high" },
        { "min_score": 50, "label": "medium" },
        { "min_score": 50, "label": "low" }
    ]);
    assert!(matches!(
        compute_pack(&inputs_of(vec![]), &config),
        Err(ComputeError::ConfigSchema(_))
    ));

    let mut config = base_config();
    config["dq_tiers"] = json!([
        { "min_score": 101, "label": "high" },
        { "min_score": 50, "label": "medium" },
        { "min_score": 0, "label": "low" }
    ]);
    assert!(matches!(
        compute_pack(&inputs_of(vec![]), &config),
        Err(ComputeError::ConfigSchema(_))
    ));
}

// --- Arithmetic: half-up rounding to grams ---

/// Fixed-point half-up rounding to integer grams: 0.5 rounds up, 0.4 down.
#[test]
fn half_up_rounding_to_grams() {
    let mut config = base_config();
    config["factors"].as_array_mut().unwrap().push(json!({
        "activity": "half_up_test", "unit": "unit", "region": "US", "year": 2025,
        "method": null, "factor": { "value": 5, "scale": 1 },
        "factor_version": "seed-test-v1", "source": "seed:test"
    }));

    let inputs = inputs_of(vec![record("rec-1", "scope1", "half_up_test", 1, "unit")]);
    let pack = compute_ok(&inputs, &config);
    assert_eq!(pack.lines[0].emission_grams, 1); // 1 × 0.5 → 1 (0.5 rounds up)

    let mut config = config.clone();
    for row in config["factors"].as_array_mut().unwrap() {
        if row["activity"] == "half_up_test" {
            row["factor"] = json!({ "value": 4, "scale": 1 });
        }
    }
    let pack = compute_ok(&inputs, &config);
    assert_eq!(pack.lines[0].emission_grams, 0); // 1 × 0.4 → 0
}

// --- Input-shape breaches ---

/// Edge case: negative and zero quantities are input breaches, never lines.
#[test]
fn negative_and_zero_quantity_are_input_breaches() {
    for value in [0i64, -5] {
        let pack = compute_ok(
            &inputs_of(vec![record("rec-1", "scope1", "natural_gas", value, "kWh")]),
            &base_config(),
        );
        assert!(pack.lines.is_empty());
        assert!(pack
            .pack
            .findings
            .iter()
            .any(|f| f.rule_id == "GHG-INPUT-INVALID"
                && f.severity == spine::Severity::Breach
                && f.subject == "rec-1"));
    }
}

/// Edge case: duplicate record ids make the population ambiguous — the
/// whole input set is refused with a breach, no lines computed.
#[test]
fn duplicate_record_id_is_breach() {
    let pack = compute_ok(
        &inputs_of(vec![
            record("rec-1", "scope1", "natural_gas", 1, "kWh"),
            record("rec-1", "scope1", "natural_gas", 2, "kWh"),
        ]),
        &base_config(),
    );
    assert!(pack.lines.is_empty());
    assert!(pack
        .pack
        .findings
        .iter()
        .any(|f| f.rule_id == "GHG-INPUT-DUPLICATE" && f.subject == "rec-1"));
}

/// Edge case: unknown scope string fails closed at parse time.
#[test]
fn unknown_scope_is_rejected() {
    let inputs = inputs_of(vec![record("rec-1", "scope4", "natural_gas", 1, "kWh")]);
    assert!(matches!(
        compute_pack(&inputs, &base_config()),
        Err(ComputeError::Parse { what: "inputs", .. })
    ));
}

// --- Determinism ---

/// Same records in a different byte order produce identical ledger lines and
/// findings — order only shifts the inputs hash, never the body.
#[test]
fn deterministic_output_regardless_of_input_order() {
    let a = record("rec-a", "scope1", "natural_gas", 1, "kWh");
    let b = scope3_record("rec-b", "business_travel_air", 10, "passenger_km");
    let pack_one = compute_ok(&inputs_of(vec![a.clone(), b.clone()]), &base_config());
    let pack_two = compute_ok(&inputs_of(vec![b, a]), &base_config());

    assert_eq!(
        serde_json::to_vec(&pack_one.lines).unwrap(),
        serde_json::to_vec(&pack_two.lines).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&pack_one.pack.findings).unwrap(),
        serde_json::to_vec(&pack_two.pack.findings).unwrap()
    );
    assert_eq!(pack_one.pack.params_hash, pack_two.pack.params_hash);
    assert_ne!(pack_one.pack.inputs_hash, pack_two.pack.inputs_hash);
}

/// Test anchor: ledger keys are the canonical grouping — `scope1`,
/// `scope2:location`, `scope2:market`, `scope3:cat-N`.
#[test]
fn ledger_keys_match_spec() {
    let mut rec = record("rec-1", "scope2", "grid_electricity", 1000, "kWh");
    rec["market_covered"] = json!({ "value": 500, "scale": 0 });
    let pack = compute_ok(
        &inputs_of(vec![
            record("rec-0", "scope1", "natural_gas", 1, "kWh"),
            rec,
            scope3_record("rec-3", "investments", 10, "usd"),
        ]),
        &base_config(),
    );
    let keys: Vec<String> = pack
        .lines
        .iter()
        .map(ghg_ledger_spine::ledger_key)
        .collect();
    assert!(keys.contains(&"scope1".to_string()));
    assert!(keys.contains(&"scope2:location".to_string()));
    assert!(keys.contains(&"scope2:market".to_string()));
    assert!(keys.contains(&"scope3:cat-15".to_string()));
}

// --- Restatements: new versions, lineage, deltas ---

/// Test anchor: restatement delta correctness — new ledger version with
/// reason, predecessor lineage, and per-key deltas; the predecessor pack is
/// untouched.
#[test]
fn restatement_delta_correctness() {
    let config = base_config();
    let prior_inputs = inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]);
    let prior = compute_ok(&prior_inputs, &config);

    let corrected_inputs = inputs_of(vec![
        record("rec-1", "scope1", "natural_gas", 3, "MWh"),
        scope3_record("rec-2", "business_travel_air", 10, "passenger_km"),
    ]);
    let corrected = compute(
        &to_bytes(&corrected_inputs),
        &to_bytes(&config),
        Some(ghg_ledger_spine::RestatementRequest {
            prior: prior.clone(),
            reason: "meter correction: rec-1 under-reported".into(),
        }),
    )
    .expect("restatement compute must succeed");

    let restatement = corrected.restatement.as_ref().expect("restatement block");
    assert_eq!(restatement.reason, "meter correction: rec-1 under-reported");
    assert_eq!(restatement.predecessor_body_hash, prior.pack.body_hash);
    assert_eq!(restatement.predecessor_inputs_hash, prior.pack.inputs_hash);

    let mut deltas = restatement.deltas.clone();
    deltas.sort_by(|a, b| a.ledger_key.cmp(&b.ledger_key));
    assert_eq!(deltas[0].ledger_key, "scope1");
    assert_eq!(deltas[0].prior_grams, 400_000);
    assert_eq!(deltas[0].current_grams, 600_000);
    assert_eq!(deltas[0].delta_grams, 200_000);
    assert_eq!(deltas[1].ledger_key, "scope3:cat-6");
    assert_eq!(deltas[1].prior_grams, 0);
    assert_eq!(deltas[1].delta_grams, 1_500);

    // Predecessor immutability.
    assert_eq!(prior.lines.len(), 1);

    // The corrected pack verifies, with and without the predecessor.
    verify(
        &corrected,
        &to_bytes(&corrected_inputs),
        &to_bytes(&config),
        Some(&prior),
    )
    .expect("restated pack must verify");
}

/// Edge case: a restatement requires a non-empty reason.
#[test]
fn restatement_requires_reason() {
    let config = base_config();
    let prior = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 1, "MWh")]),
        &config,
    );
    let corrected = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &config,
    );
    assert!(matches!(
        ghg_ledger_spine::pack::build_restatement(&prior, "   ", &corrected.lines, "2025-FY"),
        Err(ComputeError::Restatement(_))
    ));
}

/// Edge case: a restatement links versions of the same period — a predecessor
/// from another period is refused.
#[test]
fn restatement_period_mismatch_refused() {
    let mut prior_config = base_config();
    prior_config["period"] = json!("2024-FY");
    let prior = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 1, "MWh")]),
        &prior_config,
    );
    let corrected = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &base_config(),
    );
    assert!(matches!(
        ghg_ledger_spine::pack::build_restatement(&prior, "meter fix", &corrected.lines, "2025-FY"),
        Err(ComputeError::Restatement(_))
    ));
}

/// Fail-closed: a tampered predecessor pack cannot seed a restatement — the
/// predecessor's seal must recompute.
#[test]
fn restatement_refuses_tampered_predecessor() {
    let config = base_config();
    let mut prior = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 1, "MWh")]),
        &config,
    );
    // Inject a synthetic finding into the predecessor body: the mutation
    // breaks the predecessor's seal, which the restatement must refuse.
    prior.pack.findings.push(spine::Finding::breach(
        "GHG-INPUT-INVALID",
        "rec-1",
        "tampered",
    ));

    let corrected = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &config,
    );
    assert!(matches!(
        ghg_ledger_spine::pack::build_restatement(&prior, "meter fix", &corrected.lines, "2025-FY"),
        Err(ComputeError::Restatement(_))
    ));
}

// --- Fail-closed evidence packs ---

/// Test anchor: a tampered evidence pack must fail `verify` — edits to the
/// product body (lines) break the recompute comparison.
#[test]
fn verify_refuses_tampered_lines() {
    let inputs = inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]);
    let mut pack = compute_ok(&inputs, &base_config());
    pack.lines[0].emission_grams += 1;
    match verify(&pack, &to_bytes(&inputs), &to_bytes(&base_config()), None) {
        Err(VerifyRefusal::BodyMismatch { what: "lines" }) => {}
        other => panic!("expected body mismatch on lines, got {other:?}"),
    }
}

/// A tampered findings list breaks the spine seal.
#[test]
fn verify_refuses_tampered_findings() {
    let inputs = inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]);
    let mut pack = compute_ok(&inputs, &base_config());
    pack.pack.findings.push(spine::Finding::breach(
        "GHG-TEST",
        "rec-1",
        "injected post-production",
    ));
    assert!(matches!(
        verify(&pack, &to_bytes(&inputs), &to_bytes(&base_config()), None),
        Err(VerifyRefusal::Spine(SpineVerifyError::BodyHashMismatch))
    ));
}

/// Provenance: verifying against different inputs than the pack was built
/// from refuses on the inputs hash.
#[test]
fn verify_refuses_different_inputs() {
    let pack = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]),
        &base_config(),
    );
    let other = inputs_of(vec![record("rec-1", "scope1", "natural_gas", 3, "MWh")]);
    assert!(matches!(
        verify(&pack, &to_bytes(&other), &to_bytes(&base_config()), None),
        Err(VerifyRefusal::Spine(SpineVerifyError::HashMismatch {
            field: "inputs"
        }))
    ));
}

/// A restated pack verified without its predecessor refuses — lineage cannot
/// be checked that is not presented.
#[test]
fn verify_requires_prior_for_restatement_pack() {
    let config = base_config();
    let prior = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 1, "MWh")]),
        &config,
    );
    let corrected_inputs = inputs_of(vec![record("rec-1", "scope1", "natural_gas", 2, "MWh")]);
    let corrected = compute(
        &to_bytes(&corrected_inputs),
        &to_bytes(&config),
        Some(ghg_ledger_spine::RestatementRequest {
            prior,
            reason: "meter fix".into(),
        }),
    )
    .unwrap();
    assert!(matches!(
        verify(
            &corrected,
            &to_bytes(&corrected_inputs),
            &to_bytes(&config),
            None
        ),
        Err(VerifyRefusal::RestatementRequiresPriorPack)
    ));
}

/// Family contract: provenance hashes are computed over canonical bytes, so
/// whitespace-key ordering changes in the input file do not change the hash.
#[test]
fn provenance_hashes_use_canonical_bytes() {
    let a = r#"{"records":[{"record_id":"rec-1","scope":"scope1","activity":"natural_gas",
        "quantity":{"value":1,"scale":0},"unit":"kWh","region":"US","year":2025}]}"#;
    let b = r#"{"records": [{"year": 2025, "region": "US", "unit": "kWh", "quantity": {"scale": 0, "value": 1}, "activity": "natural_gas", "scope": "scope1", "record_id": "rec-1"}]}"#;
    let config = to_bytes(&base_config());
    let pack_a = compute(a.as_bytes(), &config, None).unwrap();
    let pack_b = compute(b.as_bytes(), &config, None).unwrap();
    assert_eq!(pack_a.pack.inputs_hash, pack_b.pack.inputs_hash);
    assert_eq!(
        pack_a.pack.inputs_hash,
        spine::sha256_hex(
            &ghg_ledger_spine::engine::canonical_json(a.as_bytes(), "inputs").unwrap(),
        )
    );
}

/// The pack carries the current spine version and this crate's identity —
/// foreign-version packs are refused by the spine gate (covered in the spine
/// crate); here we pin the family contract: engine id and spine version.
#[test]
fn pack_carries_engine_and_spine_identity() {
    let pack = compute_ok(
        &inputs_of(vec![record("rec-1", "scope1", "natural_gas", 1, "kWh")]),
        &base_config(),
    );
    assert_eq!(pack.pack.engine_id, ghg_ledger_spine::ENGINE_ID);
    assert_eq!(pack.pack.spine_version, SPINE_VERSION);
    assert!(!pack.pack.tool_version.is_empty());
}
