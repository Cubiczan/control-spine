//! Integration tests: evidence-pack governance and the CLI boundary.
//!
//! Tests above the unit layer prove the fail-closed contract end to end —
//! packs verify against the exact bytes consumed, tampering is refused,
//! breach findings block verification until a signoff names the finding's
//! subject, and the engine cannot countersign its own pack.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bankrec_spine::{build_pack, compute, parse_config, parse_inputs, ComputeOutput};
use spine::{Signoff, SignoffDecision, SPINE_VERSION};

fn config_bytes(tolerance: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "tolerance_cents": tolerance,
        "max_group_size": 5,
        "stale_days": 14,
        "many_to_one_candidate_cap": 100
    }))
    .unwrap()
}

fn inputs_bytes() -> Vec<u8> {
    // One clean exact match; one unmatched statement line dated 30 days
    // before the as-of date (stale → breach).
    serde_json::to_vec(&serde_json::json!({
        "statement_lines": [
            {"id": "S1", "date": "2026-09-01", "reference": "WIRE-1", "amount_cents": 125_000},
            {"id": "S2", "date": "2026-08-23", "reference": "OLD-STMT", "amount_cents": -40_000}
        ],
        "ledger_entries": [
            {"id": "L1", "date": "2026-09-01", "reference": "WIRE-1", "side": "debit", "amount_cents": 125_000}
        ]
    })).unwrap()
}

fn as_of() -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 9, 22).unwrap()
}

fn signoff(actor: &str, subject: &str, decision: SignoffDecision) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "treasurer".to_string(),
        subject: subject.to_string(),
        decision,
        at: "2026-09-22T10:00:00Z".to_string(),
    }
}

fn compute_pack(inputs: &[u8], params: &[u8]) -> spine::EvidencePack {
    compute_pack_with(inputs, params, vec![])
}

/// The fixture's stale S2 line is a breach finding, so packs only verify
/// once a distinct human signoff naming `S2` is embedded (signoffs live
/// inside the sealed body).
fn signoffs_for_s2() -> Vec<Signoff> {
    vec![signoff("shyam", "S2", SignoffDecision::Approve)]
}

fn compute_pack_with(inputs: &[u8], params: &[u8], signoffs: Vec<Signoff>) -> spine::EvidencePack {
    let validated = parse_inputs(inputs).unwrap();
    let config = parse_config(params).unwrap();
    let report = compute(&validated, &config, as_of());
    build_pack(
        &report,
        bankrec_spine::ENGINE_ID,
        bankrec_spine::TOOL_VERSION,
        inputs,
        params,
        signoffs,
    )
}

#[test]
fn pack_roundtrip_verifies_against_original_bytes() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);
    let pack = compute_pack_with(&inputs, &params, signoffs_for_s2());
    assert_eq!(pack.spine_version, SPINE_VERSION);
    assert_eq!(pack.engine_id, bankrec_spine::ENGINE_ID);
    assert!(!pack.body_hash.is_empty());
    assert_eq!(pack.verify(&inputs, &params), Ok(()));

    // The CLI-facing ComputeOutput JSON round-trips and still verifies.
    let validated = parse_inputs(&inputs).unwrap();
    let cfg = parse_config(&params).unwrap();
    let report = compute(&validated, &cfg, as_of());
    let output = ComputeOutput {
        engine_id: bankrec_spine::ENGINE_ID.to_string(),
        tool_version: bankrec_spine::TOOL_VERSION.to_string(),
        as_of: as_of().to_string(),
        report: report.clone(),
        evidence_pack: pack.clone(),
    };
    let json = serde_json::to_vec(&output).unwrap();
    let back: ComputeOutput = serde_json::from_slice(&json).unwrap();
    assert_eq!(back.evidence_pack.verify(&inputs, &params), Ok(()));
    // The stale statement line is in the report as a breach finding.
    assert!(report
        .findings
        .iter()
        .any(|f| f.subject == "S2" && f.requires_signoff));
}

#[test]
fn pack_refuses_tampered_inputs() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);
    let pack = compute_pack(&inputs, &params);

    // Same logical inputs, different bytes (re-serialization) → refuse.
    let respaced: Vec<u8> =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&inputs).unwrap())
            .unwrap();
    assert_ne!(respaced, inputs);
    assert!(pack.verify(&respaced, &params).is_err());

    // Genuinely different inputs → refuse.
    let mut tampered: serde_json::Value = serde_json::from_slice(&inputs_bytes()).unwrap();
    tampered["statement_lines"][0]["amount_cents"] = serde_json::json!(125_001);
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert!(pack.verify(&tampered, &params).is_err());
}

#[test]
fn pack_refuses_config_change() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);
    let pack = compute_pack_with(&inputs, &params, signoffs_for_s2());
    assert_eq!(pack.verify(&inputs, &params), Ok(()));
    assert!(pack.verify(&inputs, &config_bytes(501)).is_err());
}

#[test]
fn pack_refuses_body_tampering_after_seal() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);
    let mut pack = compute_pack_with(&inputs, &params, signoffs_for_s2());
    assert_eq!(pack.verify(&inputs, &params), Ok(()));

    // Downgrade the stale breach to a warning after the fact — the seal
    // must break and verify must refuse even with original bytes.
    pack.findings.iter_mut().for_each(|f| {
        if f.subject == "S2" {
            f.severity = spine::Severity::Warn;
            f.requires_signoff = false;
        }
    });
    assert_eq!(
        pack.verify(&inputs, &params),
        Err(spine::VerifyError::BodyHashMismatch)
    );
}

#[test]
fn stale_breach_blocks_verify_until_subject_signoff() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);

    let unsigned = compute_pack(&inputs, &params);
    assert_eq!(
        unsigned.verify(&inputs, &params),
        Err(spine::VerifyError::UnresolvedBreach {
            rule_id: "stmt-unmatched".to_string()
        })
    );

    // Approval on the wrong subject does not resolve it. Signoffs live
    // inside the sealed body, so each variant is built and sealed with its
    // receipt embedded (spine::first_unresolved_finding checks the embedded
    // list; the body hash covers it).
    let wrong_subject = compute_pack_with(
        &inputs,
        &params,
        vec![signoff("shyam", "S1", SignoffDecision::Approve)],
    );
    assert!(wrong_subject.verify(&inputs, &params).is_err());

    // A distinct human approving the exact subject resolves the breach.
    let resolved = compute_pack_with(&inputs, &params, signoffs_for_s2());
    assert_eq!(resolved.verify(&inputs, &params), Ok(()));
}

#[test]
fn engine_cannot_countersign_own_pack() {
    let inputs = inputs_bytes();
    let params = config_bytes(500);
    let validated = parse_inputs(&inputs).unwrap();
    let cfg = parse_config(&params).unwrap();
    let report = compute(&validated, &cfg, as_of());

    let self_signed = build_pack(
        &report,
        bankrec_spine::ENGINE_ID,
        bankrec_spine::TOOL_VERSION,
        &inputs,
        &params,
        vec![signoff(
            bankrec_spine::ENGINE_ID,
            "S2",
            SignoffDecision::Approve,
        )],
    );
    assert!(self_signed.verify(&inputs, &params).is_err());
}

// --- CLI boundary ---

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bankrec-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_temp(dir: impl AsRef<Path>, name: &str, contents: &[u8]) -> PathBuf {
    let p = dir.as_ref().join(name);
    fs::write(&p, contents).unwrap();
    p
}

const BIN: &str = env!("CARGO_BIN_EXE_bankrec-spine");

#[test]
fn cli_compute_then_verify_roundtrip() {
    let tmp = TempDir::new("compute-verify");
    let dir = tmp.path();
    let inputs = write_temp(dir, "inputs.json", &inputs_bytes());
    let config = write_temp(dir, "config.json", &config_bytes(500));
    // The fixture's stale S2 line is a breach finding — embed a distinct
    // human approval so the produced pack verifies.
    let signoffs = write_temp(
        dir,
        "signoffs.json",
        serde_json::to_vec(&[serde_json::json!({
            "actor": "shyam",
            "role": "treasurer",
            "subject": "S2",
            "decision": "approve",
            "at": "2026-09-22T10:00:00Z"
        })])
        .unwrap()
        .as_slice(),
    );
    let out_path = dir.join("out.json");

    let out = Command::new(BIN)
        .args([
            "compute",
            "--inputs",
            inputs.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
            "--signoffs",
            signoffs.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "compute failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The pack verifies against the original bytes.
    let verify = Command::new(BIN)
        .args([
            "verify",
            "--pack",
            out_path.to_str().unwrap(),
            "--inputs",
            inputs.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify refused: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // Tampered inputs flip verify to exit code 1.
    let tampered = write_temp(
        dir,
        "tampered.json",
        b"{\"statement_lines\":[],\"ledger_entries\":[]}",
    );
    let refused = Command::new(BIN)
        .args([
            "verify",
            "--pack",
            out_path.to_str().unwrap(),
            "--inputs",
            tampered.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("REFUSED"));
}

#[test]
fn cli_explain_renders_the_report() {
    let tmp = TempDir::new("explain");
    let dir = tmp.path();
    let inputs = write_temp(dir, "inputs.json", &inputs_bytes());
    let config = write_temp(dir, "config.json", &config_bytes(500));
    let out_path = dir.join("out.json");

    assert!(Command::new(BIN)
        .args([
            "compute",
            "--inputs",
            inputs.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap()
        .status
        .success());

    let out = Command::new(BIN)
        .args(["explain", "--report", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("bankrec-spine — bank reconciliation report"));
    assert!(text.contains("[exact        ] S1 ← L1"));
    assert!(text.contains("STALE"));
    assert!(text.contains("Adjustment proposals"));
}

#[test]
fn cli_rejects_invalid_config_with_exit_two() {
    let tmp = TempDir::new("bad-config");
    let dir = tmp.path();
    let inputs = write_temp(dir, "inputs.json", &inputs_bytes());
    let bad_config = write_temp(
        dir,
        "config.json",
        serde_json::to_vec(&serde_json::json!({"tolerance_cents": 0, "max_group_size": 9}))
            .unwrap()
            .as_slice(),
    );
    let out = Command::new(BIN)
        .args([
            "compute",
            "--inputs",
            inputs.to_str().unwrap(),
            "--config",
            bad_config.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("config invalid"));
}

#[test]
fn cli_rejects_bad_as_of_date() {
    let tmp = TempDir::new("bad-asof");
    let dir = tmp.path();
    let inputs = write_temp(dir, "inputs.json", &inputs_bytes());
    let config = write_temp(dir, "config.json", &config_bytes(500));
    let out = Command::new(BIN)
        .args([
            "compute",
            "--inputs",
            inputs.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--as-of",
            "09/22/2026",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--as-of"));
}
