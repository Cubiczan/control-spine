//! End-to-end CLI tests: the binary is exercised as a process against
//! fixture files, covering the compute → verify → explain surface, refusal
//! exit codes, and a signed pack accepted through the CLI.

use std::path::PathBuf;
use std::process::Command;

use dqf_spine::spine::{LockState, Signoff, SignoffDecision};
use dqf_spine::{DqfConfig, DqfError};

const BIN: &str = env!("CARGO_BIN_EXE_dqf-spine");
const AS_OF: &str = "2026-09-22";

const CONFIG_JSON: &str = r#"{
    "expiring_warn_days": 30,
    "mvr_validity_days": 365,
    "annual_review_validity_days": 365,
    "medical": {"full_max_months": 24, "variance_max_months": 12},
    "checklist": {
        "cdl": {}, "medical_certificate": {}, "mvr": {},
        "annual_review": {}, "road_test": {}, "employment_history": {}
    },
    "state_cdl_rules": []
}"#;

const CLEAN_DRIVERS_JSON: &str = r#"{"drivers": [{
    "driver_id": "D-001", "employee_id": "E-100", "cycle_id": "CY-2026",
    "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
    "documents": [
        {"doc_id": "c1", "kind": "cdl", "cycle_id": "CY-2026", "issued_on": "2024-09-01", "expires_on": "2027-09-01", "state": "TX", "endorsements": []},
        {"doc_id": "m1", "kind": "medical_certificate", "cycle_id": "CY-2026", "issued_on": "2025-09-01", "expires_on": "2027-09-01", "cert_type": "full"},
        {"doc_id": "v1", "kind": "mvr", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
        {"doc_id": "a1", "kind": "annual_review", "cycle_id": "CY-2026", "issued_on": "2026-08-01"},
        {"doc_id": "r1", "kind": "road_test", "cycle_id": "CY-2026", "issued_on": "2024-02-01"},
        {"doc_id": "h1", "kind": "employment_history", "cycle_id": "CY-2026", "issued_on": "2020-01-01"}
    ]
}]}"#;

/// Active driver with an expired medical certificate — an OOS breach.
const BREACH_DRIVERS_JSON: &str = r#"{"drivers": [{
    "driver_id": "D-101", "employee_id": "E-101", "cycle_id": "CY-2026",
    "hire_date": "2020-01-01", "active": true, "cdl_state": "TX",
    "documents": [
        {"doc_id": "c1", "kind": "cdl", "cycle_id": "CY-2026", "issued_on": "2024-01-01", "expires_on": "2027-01-01", "state": "TX", "endorsements": []},
        {"doc_id": "m1", "kind": "medical_certificate", "cycle_id": "CY-2026", "issued_on": "2024-01-01", "expires_on": "2025-06-01", "cert_type": "full"},
        {"doc_id": "v1", "kind": "mvr", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
        {"doc_id": "a1", "kind": "annual_review", "cycle_id": "CY-2026", "issued_on": "2026-05-01"},
        {"doc_id": "r1", "kind": "road_test", "cycle_id": "CY-2026", "issued_on": "2024-01-01"},
        {"doc_id": "h1", "kind": "employment_history", "cycle_id": "CY-2026", "issued_on": "2020-01-01"}
    ]
}]}"#;

struct Fixture {
    dir: PathBuf,
    drivers: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new(name: &str, drivers_json: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("dqf-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir is creatable");
        let drivers = dir.join("drivers.json");
        let config = dir.join("config.json");
        std::fs::write(&drivers, drivers_json).expect("fixture is writable");
        std::fs::write(&config, CONFIG_JSON).expect("fixture is writable");
        Fixture {
            dir,
            drivers,
            config,
        }
    }

    fn pack(&self) -> PathBuf {
        self.dir.join("pack.json")
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(BIN).args(args).output().expect("binary runs")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn compute_then_verify_clean_pack_succeeds() {
    let fx = Fixture::new("clean", CLEAN_DRIVERS_JSON);
    let out = fx.run(&[
        "compute",
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
        "--output",
        fx.pack().to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success(), "compute failed: {:?}", out.stderr);
    assert!(fx.pack().exists(), "pack file is written");

    let out = fx.run(&[
        "verify",
        "--pack",
        fx.pack().to_str().expect("utf-8 path"),
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success(), "clean pack must verify");
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK"));
}

#[test]
fn verify_refuses_a_pack_with_an_unresolved_oos_breach() {
    let fx = Fixture::new("breach", BREACH_DRIVERS_JSON);
    let out = fx.run(&[
        "compute",
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
        "--output",
        fx.pack().to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success(), "compute itself succeeds");

    let out = fx.run(&[
        "verify",
        "--pack",
        fx.pack().to_str().expect("utf-8 path"),
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out.status.code(), Some(1), "unsigned breach must refuse");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("REFUSED"), "refusal must be named: {err}");
    assert!(
        err.contains("unresolved finding"),
        "reason must be named: {err}"
    );
}

#[test]
fn verify_refuses_tampered_inputs() {
    let fx = Fixture::new("tamper", CLEAN_DRIVERS_JSON);
    let out = fx.run(&[
        "compute",
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
        "--output",
        fx.pack().to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success());

    // A single changed byte in the inputs must break the provenance hash.
    std::fs::write(&fx.drivers, format!("{CLEAN_DRIVERS_JSON}\n")).expect("fixture is writable");
    let out = fx.run(&[
        "verify",
        "--pack",
        fx.pack().to_str().expect("utf-8 path"),
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("hash mismatch: inputs"), "got: {err}");
}

#[test]
fn explain_lists_findings_and_signoff_state() {
    let fx = Fixture::new("explain", BREACH_DRIVERS_JSON);
    let out = fx.run(&[
        "compute",
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
        "--output",
        fx.pack().to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success());

    let out = fx.run(&["explain", "--pack", fx.pack().to_str().expect("utf-8 path")]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("D-101"), "driver subject is listed: {text}");
    assert!(
        text.contains("DQF-MED-EXPIRED"),
        "rule id is listed: {text}"
    );
    assert!(text.contains("BREACH"), "severity is listed: {text}");
    assert!(
        text.contains("UNRESOLVED"),
        "unsigned breach is marked: {text}"
    );
}

#[test]
fn compute_refuses_an_unknown_config_field() {
    let fx = Fixture::new("badschema", CLEAN_DRIVERS_JSON);
    std::fs::write(
        &fx.config,
        CONFIG_JSON.replace("state_cdl_rules", "bogus_extra"),
    )
    .expect("fixture is writable");
    let out = fx.run(&[
        "compute",
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
        "--as-of",
        AS_OF,
    ]);
    assert_eq!(out.status.code(), Some(2), "schema refusal exits 2");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown field"), "got: {err}");
}

#[test]
fn verify_accepts_a_signed_pack() {
    // Build a pack with the library, walk it through the lock lifecycle with
    // a four-eyes approval, and hand it to the CLI for verification.
    let fx = Fixture::new("signed", BREACH_DRIVERS_JSON);
    let drivers_bytes = std::fs::read(&fx.drivers).expect("fixture is readable");
    let config_bytes = std::fs::read(&fx.config).expect("fixture is readable");
    let as_of = chrono::NaiveDate::parse_from_str(AS_OF, "%Y-%m-%d").expect("test date");

    let mut pack = dqf_spine::build_pack(&drivers_bytes, &config_bytes, as_of)
        .expect("breach fixture computes");
    pack.signoffs = vec![signoff("sam", "D-101"), signoff("alex", "D-101")];
    let state =
        dqf_spine::spine::advance_lock(LockState::Draft, &mut pack).expect("draft advances");
    let state = dqf_spine::spine::advance_lock(state, &mut pack).expect("breaches resolved");
    assert_eq!(state, LockState::Signed);
    std::fs::write(
        fx.pack(),
        serde_json::to_vec(&pack).expect("serialization cannot fail"),
    )
    .expect("fixture is writable");

    let out = fx.run(&[
        "verify",
        "--pack",
        fx.pack().to_str().expect("utf-8 path"),
        "--drivers",
        fx.drivers.to_str().expect("utf-8 path"),
        "--config",
        fx.config.to_str().expect("utf-8 path"),
    ]);
    assert!(
        out.status.success(),
        "signed pack must verify: {:?}",
        out.stderr
    );
}

/// Re-export silence check: the public types stay nameable from outside.
#[allow(dead_code)]
fn types_are_public(_config: Result<DqfConfig, DqfError>) {}

fn signoff(actor: &str, subject: &str) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "safety_director".to_string(),
        subject: subject.to_string(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T00:00:00Z".to_string(),
    }
}
