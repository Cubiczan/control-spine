//! End-to-end CLI tests: real files, real exit codes. The filesystem use
//! here is the test harness's — the engine and pack modules stay pure.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use coi_spine::cli::{self, Cli};

const CONFIG_JSON: &str = r#"{
    "categories": {
        "electrical_contractor": {
            "critical": true,
            "coverages": {
                "general_liability": {
                    "per_occurrence_cents": 100000000,
                    "aggregate_cents": 200000000,
                    "endorsements": ["additional_insured"]
                },
                "workers_comp": {
                    "per_occurrence_cents": 50000000,
                    "aggregate_cents": 50000000
                }
            }
        }
    },
    "expiry_warning_days": 30,
    "min_carrier_rating": "a_minus"
}"#;

fn cert_json(vendor: &str, gl_expiration: &str) -> String {
    format!(
        r#"{{
        "vendor_id": "{vendor}",
        "vendor_category": "electrical_contractor",
        "policies": [
            {{
                "policy_number": "GL-2026-001",
                "carrier_name": "Seed Mutual",
                "carrier_rating": "a",
                "coverage": "general_liability",
                "per_occurrence_limit_cents": 100000000,
                "aggregate_limit_cents": 200000000,
                "effective_date": "2026-01-01",
                "expiration_date": "{gl_expiration}",
                "endorsements": ["additional_insured"]
            }},
            {{
                "policy_number": "WC-2026-001",
                "carrier_name": "Seed Mutual",
                "carrier_rating": "a_minus",
                "coverage": "workers_comp",
                "per_occurrence_limit_cents": 100000000,
                "aggregate_limit_cents": 100000000,
                "effective_date": "2026-01-01",
                "expiration_date": "2027-06-30"
            }}
        ]
    }}"#
    )
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("coi-spine-e2e-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir creates");
    dir
}

fn cli(args: &[&str]) -> i32 {
    let parsed = Cli::try_parse_from(std::iter::once("coi-spine").chain(args.iter().copied()))
        .expect("CLI arguments parse");
    cli::run(parsed)
}

#[test]
fn compute_sign_verify_roundtrip_on_clean_pack() {
    let dir = temp_dir("clean");
    let cert = dir.join("cert.json");
    let matrix = dir.join("matrix.json");
    let pack = dir.join("pack.json");
    fs::write(&cert, cert_json("V-1001", "2027-12-31")).unwrap();
    fs::write(&matrix, CONFIG_JSON).unwrap();

    assert_eq!(
        cli(&[
            "compute",
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
            "--out",
            pack.to_str().unwrap()
        ]),
        0
    );
    assert!(pack.exists());

    assert_eq!(cli(&["sign", "--pack", pack.to_str().unwrap()]), 0);

    assert_eq!(
        cli(&[
            "verify",
            "--pack",
            pack.to_str().unwrap(),
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap()
        ]),
        0
    );

    // Tamper with the sealed pack: any body edit breaks the seal — exit 1.
    let tampered = dir.join("tampered.json");
    let body = fs::read_to_string(&pack).unwrap();
    fs::write(&tampered, body.replace("coi-spine", "coi-spine-tampered")).unwrap();
    assert_eq!(
        cli(&[
            "verify",
            "--pack",
            tampered.to_str().unwrap(),
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap()
        ]),
        1
    );
}

#[test]
fn breach_pack_refuses_until_subject_scoped_signoff() {
    let dir = temp_dir("breach");
    let cert = dir.join("cert.json");
    let matrix = dir.join("matrix.json");
    let pack = dir.join("pack.json");
    // GL expired the day before the clock date.
    fs::write(&cert, cert_json("V-1001", "2026-09-21")).unwrap();
    fs::write(&matrix, CONFIG_JSON).unwrap();

    // Breaches do not block compute — the pack is the input to review.
    assert_eq!(
        cli(&[
            "compute",
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
            "--out",
            pack.to_str().unwrap()
        ]),
        0
    );

    // An unsigned breach pack refuses to verify.
    assert_eq!(
        cli(&[
            "verify",
            "--pack",
            pack.to_str().unwrap(),
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap()
        ]),
        1
    );

    // A receipt naming the wrong subject does not resolve the breach.
    assert_eq!(
        cli(&[
            "sign",
            "--pack",
            pack.to_str().unwrap(),
            "--actor",
            "Reina Park",
            "--role",
            "risk_manager",
            "--subject",
            "V-9999",
            "--at",
            "2026-09-22T15:04:05Z",
        ]),
        1
    );

    // The subject-matched approval signs and seals.
    assert_eq!(
        cli(&[
            "sign",
            "--pack",
            pack.to_str().unwrap(),
            "--actor",
            "Reina Park",
            "--role",
            "risk_manager",
            "--subject",
            "V-1001",
            "--at",
            "2026-09-22T15:04:05Z",
        ]),
        0
    );
    assert_eq!(
        cli(&[
            "verify",
            "--pack",
            pack.to_str().unwrap(),
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap()
        ]),
        0
    );

    // Signed packs are immutable: a second sign attempt refuses outright.
    assert_eq!(cli(&["sign", "--pack", pack.to_str().unwrap()]), 1);
}

#[test]
fn refusal_and_usage_exit_codes() {
    let dir = temp_dir("refusals");
    let matrix = dir.join("matrix.json");
    fs::write(&matrix, CONFIG_JSON).unwrap();

    // Malformed certificate: unknown coverage kind → refusal, exit 1.
    let malformed = dir.join("malformed.json");
    fs::write(
        &malformed,
        cert_json("V-1001", "2027-12-31").replace("general_liability", "hull"),
    )
    .unwrap();
    assert_eq!(
        cli(&[
            "compute",
            "--inputs",
            malformed.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap(),
            "--as-of",
            "2026-09-22"
        ]),
        1
    );

    // Bad clock date → usage error, exit 2.
    let cert = dir.join("cert.json");
    fs::write(&cert, cert_json("V-1001", "2027-12-31")).unwrap();
    assert_eq!(
        cli(&[
            "compute",
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap(),
            "--as-of",
            "09/22/2026"
        ]),
        2
    );

    // Verify against different inputs than the pack was computed on → exit 1.
    let pack = dir.join("pack.json");
    assert_eq!(
        cli(&[
            "compute",
            "--inputs",
            cert.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap(),
            "--as-of",
            "2026-09-22",
            "--out",
            pack.to_str().unwrap()
        ]),
        0
    );
    assert_eq!(cli(&["sign", "--pack", pack.to_str().unwrap()]), 0);
    let other = dir.join("other.json");
    fs::write(&other, cert_json("V-2002", "2027-12-31")).unwrap();
    assert_eq!(
        cli(&[
            "verify",
            "--pack",
            pack.to_str().unwrap(),
            "--inputs",
            other.to_str().unwrap(),
            "--config",
            matrix.to_str().unwrap()
        ]),
        1
    );

    // Explain renders the rule set in force, exit 0.
    assert_eq!(cli(&["explain", "--config", matrix.to_str().unwrap()]), 0);
}
