//! End-to-end CLI tests: the binary moves bytes and maps refusals to exit
//! codes — 0 verifies, 1 refuses, 2 is a usage/IO error. All logic lives in
//! the library and is covered by tests/engine.rs.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ghg-ledger-spine")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ghg-cli-{}-{}", std::process::id(), label));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
    fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        let mut f = std::fs::File::create(&path).expect("create file");
        f.write_all(content.as_bytes()).expect("write file");
        path
    }
}

fn run(args: &[String]) -> (i32, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).expect("utf8 stdout"),
        String::from_utf8(out.stderr).expect("utf8 stderr"),
    )
}

const INPUTS: &str = r#"{"records":[{"record_id":"rec-1","scope":"scope1","activity":"natural_gas","quantity":{"value":2,"scale":0},"unit":"MWh","region":"US","year":2025}]}"#;

const CONFIG: &str = r#"{
  "period": "2025-FY",
  "conversions": [
    { "from_unit": "MWh", "to_unit": "kWh", "factor": { "value": 1000, "scale": 0 } }
  ],
  "factors": [
    { "activity": "natural_gas", "unit": "kWh", "region": "US", "year": 2025, "method": null,
      "factor": { "value": 200, "scale": 0 }, "factor_version": "seed-stationary-v1", "source": "seed:epa-style" }
  ],
  "scope3_categories": [
    { "category": 1, "activities": ["purchased_goods"] }
  ],
  "dq_tiers": [
    { "min_score": 90, "label": "high" },
    { "min_score": 50, "label": "medium" },
    { "min_score": 0, "label": "low" }
  ],
  "scope2_divergence_warn_bps": 1000
}"#;

fn paths(label: &str) -> (TempDir, PathBuf, PathBuf) {
    let dir = TempDir::new(label);
    let inputs = dir.write("inputs.json", INPUTS);
    let config = dir.write("config.json", CONFIG);
    (dir, inputs, config)
}

#[test]
fn compute_verify_roundtrip() {
    let (dir, inputs, config) = paths("roundtrip");
    let (code, stdout, _) = run(&[
        "compute".into(),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 0, "compute failed: {stdout}");
    assert!(
        stdout.contains("\"inputs_hash\""),
        "stdout must be a pack JSON: {stdout}"
    );

    let pack_path = dir.write("pack.json", &stdout);

    let (code, stdout, stderr) = run(&[
        "verify".into(),
        format!("--pack={}", pack_path.display()),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 0, "verify refused: {stderr}");
    assert!(stdout.starts_with("ok:"), "verify output: {stdout}");
}

#[test]
fn verify_refuses_tampered_pack() {
    let (dir, inputs, config) = paths("tamper");
    let (code, stdout, _) = run(&[
        "compute".into(),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 0);

    // Tamper with the product body: inflate one emission line.
    let tampered = stdout.replace("\"emission_grams\": 400000", "\"emission_grams\": 400001");
    assert_ne!(tampered, stdout, "tamper must change the pack");
    let pack_path = dir.write("pack.json", &tampered);

    let (code, _, stderr) = run(&[
        "verify".into(),
        format!("--pack={}", pack_path.display()),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 1, "tampered pack must refuse");
    assert!(
        stderr.contains("refused"),
        "refusal must be explicit: {stderr}"
    );
}

#[test]
fn explain_renders_pack() {
    let (dir, inputs, config) = paths("explain");
    let (code, stdout, _) = run(&[
        "compute".into(),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 0);
    let pack_path = dir.write("pack.json", &stdout);

    let (code, stdout, stderr) =
        run(&["explain".into(), format!("--pack={}", pack_path.display())]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("period: 2025-FY"));
    assert!(stdout.contains("scope1: 400000"));
    assert!(stdout.contains("signoffs: 0"));
    assert!(stdout.contains("restatement: none"));
}

#[test]
fn restatement_flow() {
    let (dir, inputs, config) = paths("restatement");
    let (code, prior_stdout, _) = run(&[
        "compute".into(),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 0);
    let prior_path = dir.write("prior.json", &prior_stdout);

    // Corrected inputs: one more MWh consumed.
    let corrected = INPUTS.replace("\"value\":2", "\"value\":3");
    let corrected_inputs = dir.write("corrected.json", &corrected);

    let (code, stdout, stderr) = run(&[
        "compute".into(),
        format!("--inputs={}", corrected_inputs.display()),
        format!("--config={}", config.display()),
        format!("--prior-pack={}", prior_path.display()),
        "--reason=utility meter correction".into(),
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("\"restatement\""),
        "restated pack must carry the block"
    );
    assert!(stdout.contains("utility meter correction"));
    let pack_path = dir.write("pack.json", &stdout);

    // Verified with the predecessor presented.
    let (code, _, stderr) = run(&[
        "verify".into(),
        format!("--pack={}", pack_path.display()),
        format!("--inputs={}", corrected_inputs.display()),
        format!("--config={}", config.display()),
        format!("--prior-pack={}", prior_path.display()),
    ]);
    assert_eq!(code, 0, "restated pack must verify: {stderr}");

    // And refuses without it — lineage cannot be checked that is not presented.
    let (code, _, stderr) = run(&[
        "verify".into(),
        format!("--pack={}", pack_path.display()),
        format!("--inputs={}", corrected_inputs.display()),
        format!("--config={}", config.display()),
    ]);
    assert_eq!(code, 1);
    assert!(stderr.contains("restatement"), "{stderr}");
}

#[test]
fn reason_requires_prior_pack() {
    let (_dir, inputs, config) = paths("reason-guard");
    let (code, _, stderr) = run(&[
        "compute".into(),
        format!("--inputs={}", inputs.display()),
        format!("--config={}", config.display()),
        "--reason=orphan reason".into(),
    ]);
    assert_eq!(code, 2, "usage error expected");
    assert!(stderr.contains("--prior-pack"), "{stderr}");
}
