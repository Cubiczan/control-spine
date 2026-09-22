//! End-to-end CLI tests against the compiled binary: compute, verify, and
//! explain, including the fail-closed refusals (tampered pack, tampered
//! inputs, schema violations).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CLEAN_INPUTS: &str = r#"{
  "campaign_id": "2026-Q3",
  "campaign_date": "2026-09-22",
  "identities": [
    {"employee_id": "E-MGR", "email": "mgr@corp.example", "display_name": "Manager", "manager_id": null, "hire_date": "2019-05-01", "separation_date": null},
    {"employee_id": "E-1", "email": "one@corp.example", "display_name": "One", "manager_id": "E-MGR", "hire_date": "2020-01-01", "separation_date": null}
  ],
  "systems": [{"system_id": "github", "display_name": "GitHub Enterprise"}],
  "entitlements": [
    {"entitlement_id": "ENT-1", "system_id": "github", "employee_id": "E-1", "email": "one@corp.example", "entitlement_key": "repo:acme/api", "privileged": false, "granted_at": "2025-01-01", "last_authenticated_at": "2026-09-01"}
  ]
}"#;

const LEAVER_INPUTS: &str = r#"{
  "campaign_id": "2026-Q3",
  "campaign_date": "2026-09-22",
  "identities": [
    {"employee_id": "E-MGR", "email": "mgr@corp.example", "display_name": "Manager", "manager_id": null, "hire_date": "2019-05-01", "separation_date": null},
    {"employee_id": "E-1", "email": "one@corp.example", "display_name": "One", "manager_id": "E-MGR", "hire_date": "2020-01-01", "separation_date": "2026-03-01"}
  ],
  "systems": [{"system_id": "github", "display_name": "GitHub Enterprise"}],
  "entitlements": [
    {"entitlement_id": "ENT-1", "system_id": "github", "employee_id": "E-1", "email": "one@corp.example", "entitlement_key": "repo:acme/api", "privileged": false, "granted_at": "2025-01-01", "last_authenticated_at": "2026-09-01"}
  ]
}"#;

const MIXED_INPUTS: &str = r#"{
  "campaign_id": "2026-Q3",
  "campaign_date": "2026-09-22",
  "identities": [
    {"employee_id": "E-MGR", "email": "mgr@corp.example", "display_name": "Manager", "manager_id": null, "hire_date": "2019-05-01", "separation_date": null},
    {"employee_id": "E-1", "email": "one@corp.example", "display_name": "One", "manager_id": "E-MGR", "hire_date": "2020-01-01", "separation_date": "2026-03-01"}
  ],
  "systems": [{"system_id": "github", "display_name": "GitHub Enterprise"}],
  "entitlements": [
    {"entitlement_id": "ENT-L", "system_id": "github", "employee_id": "E-1", "email": "one@corp.example", "entitlement_key": "repo:acme/api", "privileged": false, "granted_at": "2025-01-01", "last_authenticated_at": "2026-09-01"},
    {"entitlement_id": "ENT-Q", "system_id": "github", "employee_id": "E-404", "email": "ghost@corp.example", "entitlement_key": "repo:acme/ghost", "privileged": false, "granted_at": "2025-02-01", "last_authenticated_at": "2026-09-01"}
  ]
}"#;

const CONFIG: &str = r#"{"stale_days": 90, "new_hire_grace_days": 30}"#;

const SIGNOFFS: &str = r#"[
  {"actor": "sam", "role": "manager", "subject": "ENT-1", "decision": "approve", "at": "2026-09-21T00:00:00Z"}
]"#;

struct Workspace {
    dir: PathBuf,
}

impl Workspace {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ars-cli-{}-{tag}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test workspace");
        Self { dir }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_access-recert-spine"))
        .args(args)
        .output()
        .expect("run binary");
    // A signal-killed process has no code; -1 keeps the integer asserts honest.
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8(output.stdout).expect("utf-8 stdout"),
        String::from_utf8(output.stderr).expect("utf-8 stderr"),
    )
}

#[test]
fn compute_verify_explain_happy_path() {
    let ws = Workspace::new("happy");
    let inputs = ws.write("inputs.json", CLEAN_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let pack = ws.dir.join("pack.json");

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "compute failed: {stderr}");

    let doc: serde_json::Value = serde_json::from_slice(&fs::read(&pack).unwrap()).unwrap();
    assert_eq!(doc["lock_state"], "signed");
    assert_eq!(doc["pack"]["spine_version"], "1.0.0");
    assert_eq!(doc["pack"]["findings"].as_array().unwrap().len(), 0);

    let (code, stdout, stderr) = run(&[
        "verify",
        "--pack",
        pack.to_str().unwrap(),
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "verify failed: {stderr}");
    assert!(stdout.contains("OK"), "{stdout}");

    let (code, stdout, stderr) = run(&["explain", "--pack", pack.to_str().unwrap()]);
    assert_eq!(code, 0, "explain failed: {stderr}");
    assert!(stdout.contains("REVOCATION QUEUE"), "{stdout}");
    assert!(stdout.contains("(none)"), "{stdout}");
    assert!(stdout.contains("RULE CATALOG"), "{stdout}");
}

#[test]
fn leaver_breach_parks_pack_and_verify_fails() {
    let ws = Workspace::new("breach");
    let inputs = ws.write("inputs.json", LEAVER_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let pack = ws.dir.join("pack.json");

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "compute itself succeeds: {stderr}");

    let doc: serde_json::Value = serde_json::from_slice(&fs::read(&pack).unwrap()).unwrap();
    assert_eq!(doc["lock_state"], "awaiting_signoff");
    assert_eq!(doc["pack"]["findings"].as_array().unwrap().len(), 1);

    let (code, _, stderr) = run(&[
        "verify",
        "--pack",
        pack.to_str().unwrap(),
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "unsigned pack must not verify");
    assert!(stderr.contains("not Signed"), "{stderr}");
}

#[test]
fn signoff_receipts_drive_pack_to_signed_and_verify_passes() {
    let ws = Workspace::new("signed");
    let inputs = ws.write("inputs.json", LEAVER_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let signoffs = ws.write("signoffs.json", SIGNOFFS);
    let pack = ws.dir.join("pack.json");

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--signoffs",
        signoffs.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "compute failed: {stderr}");

    let doc: serde_json::Value = serde_json::from_slice(&fs::read(&pack).unwrap()).unwrap();
    assert_eq!(doc["lock_state"], "signed");

    let (code, stdout, stderr) = run(&[
        "verify",
        "--pack",
        pack.to_str().unwrap(),
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "verify failed: {stderr}");
    assert!(stdout.contains("OK"), "{stdout}");
}

#[test]
fn verify_refuses_tampered_pack_file() {
    let ws = Workspace::new("tamper-pack");
    let inputs = ws.write("inputs.json", LEAVER_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let signoffs = ws.write("signoffs.json", SIGNOFFS);
    let pack = ws.dir.join("pack.json");

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--signoffs",
        signoffs.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "compute failed: {stderr}");

    // Tamper with the pack body: rewrite the separation date inside the
    // recorded finding message. The seal must catch it.
    let pack_text = fs::read_to_string(&pack).unwrap();
    assert!(pack_text.contains("separated on 2026-03-01"));
    let tampered = pack_text.replace("separated on 2026-03-01", "separated on 2026-03-02");
    fs::write(&pack, tampered).unwrap();

    let (code, _, stderr) = run(&[
        "verify",
        "--pack",
        pack.to_str().unwrap(),
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "tampered pack must not verify");
    assert!(stderr.contains("body hash"), "{stderr}");
}

#[test]
fn verify_refuses_tampered_inputs_file() {
    let ws = Workspace::new("tamper-inputs");
    let inputs = ws.write("inputs.json", CLEAN_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let pack = ws.dir.join("pack.json");

    let (code, _, _) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);

    // Even whitespace changes the canonical input bytes and must refuse.
    let mut tampered = fs::read_to_string(&inputs).unwrap();
    tampered.push(' ');
    fs::write(&inputs, tampered).unwrap();

    let (code, _, stderr) = run(&[
        "verify",
        "--pack",
        pack.to_str().unwrap(),
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "tampered inputs must not verify");
    assert!(stderr.contains("inputs"), "{stderr}");
}

#[test]
fn compute_rejects_unknown_config_field() {
    let ws = Workspace::new("bad-config");
    let inputs = ws.write("inputs.json", CLEAN_INPUTS);
    let config = ws.write(
        "config.json",
        r#"{"stale_days": 90, "new_hire_grace_days": 30, "surprise": true}"#,
    );

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "schema drift must exit 2");
    assert!(stderr.contains("unknown field"), "{stderr}");
}

#[test]
fn compute_rejects_duplicate_employee_id() {
    let ws = Workspace::new("dup-identity");
    let inputs = ws.write(
        "inputs.json",
        r#"{
          "campaign_id": "2026-Q3",
          "campaign_date": "2026-09-22",
          "identities": [
            {"employee_id": "E-MGR", "email": "mgr@corp.example", "display_name": "Manager", "manager_id": null, "hire_date": "2019-05-01", "separation_date": null},
            {"employee_id": "E-1", "email": "a@corp.example", "display_name": "A", "manager_id": "E-MGR", "hire_date": "2020-01-01", "separation_date": null},
            {"employee_id": "E-1", "email": "b@corp.example", "display_name": "B", "manager_id": "E-MGR", "hire_date": "2021-01-01", "separation_date": null}
          ],
          "systems": [{"system_id": "github", "display_name": "GitHub Enterprise"}],
          "entitlements": []
        }"#,
    );
    let config = ws.write("config.json", CONFIG);

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "ambiguous identity keys must exit 2");
    assert!(
        stderr.contains("duplicate identity employee_id"),
        "{stderr}"
    );
}

#[test]
fn explain_lists_revocation_and_quarantine_queues() {
    let ws = Workspace::new("explain");
    let inputs = ws.write("inputs.json", MIXED_INPUTS);
    let config = ws.write("config.json", CONFIG);
    let pack = ws.dir.join("pack.json");

    let (code, _, stderr) = run(&[
        "compute",
        "--inputs",
        inputs.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--out",
        pack.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "compute failed: {stderr}");

    let (code, stdout, stderr) = run(&["explain", "--pack", pack.to_str().unwrap()]);
    assert_eq!(code, 0, "explain failed: {stderr}");
    assert!(stdout.contains("REVOCATION QUEUE"), "{stdout}");
    assert!(stdout.contains("leaver-active-entitlement"), "{stdout}");
    assert!(stdout.contains("QUARANTINE QUEUE"), "{stdout}");
    assert!(stdout.contains("ENT-Q"), "{stdout}");
    assert!(stdout.contains("awaiting_signoff"), "{stdout}");
}
