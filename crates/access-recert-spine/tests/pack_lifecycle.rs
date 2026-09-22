//! Pack assembly, lock progression, and fail-closed verification tests.
//!
//! The fail-closed path is the contract: a tampered evidence pack must
//! fail `verify` — body tampering, input tampering, and even a re-sealed
//! downgrade that defeats the body hash alone.

mod common;

use spine::{
    sha256_hex, EvidencePack, LockState, Severity, SignoffDecision, VerifyError, SPINE_VERSION,
};

use access_recert_spine::engine::RULE_PRIVILEGED_FOUR_EYES;
use access_recert_spine::model::{CampaignInput, RecertConfig};
use access_recert_spine::pack::{build_pack, verify_pack, PackDocument, PackVerificationError};

use common::{approval, campaign, config, d, entitlement, identity, ENGINE};

const INPUT_BYTES: &[u8] = b"campaign-inputs-bytes";
const PARAM_BYTES: &[u8] = b"campaign-params-bytes";

fn clean_campaign() -> (CampaignInput, RecertConfig) {
    (
        campaign(
            vec![identity("E-MGR"), identity("E-1")],
            vec![entitlement("ENT-1")],
        ),
        config(),
    )
}

fn leaver_campaign() -> (CampaignInput, RecertConfig) {
    let mut leaver = identity("E-1");
    leaver.separation_date = Some(d("2026-03-01"));
    (
        campaign(vec![identity("E-MGR"), leaver], vec![entitlement("ENT-1")]),
        config(),
    )
}

fn leaver_signoff(subject: &str) -> spine::Signoff {
    approval("sam", subject, SignoffDecision::Approve)
}

// ---- Lock lifecycle -------------------------------------------------------

#[test]
fn clean_campaign_reaches_signed_and_seals() {
    let (input, cfg) = clean_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(doc.lock_state, LockState::Signed);
    assert!(!doc.pack.body_hash.is_empty());
    assert_eq!(doc.pack.inputs_hash, sha256_hex(INPUT_BYTES));
    assert_eq!(doc.pack.params_hash, sha256_hex(PARAM_BYTES));
    assert_eq!(
        verify_pack(&doc, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Ok(())
    );
}

#[test]
fn breach_without_signoff_parks_at_awaiting_signoff_and_is_not_evidence() {
    let (input, cfg) = leaver_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
    // Only Signed packs are evidence — verification refuses.
    assert_eq!(
        verify_pack(&doc, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Err(PackVerificationError::NotSigned)
    );
}

#[test]
fn subject_scoped_signoffs_drive_pack_to_signed() {
    let mut first_leaver = identity("E-1");
    first_leaver.separation_date = Some(d("2026-03-01"));
    let mut second_leaver = identity("E-2");
    second_leaver.separation_date = Some(d("2026-03-01"));
    let mut second = entitlement("ENT-B");
    second.employee_id = "E-2".to_string();
    let input = campaign(
        vec![identity("E-MGR"), first_leaver, second_leaver],
        vec![entitlement("ENT-1"), second],
    );
    let cfg = config();

    // One of two subjects signed: pack stays parked.
    let partially = vec![leaver_signoff("ENT-B")];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, partially).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);

    // Both subjects signed: pack seals at Signed and verifies.
    let fully = vec![leaver_signoff("ENT-B"), leaver_signoff("ENT-1")];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, fully).unwrap();
    assert_eq!(doc.lock_state, LockState::Signed);
    assert_eq!(
        verify_pack(&doc, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Ok(())
    );
}

#[test]
fn signoff_for_other_subject_does_not_resolve_breach() {
    let (input, cfg) = leaver_campaign();
    let signoffs = vec![leaver_signoff("ENT-OTHER")];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, signoffs).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
}

#[test]
fn engine_actor_signoff_does_not_resolve_breach() {
    // Separation of duties: the producing engine cannot countersign its
    // own pack, so a receipt from the engine's own identity leaves the
    // breach unresolved.
    let (input, cfg) = leaver_campaign();
    let signoffs = vec![leaver_signoff_of_engine("ENT-1")];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, signoffs).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
}

fn leaver_signoff_of_engine(subject: &str) -> spine::Signoff {
    approval(ENGINE, subject, SignoffDecision::Approve)
}

// ---- Fail-closed verification ----------------------------------------------

#[test]
fn tampered_pack_body_fails_verify() {
    let (input, cfg) = leaver_campaign();
    let doc = build_pack(
        &input,
        &cfg,
        INPUT_BYTES,
        PARAM_BYTES,
        vec![leaver_signoff("ENT-1")],
    )
    .unwrap();
    assert_eq!(doc.lock_state, LockState::Signed);

    let mut tampered = doc.clone();
    tampered.pack.findings[0].message = "tampered message".to_string();
    assert_eq!(
        verify_pack(&tampered, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Err(PackVerificationError::Spine(VerifyError::BodyHashMismatch))
    );
}

#[test]
fn tampered_inputs_fail_verify() {
    let (input, cfg) = clean_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(
        verify_pack(&doc, &input, &cfg, b"tampered-inputs", PARAM_BYTES),
        Err(PackVerificationError::Spine(VerifyError::HashMismatch {
            field: "inputs"
        }))
    );
}

#[test]
fn tampered_params_fail_verify() {
    let (input, cfg) = clean_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(
        verify_pack(&doc, &input, &cfg, INPUT_BYTES, b"tampered-params"),
        Err(PackVerificationError::Spine(VerifyError::HashMismatch {
            field: "params"
        }))
    );
}

#[test]
fn resealed_downgrade_still_refuses_via_recomputation() {
    // An attacker who edits findings AND recomputes the body hash defeats
    // the seal alone — the recompute gate is what refuses them: the pack's
    // findings must reproduce from the inputs.
    let (input, cfg) = leaver_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);

    let mut forged_pack = doc.pack.clone();
    assert_eq!(forged_pack.findings.len(), 1);
    forged_pack.findings[0].severity = Severity::Warn;
    forged_pack.findings[0].requires_signoff = false;
    let forged = PackDocument {
        lock_state: LockState::Signed,
        pack: forged_pack.sealed(),
    };
    assert_eq!(
        verify_pack(&forged, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Err(PackVerificationError::RecomputationMismatch)
    );
}

#[test]
fn foreign_spine_version_refuses() {
    // A pack produced under a different spine version is not evidence,
    // even when its hashes and seal are internally consistent.
    let pack = EvidencePack {
        engine_id: ENGINE.to_string(),
        tool_version: "access-recert-spine v0.1.0".to_string(),
        spine_version: "9.9.9".to_string(),
        inputs_hash: sha256_hex(INPUT_BYTES),
        params_hash: sha256_hex(PARAM_BYTES),
        findings: vec![],
        signoffs: vec![],
        body_hash: String::new(),
    }
    .sealed();
    assert_eq!(
        pack.verify(INPUT_BYTES, PARAM_BYTES),
        Err(VerifyError::ForeignVersion)
    );
    assert_eq!(pack.spine_version, "9.9.9");
    assert_ne!(pack.spine_version, SPINE_VERSION);
}

#[test]
fn unresolved_breach_packs_do_not_seal_at_signed() {
    // The lock lifecycle refuses to sign a pack whose gated findings are
    // unresolved — the pack cannot reach the sealed evidence state.
    let (input, cfg) = leaver_campaign();
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, vec![]).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
    assert_eq!(doc.pack.body_hash, String::new());
}

// ---- Four-eyes lock gate ---------------------------------------------------

/// A privileged entitlement retained without pre-compute approvals fires the
/// `privileged-four-eyes` gated warn. Its subject needs two distinct
/// post-compute approvers before the pack may seal.
fn four_eyes_campaign() -> (CampaignInput, RecertConfig) {
    let mut priv_ent = entitlement("ENT-P");
    priv_ent.privileged = true;
    (
        campaign(vec![identity("E-MGR"), identity("E-1")], vec![priv_ent]),
        config(),
    )
}

#[test]
fn one_post_compute_signoff_cannot_resolve_four_eyes_gap() {
    // A single human attestation does not satisfy a four-eyes control: the
    // pack parks at awaiting_signoff instead of sealing as evidence.
    let (input, cfg) = four_eyes_campaign();
    let doc = build_pack(
        &input,
        &cfg,
        INPUT_BYTES,
        PARAM_BYTES,
        vec![leaver_signoff("ENT-P")],
    )
    .unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
}

#[test]
fn two_distinct_approvers_seal_four_eyes_pack() {
    let (input, cfg) = four_eyes_campaign();
    let signoffs = vec![
        approval("sam", "ENT-P", SignoffDecision::Approve),
        approval("dana", "ENT-P", SignoffDecision::Approve),
    ];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, signoffs).unwrap();
    assert_eq!(doc.lock_state, LockState::Signed);
    assert_eq!(
        verify_pack(&doc, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Ok(())
    );
}

#[test]
fn four_eyes_distinctness_ignores_case_variants() {
    // The spine's distinctness is trimmed and case-insensitive — fail-closed:
    // `sam` and `Sam` count as one signer, never two.
    let (input, cfg) = four_eyes_campaign();
    let signoffs = vec![
        approval("sam", "ENT-P", SignoffDecision::Approve),
        approval("Sam", "ENT-P", SignoffDecision::Approve),
    ];
    let doc = build_pack(&input, &cfg, INPUT_BYTES, PARAM_BYTES, signoffs).unwrap();
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
}

#[test]
fn sealed_pack_with_undercounted_four_eyes_signers_refuses_verify() {
    // The attack the strict gate exists for: seal a pack carrying only one
    // approver on a four-eyes subject and claim Signed. The spine floor
    // accepts it (a warn is not a breach); the product's lock gate must
    // still refuse.
    let (input, cfg) = four_eyes_campaign();
    let parked = build_pack(
        &input,
        &cfg,
        INPUT_BYTES,
        PARAM_BYTES,
        vec![leaver_signoff("ENT-P")],
    )
    .unwrap();
    let forged = PackDocument {
        lock_state: LockState::Signed,
        pack: parked.pack.sealed(),
    };
    assert_eq!(
        verify_pack(&forged, &input, &cfg, INPUT_BYTES, PARAM_BYTES),
        Err(PackVerificationError::UnresolvedGate {
            rule_id: RULE_PRIVILEGED_FOUR_EYES.to_string()
        })
    );
}
