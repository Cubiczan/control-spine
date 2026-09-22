//! End-to-end governance tests: the full commission lifecycle through the
//! public API — compute, sign, seal, verify — plus determinism and the
//! fail-closed paths the spec calls out. These run against the library the
//! same way an external consumer would.

use chrono::NaiveDate;
use commission_spine::config::{Band, BandMode, PlanConfig, PlanVersion, RoleWeight};
use commission_spine::evidence::{
    advance_lock, append_signoff, compute_document, verify_document, EvidenceDocument,
    SignoffError, VerifyFailure,
};
use commission_spine::input::{Credit, Transaction, TransactionsFile, TxnKind};
use spine::{LockState, SignoffDecision, VerifyError};

fn date(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("valid date")
}

fn plan_bytes() -> Vec<u8> {
    let plan = PlanConfig {
        plan_id: "fy26-americas".to_string(),
        versions: vec![PlanVersion {
            version: 1,
            effective_from: date("2026-01-01"),
            effective_to: None,
            quota_cents: 10_000_000,
            band_mode: BandMode::Marginal,
            bands: vec![
                Band {
                    up_to_ppm: Some(1_000_000),
                    rate_bps: 200,
                },
                Band {
                    up_to_ppm: None,
                    rate_bps: 500,
                },
            ],
            windfall_cap_ppm: None,
            max_spread_bps: None,
            role_weights: vec![
                RoleWeight {
                    role: "ae".to_string(),
                    weight_bps: 7_000,
                },
                RoleWeight {
                    role: "se".to_string(),
                    weight_bps: 3_000,
                },
            ],
        }],
    };
    serde_json::to_vec_pretty(&plan).expect("plan serializes")
}

fn sale(id: &str, day: &str, amount: i128, original: Option<&str>) -> Transaction {
    Transaction {
        transaction_id: id.to_string(),
        date: date(day),
        amount_cents: amount,
        kind: if original.is_some() {
            TxnKind::Return
        } else {
            TxnKind::Sale
        },
        original_transaction_id: original.map(|s| s.to_string()),
        credits: if original.is_some() {
            Vec::new()
        } else {
            vec![
                Credit {
                    rep_id: "rep-1".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                },
                Credit {
                    rep_id: "rep-2".to_string(),
                    role: "se".to_string(),
                    priority: 1,
                },
            ]
        },
    }
}

fn txn_bytes(variant: &str) -> Vec<u8> {
    let file = match variant {
        "clean" => TransactionsFile {
            transactions: vec![sale("T1", "2026-02-10", 5_000_000, None)],
        },
        "clawback" => TransactionsFile {
            transactions: vec![
                sale("T1", "2026-02-10", 5_000_000, None),
                sale("T2", "2026-03-05", 1_000_000, Some("T1")),
            ],
        },
        other => panic!("unknown variant {other}"),
    };
    serde_json::to_vec_pretty(&file).expect("transactions serialize")
}

fn approve(actor: &str, subject: &str) -> spine::Signoff {
    spine::Signoff {
        actor: actor.to_string(),
        role: "controller".to_string(),
        subject: subject.to_string(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T12:00:00Z".to_string(),
    }
}

#[test]
fn clean_lifecycle_round_trips_to_a_signed_verifying_pack() {
    let plan = plan_bytes();
    let txns = txn_bytes("clean");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    assert_eq!(doc.lock_state, LockState::Draft);
    // Draft packs verify (no breaches) but are not yet evidence — the lock
    // has not reached Signed.
    assert_eq!(verify_document(&doc, &plan, &txns), Ok(()));
    assert_eq!(advance_lock(&mut doc), Ok(LockState::AwaitingSignoff));
    assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
    assert_eq!(doc.pack.verify(&txns, &plan), Ok(()));
    assert_eq!(doc.pack.spine_version, "1.0.0");
    assert_eq!(doc.pack.engine_id, "commission-spine");
}

#[test]
fn clawback_pack_refuses_verify_until_the_subject_is_approved_and_sealed() {
    let plan = plan_bytes();
    let txns = txn_bytes("clawback");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    // Deep verify reproduces the pack but the spine gate refuses: the
    // CLAWBACK breach has no approving signoff.
    assert!(matches!(
        verify_document(&doc, &plan, &txns),
        Err(VerifyFailure::Refused(VerifyError::UnresolvedBreach { .. }))
    ));
    append_signoff(&mut doc, approve("sam", "txn:T2")).expect("subject matches");
    // The first signature submits the pack and the finding is resolved, so
    // the seal proceeds and the pack verifies.
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
    assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
    assert_eq!(verify_document(&doc, &plan, &txns), Ok(()));
}

#[test]
fn each_breach_subject_needs_its_own_approval() {
    let plan = plan_bytes();
    // Two independent returned transactions → two CLAWBACK breaches with
    // different subjects.
    let file = TransactionsFile {
        transactions: vec![
            sale("T1", "2026-02-10", 5_000_000, None),
            sale("T2", "2026-03-05", 1_000_000, Some("T1")),
            sale("T3", "2026-03-06", 2_000_000, Some("T1")),
        ],
    };
    let txns = serde_json::to_vec_pretty(&file).expect("serializes");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    append_signoff(&mut doc, approve("sam", "txn:T2")).expect("subject matches");
    // One subject approved; the other still blocks the seal.
    assert!(matches!(
        advance_lock(&mut doc),
        Err(spine::LockError::UnresolvedBreach { .. })
    ));
    append_signoff(&mut doc, approve("quinn", "txn:T3")).expect("subject matches");
    assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
    assert_eq!(doc.pack.verify(&txns, &plan), Ok(()));
}

#[test]
fn compute_is_bit_for_bit_reproducible_regardless_of_input_order() {
    let plan = plan_bytes();
    let file_a = TransactionsFile {
        transactions: vec![
            sale("T1", "2026-02-10", 5_000_000, None),
            sale("T2", "2026-03-05", 1_000_000, Some("T1")),
        ],
    };
    let file_b = TransactionsFile {
        transactions: vec![
            sale("T2", "2026-03-05", 1_000_000, Some("T1")),
            sale("T1", "2026-02-10", 5_000_000, None),
        ],
    };
    let a_bytes = serde_json::to_vec_pretty(&file_a).expect("serializes");
    // Same bytes → same provenance hashes and same seal, bit-for-bit.
    let doc_a = compute_document(&plan, &a_bytes, "commission-spine").expect("computes");
    let doc_a2 = compute_document(&plan, &a_bytes, "commission-spine").expect("computes");
    assert_eq!(doc_a.pack.inputs_hash, doc_a2.pack.inputs_hash);
    assert_eq!(doc_a.pack.body_hash, doc_a2.pack.body_hash);

    // Engine-level order independence: same findings and credit lines in
    // canonical order.
    let plan_cfg: PlanConfig = serde_json::from_slice(&plan).expect("plan");
    let out_a = commission_spine::engine::run(&plan_cfg, &file_a).expect("runs");
    let out_b = commission_spine::engine::run(&plan_cfg, &file_b).expect("runs");
    assert_eq!(out_a.credit_lines, out_b.credit_lines);
    assert_eq!(out_a.rep_summaries, out_b.rep_summaries);
    assert_eq!(out_a.findings.len(), out_b.findings.len());
}

#[test]
fn signoff_subject_must_name_a_finding() {
    let plan = plan_bytes();
    let txns = txn_bytes("clawback");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    assert_eq!(
        append_signoff(&mut doc, approve("sam", "txn:NONEXISTENT")),
        Err(SignoffError::UnknownSubject("txn:NONEXISTENT".to_string()))
    );
    // A typo must not silently resolve anything: the pack still refuses.
    assert!(matches!(
        doc.pack.verify(&txns, &plan),
        Err(VerifyError::UnresolvedBreach { .. })
    ));
}

#[test]
fn the_engine_may_not_approve_its_own_pack() {
    let plan = plan_bytes();
    let txns = txn_bytes("clawback");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    append_signoff(&mut doc, approve("commission-spine", "txn:T2")).expect("subject matches");
    // Separation of duties: the spine voids the engine's own approval.
    assert!(matches!(
        doc.pack.verify(&txns, &plan),
        Err(VerifyError::UnresolvedBreach { .. })
    ));
}

#[test]
fn four_eyes_requires_two_distinct_signers() {
    // Family-contract anchor: privileged actions take two distinct human
    // signers; no commission rule designates a four-eyes action in this
    // wave, but the helper must behave fail-closed if one ever does.
    let one = vec![approve("sam", "x")];
    let two = vec![approve("sam", "x"), approve("Sam", "x")]; // same signer, cased
    let real_two = vec![approve("sam", "x"), approve("quinn", "x")];
    assert!(!spine::four_eyes_satisfied(&one));
    assert!(!spine::four_eyes_satisfied(&two));
    assert!(spine::four_eyes_satisfied(&real_two));
}

#[test]
fn tampered_documents_refuse_at_every_lid() {
    let plan = plan_bytes();
    let txns = txn_bytes("clawback");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    append_signoff(&mut doc, approve("sam", "txn:T2")).expect("signs");
    // The first signature submits the pack; one seal step completes it.
    assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
    assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));

    // 1. Tampered signoff record → seal broken.
    let mut tampered_actor = doc.clone();
    tampered_actor.pack.signoffs[0].actor = "attacker".to_string();
    assert_eq!(
        tampered_actor.pack.verify(&txns, &plan),
        Err(VerifyError::BodyHashMismatch)
    );

    // 2. Tampered finding (dropped breach) → seal broken AND deep check.
    // The deep recompute runs before the spine gate, so the full-flow
    // refusal is FindingsDiverged; the direct pack.verify above already
    // pins the BodyHashMismatch lid for the same tamper.
    let mut dropped = doc.clone();
    dropped.pack.findings.retain(|f| f.rule_id != "CLAWBACK");
    assert_eq!(
        dropped.pack.verify(&txns, &plan),
        Err(VerifyError::BodyHashMismatch)
    );
    assert!(matches!(
        verify_document(&dropped, &plan, &txns),
        Err(VerifyFailure::FindingsDiverged)
    ));

    // 3. Swapped inputs (plan bytes presented as transactions) → hash
    // mismatch.
    assert_eq!(
        doc.pack.verify(&plan, &txns),
        Err(VerifyError::HashMismatch { field: "inputs" })
    );

    // 4. Different engine id in the presented pack: body hash mismatch too.
    let mut engine_swap = doc.clone();
    engine_swap.pack.engine_id = "someone-else".to_string();
    assert_eq!(
        engine_swap.pack.verify(&txns, &plan),
        Err(VerifyError::BodyHashMismatch)
    );
}

#[test]
fn lock_cannot_advance_past_signed() {
    let plan = plan_bytes();
    let txns = txn_bytes("clean");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    assert_eq!(advance_lock(&mut doc), Ok(LockState::AwaitingSignoff));
    assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
    assert_eq!(
        advance_lock(&mut doc),
        Err(spine::LockError::InvalidTransition(LockState::Signed))
    );
}

#[test]
fn evidence_documents_round_trip_through_serde() {
    let plan = plan_bytes();
    let txns = txn_bytes("clawback");
    let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
    append_signoff(&mut doc, approve("sam", "txn:T2")).expect("signs");
    let bytes = serde_json::to_vec_pretty(&doc).expect("serializes");
    let round: EvidenceDocument = serde_json::from_slice(&bytes).expect("parses");
    assert_eq!(round.lock_state, doc.lock_state);
    assert_eq!(round.pack.inputs_hash, doc.pack.inputs_hash);
    assert_eq!(round.pack.body_hash, doc.pack.body_hash);
}
