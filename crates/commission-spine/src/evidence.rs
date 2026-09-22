//! Evidence assembly and fail-closed verification for the commission spine.
//!
//! `compute` produces an [`EvidenceDocument`]: the spine [`EvidencePack`]
//! (provenance hashes over the exact input bytes, findings, seal) plus the
//! product-side lock state. Human signoffs are appended through the CLI
//! `sign` command; `seal` advances the lock — `draft` → `awaiting_signoff`
//! → `signed`, sealing the pack at `Signed` (signed packs are immutable;
//! corrections are new packs, never edits). `verify` recomputes the engine
//! from the presented bytes, requires the re-run to reproduce the pack's
//! findings, then hands the pack to [`EvidencePack::verify`], which refuses
//! on any version, seal, hash, or unresolved-breach doubt.

use spine::{EvidencePack, Finding, LockError, LockState, SPINE_VERSION};

use crate::config::{ConfigError, PlanConfig};
use crate::engine::{self, EngineError};
use crate::input::{InputError, TransactionsFile};

/// Version of this product crate, recorded in every pack.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The on-disk evidence document: spine pack plus product lock state.
///
/// `EvidencePack` is a foreign spine type without `PartialEq`, so the
/// document derives only serde traits — compare via the pack's hashes and
/// lock state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceDocument {
    pub lock_state: LockState,
    pub pack: EvidencePack,
}

/// `compute` refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComputeError {
    #[error("engine id must be non-empty")]
    EmptyEngineId,
    #[error("plan config invalid: {0}")]
    PlanConfig(#[from] ConfigError),
    #[error("transactions input invalid: {0}")]
    Transactions(#[from] InputError),
    #[error("plan config JSON: {0}")]
    PlanJson(String),
    #[error("transactions JSON: {0}")]
    TransactionsJson(String),
    #[error("engine: {0}")]
    Engine(#[from] EngineError),
}

/// `verify` refusals. The deep check runs first: a pack whose own engine
/// cannot reproduce its findings from the presented bytes is refused before
/// the spine gate runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyFailure {
    #[error("recomputed findings diverge from the pack (nondeterminism or tampering)")]
    FindingsDiverged,
    #[error("spine verification refused: {0}")]
    Refused(#[from] spine::VerifyError),
    #[error("recompute during verify: {0}")]
    Recompute(#[from] ComputeError),
}

/// Parse, validate, and run the engine over the canonical bytes.
fn recompute(plan_bytes: &[u8], txn_bytes: &[u8]) -> Result<engine::EngineOutput, ComputeError> {
    let plan: PlanConfig =
        serde_json::from_slice(plan_bytes).map_err(|e| ComputeError::PlanJson(e.to_string()))?;
    plan.validate()?;
    let txns: TransactionsFile = serde_json::from_slice(txn_bytes)
        .map_err(|e| ComputeError::TransactionsJson(e.to_string()))?;
    txns.validate()?;
    engine::run(&plan, &txns).map_err(ComputeError::from)
}

/// Compute an evidence document from the exact plan and transaction bytes.
/// Provenance hashes are over those bytes — byte-exact, so verify is
/// reproducible bit-for-bit. The pack is sealed at production: any later
/// body change breaks the seal and verify refuses.
pub fn compute_document(
    plan_bytes: &[u8],
    txn_bytes: &[u8],
    engine_id: &str,
) -> Result<EvidenceDocument, ComputeError> {
    let engine_id = engine_id.trim();
    if engine_id.is_empty() {
        return Err(ComputeError::EmptyEngineId);
    }
    let out = recompute(plan_bytes, txn_bytes)?;
    let pack = EvidencePack {
        engine_id: engine_id.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        spine_version: SPINE_VERSION.to_string(),
        inputs_hash: spine::sha256_hex(txn_bytes),
        params_hash: spine::sha256_hex(plan_bytes),
        findings: out.findings,
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
    .sealed();
    Ok(EvidenceDocument {
        lock_state: LockState::Draft,
        pack,
    })
}

/// Fail-closed verification: deep-recompute the engine over the presented
/// bytes, require the findings to match the pack exactly, then run the
/// spine gate (versions, seal, provenance hashes, subject-scoped signoffs).
pub fn verify_document(
    doc: &EvidenceDocument,
    plan_bytes: &[u8],
    txn_bytes: &[u8],
) -> Result<(), VerifyFailure> {
    let out = recompute(plan_bytes, txn_bytes)?;
    if !findings_equal(&out.findings, &doc.pack.findings) {
        return Err(VerifyFailure::FindingsDiverged);
    }
    doc.pack
        .verify(txn_bytes, plan_bytes)
        .map_err(VerifyFailure::from)
}

/// Append a human signoff receipt to a draft/awaiting document and re-seal.
/// Refuses on a `Signed` (immutable) document, an empty actor (anonymous
/// receipts are void), or a subject that names no finding in the pack —
/// a typo'd subject would silently resolve nothing.
pub fn append_signoff(
    doc: &mut EvidenceDocument,
    signoff: spine::Signoff,
) -> Result<(), SignoffError> {
    if doc.lock_state == LockState::Signed {
        return Err(SignoffError::SignedIsImmutable);
    }
    if signoff.actor.trim().is_empty() {
        return Err(SignoffError::EmptyActor);
    }
    if signoff.role.trim().is_empty() {
        return Err(SignoffError::EmptyRole);
    }
    let subject = signoff.subject.clone();
    let known = doc.pack.findings.iter().any(|f| f.subject == subject);
    if !known {
        return Err(SignoffError::UnknownSubject(subject));
    }
    doc.pack.signoffs.push(signoff);
    if doc.lock_state == LockState::Draft {
        // A first signature submits the pack for review.
        doc.lock_state = LockState::AwaitingSignoff;
    }
    doc.pack = doc.pack.clone().sealed();
    Ok(())
}

/// Advance the lock one step (`draft` → `awaiting_signoff` → `signed`).
/// Signing an awaiting pack seals it; unresolved findings block the step.
pub fn advance_lock(doc: &mut EvidenceDocument) -> Result<LockState, LockError> {
    let current = doc.lock_state;
    let next = spine::advance_lock(current, &mut doc.pack)?;
    doc.lock_state = next;
    Ok(next)
}

/// `sign`/`seal` refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignoffError {
    #[error("signed packs are immutable; a correction is a new pack, never an edit")]
    SignedIsImmutable,
    #[error("signoff actor must be non-empty (anonymous receipts are void)")]
    EmptyActor,
    #[error("signoff role must be non-empty")]
    EmptyRole,
    #[error("signoff subject {0:?} names no finding in this pack")]
    UnknownSubject(String),
    #[error("lock: {0}")]
    Lock(#[from] LockError),
}

/// Field-wise findings equality (Findings do not derive PartialEq).
fn findings_equal(a: &[Finding], b: &[Finding]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(x, y)| {
            x.rule_id == y.rule_id
                && x.severity == y.severity
                && x.subject == y.subject
                && x.message == y.message
                && x.requires_signoff == y.requires_signoff
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Band, BandMode, PlanConfig, PlanVersion, RoleWeight};
    use crate::input::{Credit, Transaction, TxnKind};
    use chrono::NaiveDate;
    use spine::{SignoffDecision, VerifyError};

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("valid date")
    }

    fn plan_bytes() -> Vec<u8> {
        let plan = PlanConfig {
            plan_id: "fy26".to_string(),
            versions: vec![PlanVersion {
                version: 1,
                effective_from: date("2026-01-01"),
                effective_to: None,
                quota_cents: 1_000_000,
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
                role_weights: vec![RoleWeight {
                    role: "ae".to_string(),
                    weight_bps: 10_000,
                }],
            }],
        };
        serde_json::to_vec_pretty(&plan).expect("plan serializes")
    }

    fn txn_bytes() -> Vec<u8> {
        let file = TransactionsFile {
            transactions: vec![Transaction {
                transaction_id: "T1".to_string(),
                date: date("2026-02-01"),
                amount_cents: 1_000_000,
                kind: TxnKind::Sale,
                original_transaction_id: None,
                credits: vec![Credit {
                    rep_id: "rep-1".to_string(),
                    role: "ae".to_string(),
                    priority: 1,
                }],
            }],
        };
        serde_json::to_vec_pretty(&file).expect("transactions serialize")
    }

    fn clawback_bytes() -> Vec<u8> {
        let file = TransactionsFile {
            transactions: vec![
                Transaction {
                    transaction_id: "T1".to_string(),
                    date: date("2026-02-01"),
                    amount_cents: 2_000_000,
                    kind: TxnKind::Sale,
                    original_transaction_id: None,
                    credits: vec![Credit {
                        rep_id: "rep-1".to_string(),
                        role: "ae".to_string(),
                        priority: 1,
                    }],
                },
                Transaction {
                    transaction_id: "T2".to_string(),
                    date: date("2026-03-01"),
                    amount_cents: 500_000,
                    kind: TxnKind::Return,
                    original_transaction_id: Some("T1".to_string()),
                    credits: Vec::new(),
                },
            ],
        };
        serde_json::to_vec_pretty(&file).expect("transactions serialize")
    }

    fn signoff(actor: &str, subject: &str) -> spine::Signoff {
        spine::Signoff {
            actor: actor.to_string(),
            role: "controller".to_string(),
            subject: subject.to_string(),
            decision: SignoffDecision::Approve,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn clean_compute_seals_and_verifies() {
        let doc =
            compute_document(&plan_bytes(), &txn_bytes(), "commission-spine").expect("computes");
        assert_eq!(doc.lock_state, LockState::Draft);
        assert_eq!(doc.pack.verify(&txn_bytes(), &plan_bytes()), Ok(()));
    }

    #[test]
    fn empty_engine_id_is_refused() {
        assert!(matches!(
            compute_document(&plan_bytes(), &txn_bytes(), "  "),
            Err(ComputeError::EmptyEngineId)
        ));
    }

    #[test]
    fn tampered_findings_break_the_seal() {
        let mut doc = compute_document(&plan_bytes(), &clawback_bytes(), "commission-spine")
            .expect("computes");
        doc.pack.findings[0].message = "tampered".to_string();
        assert_eq!(
            doc.pack.verify(&clawback_bytes(), &plan_bytes()),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn altered_inputs_are_refused() {
        let doc =
            compute_document(&plan_bytes(), &txn_bytes(), "commission-spine").expect("computes");
        assert_eq!(
            doc.pack.verify(b"tampered", &plan_bytes()),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
        assert_eq!(
            doc.pack.verify(&txn_bytes(), b"tampered"),
            Err(VerifyError::HashMismatch { field: "params" })
        );
    }

    #[test]
    fn verify_document_reproduces_and_accepts_a_clean_pack() {
        let plan = plan_bytes();
        let txns = txn_bytes();
        let doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
        assert_eq!(verify_document(&doc, &plan, &txns), Ok(()));
    }

    #[test]
    fn verify_document_refuses_diverging_inputs() {
        let doc =
            compute_document(&plan_bytes(), &txn_bytes(), "commission-spine").expect("computes");
        // Different transactions: the re-run diverges from the pack.
        let result = verify_document(&doc, &plan_bytes(), &clawback_bytes());
        assert!(matches!(result, Err(VerifyFailure::FindingsDiverged)));
    }

    #[test]
    fn breach_pack_refuses_until_the_named_subject_is_approved() {
        let plan = plan_bytes();
        let txns = clawback_bytes();
        let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
        assert_eq!(
            doc.pack.verify(&txns, &plan),
            Err(VerifyError::UnresolvedBreach {
                rule_id: "CLAWBACK".to_string()
            })
        );
        // Wrong subject resolves nothing.
        append_signoff(&mut doc, signoff("sam", "txn:OTHER")).expect_err("unknown subject");
        assert_eq!(
            doc.pack.verify(&txns, &plan),
            Err(VerifyError::UnresolvedBreach {
                rule_id: "CLAWBACK".to_string()
            })
        );
        // The right subject resolves the breach.
        append_signoff(&mut doc, signoff("sam", "txn:T2")).expect("subject matches");
        assert_eq!(doc.pack.verify(&txns, &plan), Ok(()));
    }

    #[test]
    fn engine_cannot_countersign_its_own_pack() {
        let plan = plan_bytes();
        let txns = clawback_bytes();
        let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
        append_signoff(&mut doc, signoff("commission-spine", "txn:T2")).expect("subject matches");
        assert!(doc.pack.verify(&txns, &plan).is_err());
    }

    #[test]
    fn signed_documents_are_immutable() {
        let plan = plan_bytes();
        let txns = clawback_bytes();
        let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
        append_signoff(&mut doc, signoff("sam", "txn:T2")).expect("signs");
        // The first signature submits the pack for review...
        assert_eq!(doc.lock_state, LockState::AwaitingSignoff);
        // ...and one seal step completes it (the finding is resolved).
        assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
        assert_eq!(doc.pack.verify(&txns, &plan), Ok(()));
        // Immutability: no further signoffs on a Signed document.
        assert_eq!(
            append_signoff(&mut doc, signoff("quinn", "txn:T2")),
            Err(SignoffError::SignedIsImmutable)
        );
        // Any body tampering breaks the seal.
        let mut tampered = doc.clone();
        tampered.pack.signoffs[0].actor = "someone-else".to_string();
        assert_eq!(
            tampered.pack.verify(&txns, &plan),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn lock_blocks_signing_while_a_breach_is_unresolved() {
        let plan = plan_bytes();
        let txns = clawback_bytes();
        let mut doc = compute_document(&plan, &txns, "commission-spine").expect("computes");
        assert_eq!(advance_lock(&mut doc), Ok(LockState::AwaitingSignoff));
        assert!(matches!(
            advance_lock(&mut doc),
            Err(LockError::UnresolvedBreach { .. })
        ));
        append_signoff(&mut doc, signoff("sam", "txn:T2")).expect("signs");
        assert_eq!(advance_lock(&mut doc), Ok(LockState::Signed));
    }
}
