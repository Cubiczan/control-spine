//! Evidence-pack assembly and the product-level seal gate. The pack shape,
//! hash contract, lock lifecycle, and fail-closed verification are the
//! canonical `spine` crate's — this module only builds packs, records
//! receipts, and applies the family's four-eyes rule where this product's
//! privileged action lives (accepting a covenant breach).

use serde::{Deserialize, Serialize};
use spine::{
    advance_lock, first_unresolved_finding, four_eyes_satisfied, sha256_hex, EvidencePack,
    LockError, LockState, Severity, Signoff, SPINE_VERSION,
};

use crate::engine::Evaluation;
use crate::ENGINE_ID;

/// Compute output file: the spine evidence pack plus the product lock state
/// the CLI advances through `draft` -> `awaiting_signoff` -> `signed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackEnvelope {
    pub lock_state: LockState,
    pub pack: EvidencePack,
}

/// Build an unsealed pack for an evaluation. `params_bytes` are the
/// canonical config bytes, `inputs_bytes` the canonical financials bytes —
/// both hashed for provenance.
pub fn build_pack(
    params_bytes: &[u8],
    inputs_bytes: &[u8],
    evaluation: &Evaluation,
) -> EvidencePack {
    EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(inputs_bytes),
        params_hash: sha256_hex(params_bytes),
        findings: evaluation.findings.clone(),
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
}

/// Build the compute output envelope: a fresh pack advanced into
/// `awaiting_signoff` — a computed pack is immediately submitted for human
/// review.
pub fn compute_envelope(
    params_bytes: &[u8],
    inputs_bytes: &[u8],
    evaluation: &Evaluation,
) -> PackEnvelope {
    let mut pack = build_pack(params_bytes, inputs_bytes, evaluation);
    match advance_lock(LockState::Draft, &mut pack) {
        Ok(LockState::AwaitingSignoff) => {}
        _ => unreachable!("draft -> awaiting_signoff is the only arm of this transition"),
    }
    PackEnvelope {
        lock_state: LockState::AwaitingSignoff,
        pack,
    }
}

/// Why a pack is still `awaiting_signoff` after a seal attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwaitingReason {
    UnresolvedFinding { rule_id: String },
    FourEyesRequired,
}

impl core::fmt::Display for AwaitingReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnresolvedFinding { rule_id } => write!(
                f,
                "finding on rule {rule_id} needs an approving receipt naming its subject"
            ),
            Self::FourEyesRequired => write!(
                f,
                "breach acceptance is a privileged action: approvals from two distinct signers are required (four-eyes)"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealOutcome {
    Signed,
    Awaiting(AwaitingReason),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("pack is already signed; signed packs are immutable")]
    AlreadySigned,
    #[error("lock error: {0}")]
    Lock(#[from] LockError),
}

/// Try to seal a pack after a receipt was added. Spine enforces per-subject
/// approval coverage; this gate adds the family's four-eyes rule for the
/// privileged action this product has — accepting a covenant breach —
/// counting only valid human receipts (the engine's own receipts are void
/// per spine's separation-of-duties rule, so they must not count as
/// signers). Clean packs seal without receipts, per spine semantics.
pub fn attempt_seal(envelope: &mut PackEnvelope) -> Result<SealOutcome, SealError> {
    match envelope.lock_state {
        LockState::Signed => return Err(SealError::AlreadySigned),
        LockState::Draft => {
            envelope.lock_state = advance_lock(LockState::Draft, &mut envelope.pack)?;
        }
        LockState::AwaitingSignoff => {}
    }
    if let Some(finding) = first_unresolved_finding(&envelope.pack) {
        return Ok(SealOutcome::Awaiting(AwaitingReason::UnresolvedFinding {
            rule_id: finding.rule_id.clone(),
        }));
    }
    let has_breach = envelope
        .pack
        .findings
        .iter()
        .any(|f| f.severity == Severity::Breach);
    if has_breach {
        let human_receipts: Vec<Signoff> = envelope
            .pack
            .signoffs
            .iter()
            .filter(|s| !s.actor.trim().eq_ignore_ascii_case(ENGINE_ID))
            .cloned()
            .collect();
        if !four_eyes_satisfied(&human_receipts) {
            return Ok(SealOutcome::Awaiting(AwaitingReason::FourEyesRequired));
        }
    }
    envelope.lock_state = advance_lock(LockState::AwaitingSignoff, &mut envelope.pack)?;
    Ok(SealOutcome::Signed)
}

/// Canonical JSON bytes for hashing: parsed and re-serialized with sorted
/// keys and no insignificant whitespace, so cosmetic reformatting never
/// breaks verification while any value change does.
pub fn canonical_json(bytes: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    serde_json::to_vec(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spine::{Finding, SignoffDecision, VerifyError};

    const INPUTS: &[u8] = b"covenant-inputs-bytes";
    const PARAMS: &[u8] = b"covenant-params-bytes";

    fn clean_eval() -> Evaluation {
        Evaluation::default()
    }

    fn breach_eval(subjects: &[&str]) -> Evaluation {
        Evaluation {
            findings: subjects
                .iter()
                .map(|s| Finding::breach("covenant-test", *s, "breach"))
                .collect(),
            results: Vec::new(),
        }
    }

    fn envelope(ev: &Evaluation) -> PackEnvelope {
        compute_envelope(PARAMS, INPUTS, ev)
    }

    fn signoff(actor: &str, subject: &str, decision: SignoffDecision) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "treasury controller".to_string(),
            subject: subject.to_string(),
            decision,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn compute_envelope_carries_provenance_and_awaiting_signoff() {
        let env = envelope(&clean_eval());
        assert_eq!(env.lock_state, LockState::AwaitingSignoff);
        assert_eq!(env.pack.engine_id, ENGINE_ID);
        assert_eq!(env.pack.spine_version, SPINE_VERSION);
        assert!(!env.pack.tool_version.is_empty());
        assert_eq!(env.pack.inputs_hash, sha256_hex(INPUTS));
        assert_eq!(env.pack.params_hash, sha256_hex(PARAMS));
        assert!(env.pack.signoffs.is_empty());
        // Unsealed until Signed — verify refuses unsealed packs.
        assert!(env.pack.body_hash.is_empty());
    }

    #[test]
    fn unsealed_pack_refuses_verification() {
        let env = envelope(&clean_eval());
        assert_eq!(
            env.pack.verify(INPUTS, PARAMS),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn clean_pack_signs_without_receipts_and_verifies() {
        let mut env = envelope(&clean_eval());
        assert_eq!(attempt_seal(&mut env), Ok(SealOutcome::Signed));
        assert_eq!(env.lock_state, LockState::Signed);
        assert!(!env.pack.body_hash.is_empty());
        assert_eq!(env.pack.verify(INPUTS, PARAMS), Ok(()));
        // Sealing twice is refused — signed packs are immutable.
        assert_eq!(attempt_seal(&mut env), Err(SealError::AlreadySigned));
    }

    #[test]
    fn attempt_seal_promotes_a_draft_envelope() {
        let mut env = PackEnvelope {
            lock_state: LockState::Draft,
            pack: build_pack(PARAMS, INPUTS, &clean_eval()),
        };
        assert_eq!(attempt_seal(&mut env), Ok(SealOutcome::Signed));
        assert_eq!(env.pack.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn breach_pack_needs_per_subject_coverage_then_four_eyes() {
        let mut env = envelope(&breach_eval(&["LEV", "IC"]));
        // First receipt resolves only its own subject.
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Approve));
        assert_eq!(
            attempt_seal(&mut env),
            Ok(SealOutcome::Awaiting(AwaitingReason::UnresolvedFinding {
                rule_id: "covenant-test".to_string()
            }))
        );
        // All subjects covered, but one signer only: four-eyes holds the seal.
        env.pack
            .signoffs
            .push(signoff("sam", "IC", SignoffDecision::Approve));
        assert_eq!(
            attempt_seal(&mut env),
            Ok(SealOutcome::Awaiting(AwaitingReason::FourEyesRequired))
        );
        // Second distinct signer: seal and verify.
        env.pack
            .signoffs
            .push(signoff("quinn", "IC", SignoffDecision::Approve));
        assert_eq!(attempt_seal(&mut env), Ok(SealOutcome::Signed));
        assert_eq!(env.pack.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn duplicate_signer_never_satisfies_four_eyes() {
        let mut env = envelope(&breach_eval(&["LEV"]));
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Approve));
        env.pack
            .signoffs
            .push(signoff("Sam", "LEV", SignoffDecision::Approve)); // case-merge: one signer
        assert_eq!(
            attempt_seal(&mut env),
            Ok(SealOutcome::Awaiting(AwaitingReason::FourEyesRequired))
        );
    }

    #[test]
    fn reject_decision_does_not_resolve_a_breach() {
        let mut env = envelope(&breach_eval(&["LEV"]));
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Reject));
        assert_eq!(
            attempt_seal(&mut env),
            Ok(SealOutcome::Awaiting(AwaitingReason::UnresolvedFinding {
                rule_id: "covenant-test".to_string()
            }))
        );
    }

    #[test]
    fn tampered_inputs_or_params_refuse_verification() {
        let mut env = envelope(&clean_eval());
        attempt_seal(&mut env).unwrap();
        assert_eq!(
            env.pack.verify(b"tampered-inputs", PARAMS),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
        assert_eq!(
            env.pack.verify(INPUTS, b"tampered-params"),
            Err(VerifyError::HashMismatch { field: "params" })
        );
    }

    #[test]
    fn tampered_pack_body_breaks_the_seal() {
        let mut env = envelope(&breach_eval(&["LEV"]));
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Approve));
        env.pack
            .signoffs
            .push(signoff("quinn", "LEV", SignoffDecision::Approve));
        assert_eq!(attempt_seal(&mut env), Ok(SealOutcome::Signed));
        env.pack.findings[0].message = "edited after the fact".to_string();
        assert_eq!(
            env.pack.verify(INPUTS, PARAMS),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn engine_cannot_count_as_a_four_eyes_signer() {
        // The engine's own receipt is void (spine refuses engine
        // countersigns), and the four-eyes gate must not count it as a
        // signer either.
        let mut env = envelope(&breach_eval(&["LEV"]));
        env.pack
            .signoffs
            .push(signoff(ENGINE_ID, "LEV", SignoffDecision::Approve));
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Approve));
        assert_eq!(
            attempt_seal(&mut env),
            Ok(SealOutcome::Awaiting(AwaitingReason::FourEyesRequired))
        );
        env.pack
            .signoffs
            .push(signoff("quinn", "LEV", SignoffDecision::Approve));
        assert_eq!(attempt_seal(&mut env), Ok(SealOutcome::Signed));
        assert_eq!(env.pack.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn canonical_json_is_key_sorted_and_whitespace_insensitive() {
        let a = canonical_json(br#"{"b": 1, "a": 2}"#).unwrap();
        let b = canonical_json(br#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(a, b);
        let c = canonical_json(br#"{"a":2,"b":3}"#).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn envelope_json_roundtrip_preserves_verify() {
        let mut env = envelope(&breach_eval(&["LEV"]));
        env.pack
            .signoffs
            .push(signoff("sam", "LEV", SignoffDecision::Approve));
        env.pack
            .signoffs
            .push(signoff("quinn", "LEV", SignoffDecision::Approve));
        attempt_seal(&mut env).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let back: PackEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.lock_state, LockState::Signed);
        assert_eq!(back.pack.verify(INPUTS, PARAMS), Ok(()));
    }
}
