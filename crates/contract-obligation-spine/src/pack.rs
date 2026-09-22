//! Evidence-pack assembly and verification for this product.
//!
//! Provenance hashes are computed over canonical re-serializations of the
//! parsed inputs and params (fixed field order, unknown fields already
//! refused at load), so whitespace-only refactors of a JSON file do not
//! change identity — content changes always do.
//!
//! Governance layering, per the family contract:
//! * `spine::EvidencePack::verify` — fail-closed provenance, seal, version,
//!   and subject-scoped signoff resolution.
//! * `verify_pack` adds the register's one privileged action: a register
//!   correction is a four-eyes action (two distinct approving signers per
//!   corrected obligation).

use spine::{sha256_hex, EvidencePack, LockState, Signoff, SignoffDecision, VerifyError};

use crate::model::{PolicyParams, RegisterInputs};

/// Identity of this engine in every pack it produces. Separation of duties:
/// an approval whose actor matches this id is void.
pub const ENGINE_ID: &str = "contract-obligation-spine";

/// Canonical bytes for the inputs (register) side of the provenance hashes.
pub fn canonical_inputs_bytes(inputs: &RegisterInputs) -> Vec<u8> {
    serde_json::to_vec(inputs)
        .expect("RegisterInputs is a fixed-shape struct; serialization cannot fail")
}

/// Canonical bytes for the params (policy config) side of the provenance hashes.
pub fn canonical_params_bytes(params: &PolicyParams) -> Vec<u8> {
    serde_json::to_vec(params)
        .expect("PolicyParams is a fixed-shape struct; serialization cannot fail")
}

/// Build an unsealed pack from an evaluation. The caller supplies signoffs
/// (possibly empty); the lock lifecycle and sealing happen in
/// [`finalize_lock`].
pub fn build_pack(
    findings: Vec<spine::Finding>,
    inputs: &RegisterInputs,
    params: &PolicyParams,
    signoffs: Vec<Signoff>,
) -> EvidencePack {
    EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(&canonical_inputs_bytes(inputs)),
        params_hash: sha256_hex(&canonical_params_bytes(params)),
        findings,
        signoffs,
        body_hash: String::new(),
    }
}

/// Advance the pack through the lock lifecycle: `draft` →
/// `awaiting_signoff` always; → `signed` only when no finding is unresolved.
/// A pack that stops at `awaiting_signoff` is still sealed for tamper
/// evidence; resolving it means re-computing with signoffs and producing a
/// new pack (a sealed pack's body is immutable).
pub fn finalize_lock(mut pack: EvidencePack) -> (EvidencePack, LockState) {
    let state = spine::advance_lock(LockState::Draft, &mut pack).expect("draft always advances");
    if state == LockState::AwaitingSignoff && spine::first_unresolved_finding(&pack).is_none() {
        let signed = spine::advance_lock(state, &mut pack).expect("clean pack signs");
        return (pack, signed);
    }
    (pack.sealed(), state)
}

/// Register correction: the spine's one privileged action. Corrected
/// obligation ids, sorted and unique.
pub fn corrected_obligation_ids(inputs: &RegisterInputs) -> Vec<String> {
    let mut ids: Vec<String> = inputs
        .obligations
        .iter()
        .filter(|r| r.supersedes.is_some())
        .map(|r| r.id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Why a pack refuses to verify, beyond the spine's own reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyFailure {
    #[error("{0}")]
    Spine(#[from] VerifyError),
    #[error(
        "four-eyes not satisfied for corrected obligation {obligation_id}: two distinct approving signers required"
    )]
    FourEyes { obligation_id: String },
}

/// Fail-closed verification of a pack against register and params: the
/// spine's checks (version, seal, provenance hashes, subject-scoped signoff
/// resolution) plus four-eyes on every corrected obligation. Engine-identity
/// approvals are void here too — an engine cannot countersign its own pack.
pub fn verify_pack(
    pack: &EvidencePack,
    inputs: &RegisterInputs,
    params: &PolicyParams,
) -> Result<(), VerifyFailure> {
    pack.verify(
        &canonical_inputs_bytes(inputs),
        &canonical_params_bytes(params),
    )?;
    for id in corrected_obligation_ids(inputs) {
        let approvals: Vec<Signoff> = pack
            .signoffs
            .iter()
            .filter(|s| s.decision == SignoffDecision::Approve && s.subject == id)
            .filter(|s| !s.actor.trim().eq_ignore_ascii_case(ENGINE_ID))
            .cloned()
            .collect();
        if !spine::four_eyes_satisfied(&approvals) {
            return Err(VerifyFailure::FourEyes { obligation_id: id });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::evaluate;
    use crate::model::{
        DateSpec, ObligationRecord, ObligationType, PolicyParams, RegisterInputs, RollMode, SlaTier,
    };
    use chrono::NaiveDate;
    use spine::{Finding, Severity};
    use std::collections::BTreeMap;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid test date")
    }

    fn clock() -> NaiveDate {
        d(2026, 9, 22)
    }

    fn params() -> PolicyParams {
        PolicyParams {
            warn_days_before_due: 10,
            warn_days_before_optout: 14,
            business_day_roll: RollMode::None,
            calendars: BTreeMap::new(),
            sla_credit_tiers: vec![SlaTier {
                min_uptime_bp: 9900,
                credit_bp: 100,
            }],
        }
    }

    fn payment(due: NaiveDate) -> ObligationRecord {
        ObligationRecord {
            id: "O-PAY".to_string(),
            version: 1,
            supersedes: None,
            counterparty: "Acme Corp".to_string(),
            obligation_type: ObligationType::Payment,
            jurisdiction: None,
            due: Some(DateSpec::Explicit { date: due }),
            amount_cents: Some(1_000_000),
            satisfied_on: None,
            completed_on: None,
            renewal: None,
            sla: None,
            sla_measurements: vec![],
        }
    }

    fn inputs(records: Vec<ObligationRecord>) -> RegisterInputs {
        RegisterInputs {
            obligations: records,
        }
    }

    fn signoff(actor: &str, subject: &str) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "controller".to_string(),
            subject: subject.to_string(),
            decision: SignoffDecision::Approve,
            at: "2026-09-22T12:00:00Z".to_string(),
        }
    }

    /// Overdue payment at the clock: exactly one breach finding.
    fn breached_pack() -> EvidencePack {
        let reg = inputs(vec![payment(d(2026, 9, 21))]);
        let ev = evaluate(&reg, &params(), clock()).expect("valid register");
        build_pack(ev.findings, &reg, &params(), vec![])
    }

    /// Clean register: due far in the future, zero findings.
    fn clean_pack() -> EvidencePack {
        let reg = inputs(vec![payment(d(2026, 12, 1))]);
        let ev = evaluate(&reg, &params(), clock()).expect("valid register");
        assert!(ev.findings.is_empty());
        build_pack(ev.findings, &reg, &params(), vec![])
    }

    #[test]
    fn clean_pack_signs_and_verifies() {
        let (pack, state) = finalize_lock(clean_pack());
        assert_eq!(state, LockState::Signed);
        assert!(verify_pack(&pack, &inputs(vec![payment(d(2026, 12, 1))]), &params()).is_ok());
    }

    #[test]
    fn breach_pack_awaits_signoff_and_verify_refuses() {
        let (pack, state) = finalize_lock(breached_pack());
        assert_eq!(state, LockState::AwaitingSignoff);
        let err = verify_pack(&pack, &inputs(vec![payment(d(2026, 9, 21))]), &params())
            .expect_err("unresolved breach must refuse");
        assert!(matches!(
            err,
            VerifyFailure::Spine(VerifyError::UnresolvedBreach { .. })
        ));
    }

    #[test]
    fn breach_resolves_only_with_a_signoff_on_the_finding_subject() {
        // Signoff naming the breach subject: the pack signs and verifies.
        let reg = inputs(vec![payment(d(2026, 9, 21))]);
        let ev = evaluate(&reg, &params(), clock()).expect("valid register");
        let (pack, state) = finalize_lock(build_pack(
            ev.findings,
            &reg,
            &params(),
            vec![signoff("sam", "O-PAY")],
        ));
        assert_eq!(state, LockState::Signed);
        assert!(verify_pack(&pack, &reg, &params()).is_ok());

        // The same signoff on the wrong subject leaves the breach unresolved.
        let reg2 = inputs(vec![payment(d(2026, 9, 21))]);
        let ev2 = evaluate(&reg2, &params(), clock()).expect("valid register");
        let (pack_wrong, state_wrong) = finalize_lock(build_pack(
            ev2.findings,
            &reg2,
            &params(),
            vec![signoff("sam", "O-OTHER")],
        ));
        assert_eq!(state_wrong, LockState::AwaitingSignoff);
        let err = verify_pack(&pack_wrong, &reg2, &params())
            .expect_err("signoff on the wrong subject must not resolve the breach");
        assert!(matches!(
            err,
            VerifyFailure::Spine(VerifyError::UnresolvedBreach { .. })
        ));
    }

    #[test]
    fn the_engine_cannot_countersign_its_own_pack() {
        let reg = inputs(vec![payment(d(2026, 9, 21))]);
        let ev = evaluate(&reg, &params(), clock()).expect("valid register");
        let pack = build_pack(
            ev.findings,
            &reg,
            &params(),
            vec![signoff(ENGINE_ID, "O-PAY")],
        );
        let (pack, state) = finalize_lock(pack);
        // The engine-identity approval is void: the pack cannot reach Signed.
        assert_eq!(state, LockState::AwaitingSignoff);
        assert!(verify_pack(&pack, &reg, &params()).is_err());
    }

    #[test]
    fn tampered_inputs_refuse_verification() {
        let (pack, _) = finalize_lock(clean_pack());
        let modified = inputs(vec![payment(d(2026, 12, 15))]); // different due
        let err = verify_pack(&pack, &modified, &params()).expect_err("must refuse");
        assert!(matches!(
            err,
            VerifyFailure::Spine(VerifyError::HashMismatch { field: "inputs" })
        ));
    }

    #[test]
    fn tampered_params_refuse_verification() {
        let (pack, _) = finalize_lock(clean_pack());
        let mut modified = params();
        modified.warn_days_before_due = 30;
        let err = verify_pack(&pack, &inputs(vec![payment(d(2026, 12, 1))]), &modified)
            .expect_err("must refuse");
        assert!(matches!(
            err,
            VerifyFailure::Spine(VerifyError::HashMismatch { field: "params" })
        ));
    }

    #[test]
    fn tampered_findings_refuse_verification_via_the_body_seal() {
        let (mut pack, _) = finalize_lock(clean_pack());
        pack.findings.push(Finding {
            rule_id: "smuggled".to_string(),
            severity: Severity::Warn,
            subject: "O-PAY".to_string(),
            message: "smuggled finding".to_string(),
            requires_signoff: false,
        });
        let err = verify_pack(&pack, &inputs(vec![payment(d(2026, 12, 1))]), &params())
            .expect_err("body tampering must refuse");
        assert!(matches!(
            err,
            VerifyFailure::Spine(VerifyError::BodyHashMismatch)
        ));
    }

    #[test]
    fn a_corrected_register_requires_four_eyes_signoff() {
        // A register whose O-PAY record corrects version 1: one approval is
        // not enough to verify a pack over it.
        let mut v2 = payment(d(2026, 12, 1));
        v2.version = 2;
        v2.supersedes = Some(1);
        let reg = inputs(vec![payment(d(2026, 12, 1)), v2]);
        let ev = evaluate(&reg, &params(), clock()).expect("valid register");
        let (pack, state) = finalize_lock(build_pack(
            ev.findings,
            &reg,
            &params(),
            vec![signoff("sam", "O-PAY")],
        ));
        assert_eq!(state, LockState::Signed);
        let err = verify_pack(&pack, &reg, &params()).expect_err("one approval is not four-eyes");
        assert!(
            matches!(err, VerifyFailure::FourEyes { obligation_id } if obligation_id == "O-PAY")
        );

        // Two distinct approving signers satisfy four-eyes.
        let reg2 = inputs(vec![payment(d(2026, 12, 1)), {
            let mut v = payment(d(2026, 12, 1));
            v.version = 2;
            v.supersedes = Some(1);
            v
        }]);
        let ev2 = evaluate(&reg2, &params(), clock()).expect("valid register");
        let (pack2, _) = finalize_lock(build_pack(
            ev2.findings,
            &reg2,
            &params(),
            vec![signoff("sam", "O-PAY"), signoff("maya", "O-PAY")],
        ));
        assert!(verify_pack(&pack2, &reg2, &params()).is_ok());
    }

    #[test]
    fn canonical_bytes_are_identical_for_equal_registers() {
        // Two registers built fresh (not cloned) with equal content hash to
        // the same bytes; a content change changes the hash.
        let a = canonical_inputs_bytes(&inputs(vec![payment(d(2026, 12, 1))]));
        let b = canonical_inputs_bytes(&inputs(vec![payment(d(2026, 12, 1))]));
        assert_eq!(a, b);
        let c = canonical_inputs_bytes(&inputs(vec![payment(d(2026, 12, 2))]));
        assert_ne!(a, c);
    }
}
