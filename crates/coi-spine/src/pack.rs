//! Evidence-pack assembly for coi-spine: provenance hashing and the
//! canonical-byte helpers the CLI's compute/verify paths share.
//!
//! The pack is the canonical [`spine::EvidencePack`]; lifecycle (draft →
//! awaiting signoff → signed, sealing on Signed) is advanced through
//! `spine::advance_lock` by the product CLI. No filesystem, clock, or
//! network access happens in this module.

use chrono::NaiveDate;
use serde::Serialize;
use spine::{sha256_hex, EvidencePack, SPINE_VERSION};

use crate::cert::Certificate;
use crate::config::RequirementsConfig;
use crate::engine::{self, Evaluation};
use crate::error::CoiError;

/// Engine identity. Separation of duties: a signoff receipt whose actor
/// matches this id cannot countersign a coi-spine pack (enforced by spine).
pub const ENGINE_ID: &str = "coi-spine";

/// Canonical bytes for hashing: the validated document re-serialized with
/// serde_json (fixed struct field order, BTreeMap key order). Byte-
/// deterministic for identical parsed content regardless of input whitespace
/// or JSON key order.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CoiError> {
    serde_json::to_vec(value).map_err(|e| CoiError::Schema(format!("canonical serialization: {e}")))
}

/// Run the pure evaluation and assemble an unsealed evidence pack carrying
/// SHA-256 provenance for the canonical inputs and params. The pack verifies
/// only after the lock lifecycle signs it (which seals the body).
pub fn build_pack(
    cert: &Certificate,
    cfg: &RequirementsConfig,
    as_of: NaiveDate,
) -> Result<(EvidencePack, Evaluation), CoiError> {
    let evaluation = engine::evaluate(cert, cfg, as_of);
    let inputs = canonical_json(cert)?;
    let params = canonical_json(cfg)?;
    let pack = EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(&inputs),
        params_hash: sha256_hex(&params),
        findings: evaluation.findings.clone(),
        signoffs: Vec::new(),
        body_hash: String::new(),
    };
    Ok((pack, evaluation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CarrierRating, CategoryRequirement, Coverage, Endorsement};
    use spine::{
        advance_lock, first_unresolved_finding, LockError, LockState, Signoff, SignoffDecision,
        VerifyError,
    };
    use std::collections::BTreeMap;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    fn config(critical: bool) -> RequirementsConfig {
        RequirementsConfig {
            categories: BTreeMap::from([(
                "electrical_contractor".to_string(),
                CategoryRequirement {
                    critical,
                    coverages: BTreeMap::from([(
                        Coverage::GeneralLiability,
                        crate::config::CoverageRequirement {
                            per_occurrence_cents: 100_000_000,
                            aggregate_cents: 200_000_000,
                            endorsements: vec![Endorsement::AdditionalInsured],
                        },
                    )]),
                },
            )]),
            expiry_warning_days: 30,
            min_carrier_rating: CarrierRating::AMinus,
        }
    }

    fn line(expiration: NaiveDate) -> crate::cert::PolicyLine {
        crate::cert::PolicyLine {
            policy_number: "GL-1".to_string(),
            carrier_name: "Seed Mutual".to_string(),
            carrier_rating: CarrierRating::AMinus,
            coverage: Coverage::GeneralLiability,
            per_occurrence_limit_cents: 100_000_000,
            aggregate_limit_cents: 200_000_000,
            effective_date: date(2026, 1, 1),
            expiration_date: expiration,
            endorsements: vec![Endorsement::AdditionalInsured],
        }
    }

    fn cert(expiration: NaiveDate, vendor: &str) -> Certificate {
        Certificate {
            vendor_id: vendor.to_string(),
            vendor_category: "electrical_contractor".to_string(),
            policies: vec![line(expiration)],
        }
    }

    fn approve(actor: &str, subject: &str) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "risk_manager".to_string(),
            subject: subject.to_string(),
            decision: SignoffDecision::Approve,
            at: "2026-09-22T15:04:05Z".to_string(),
        }
    }

    #[test]
    fn clean_pack_signs_and_verifies_end_to_end() {
        let incoming = cert(date(2027, 6, 30), "V-1001");
        let cfg = config(true);
        let (mut pack, evaluation) = build_pack(&incoming, &cfg, date(2026, 9, 22)).unwrap();
        assert!(evaluation.findings.is_empty());

        let inputs = canonical_json(&incoming).unwrap();
        let params = canonical_json(&cfg).unwrap();

        // Fail-closed before sealing: an unsealed pack refuses even with the
        // original inputs presented.
        assert_eq!(
            pack.verify(&inputs, &params),
            Err(VerifyError::BodyHashMismatch)
        );

        let state = advance_lock(LockState::Draft, &mut pack).unwrap();
        assert_eq!(state, LockState::AwaitingSignoff);
        let state = advance_lock(state, &mut pack).unwrap();
        assert_eq!(state, LockState::Signed);
        assert!(!pack.body_hash.is_empty());
        assert_eq!(pack.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn breach_pack_blocks_signing_until_subject_scoped_signoff() {
        let incoming = cert(date(2026, 9, 21), "V-1001"); // expired the day before the clock
        let cfg = config(true);
        let as_of = date(2026, 9, 22);
        let (mut pack, evaluation) = build_pack(&incoming, &cfg, as_of).unwrap();
        assert!(!evaluation.findings.is_empty());

        let inputs = canonical_json(&incoming).unwrap();
        let params = canonical_json(&cfg).unwrap();

        // The seal is checked before signoff coverage (fail-closed order);
        // the breach gate itself is exercised via advance_lock below.
        assert_eq!(
            pack.verify(&inputs, &params),
            Err(VerifyError::BodyHashMismatch)
        );
        assert_eq!(
            advance_lock(LockState::AwaitingSignoff, &mut pack),
            Err(LockError::UnresolvedBreach {
                rule_id: crate::engine::RULE_COVERAGE_EXPIRED.to_string()
            })
        );

        // A receipt naming a different subject resolves nothing.
        pack.signoffs.push(approve("Reina Park", "V-9999"));
        assert!(first_unresolved_finding(&pack).is_some());

        // The subject-matched human approval resolves the breach.
        pack.signoffs.push(approve("Reina Park", "V-1001"));
        let state = advance_lock(LockState::Draft, &mut pack).unwrap();
        assert_eq!(advance_lock(state, &mut pack), Ok(LockState::Signed));
        assert_eq!(pack.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn engine_cannot_countersign_own_pack() {
        let incoming = cert(date(2026, 9, 21), "V-1001");
        let cfg = config(true);
        let (mut pack, _) = build_pack(&incoming, &cfg, date(2026, 9, 22)).unwrap();
        let inputs = canonical_json(&incoming).unwrap();
        let params = canonical_json(&cfg).unwrap();

        // The producing engine's receipt is void — case-insensitively.
        pack.signoffs.push(approve(ENGINE_ID, "V-1001"));
        pack.signoffs.push(approve("COI-Spine", "V-1001"));
        assert!(first_unresolved_finding(&pack).is_some());

        // A distinct human receipt resolves.
        pack.signoffs.push(approve("Reina Park", "V-1001"));
        let state = advance_lock(LockState::Draft, &mut pack).unwrap();
        advance_lock(state, &mut pack).unwrap();
        assert_eq!(pack.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn tampered_pack_fails_verify() {
        let incoming = cert(date(2026, 9, 21), "V-1001");
        let cfg = config(true);
        let (mut pack, _) = build_pack(&incoming, &cfg, date(2026, 9, 22)).unwrap();
        pack.signoffs.push(approve("Reina Park", "V-1001"));
        let state = advance_lock(LockState::Draft, &mut pack).unwrap();
        advance_lock(state, &mut pack).unwrap();
        let inputs = canonical_json(&incoming).unwrap();
        let params = canonical_json(&cfg).unwrap();
        assert_eq!(pack.verify(&inputs, &params), Ok(()));

        // Message edit after sealing → seal refusal even with original inputs.
        pack.findings[0].message = "altered".to_string();
        assert_eq!(
            pack.verify(&inputs, &params),
            Err(VerifyError::BodyHashMismatch)
        );

        // Different inputs than the pack was computed on → provenance refusal.
        let other = cert(date(2026, 9, 21), "V-2002");
        let other_inputs = canonical_json(&other).unwrap();
        let intact = build_pack(&incoming, &cfg, date(2026, 9, 22)).unwrap().0;
        let intact = {
            let mut p = intact;
            p.signoffs.push(approve("Reina Park", "V-1001"));
            let state = advance_lock(LockState::Draft, &mut p).unwrap();
            advance_lock(state, &mut p).unwrap();
            p
        };
        assert_eq!(
            intact.verify(&other_inputs, &params),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
    }

    #[test]
    fn warn_only_pack_needs_no_receipts() {
        // Expiring within the window (warn, not breach): the pack signs with
        // zero receipts — warnings are advisory.
        let cert = cert(date(2026, 10, 10), "V-1001");
        let cfg = config(true);
        let (mut pack, evaluation) = build_pack(&cert, &cfg, date(2026, 9, 22)).unwrap();
        assert!(!evaluation.findings.is_empty());
        assert!(evaluation.findings.iter().all(|f| !f.requires_signoff));

        let inputs = canonical_json(&cert).unwrap();
        let params = canonical_json(&cfg).unwrap();
        let state = advance_lock(LockState::Draft, &mut pack).unwrap();
        advance_lock(state, &mut pack).unwrap();
        assert_eq!(pack.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn provenance_hashes_are_stable_across_whitespace_and_key_order() {
        let cert_a = cert(date(2027, 6, 30), "V-1001");
        let json_a = serde_json::to_string_pretty(&cert_a).unwrap();
        let cert_b: Certificate = serde_json::from_str(&json_a).expect("same content reparses");
        let cfg_a = config(true);
        let cfg_b: RequirementsConfig =
            serde_json::from_str(&serde_json::to_string(&cfg_a).unwrap()).unwrap();

        let (pack_a, _) = build_pack(&cert_a, &cfg_a, date(2026, 9, 22)).unwrap();
        let (pack_b, _) = build_pack(&cert_b, &cfg_b, date(2026, 9, 22)).unwrap();
        assert_eq!(pack_a.inputs_hash, pack_b.inputs_hash);
        assert_eq!(pack_a.params_hash, pack_b.params_hash);
        // spine::Finding does not implement PartialEq; serialized equality is
        // exact for evidence purposes.
        assert_eq!(
            serde_json::to_string(&pack_a.findings).unwrap(),
            serde_json::to_string(&pack_b.findings).unwrap()
        );
    }
}
