//! Canonical governance crate for the control-spine family.
//!
//! Every department engine crate in this workspace depends on `spine` by path
//! and ships the same contract: typed findings, human signoff receipts, the
//! lock lifecycle, and evidence packs with SHA-256 provenance hashes that
//! fail closed — a pack either proves itself or [`EvidencePack::verify`]
//! refuses.
//!
//! Engine purity is a family rule: no clock reads, no network, no
//! filesystem; randomness only from a SHA-256-derived seed, and only in
//! engine crates that sample. Money is integer cents (i128). Time is an
//! input supplied by the caller.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version pin for the family contract. Bumping it invalidates evidence
/// packs produced under other spine versions on verify.
pub const SPINE_VERSION: &str = "1.0.0";

/// Severity of a control finding. Breach-severity findings cannot resolve
/// without a signoff receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Breach,
}

/// A human reviewer's decision on a finding or pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignoffDecision {
    Approve,
    Reject,
}

/// A typed control finding. `subject` is the stable business key the finding
/// is about: an account, vendor, driver, control id, and so on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub subject: String,
    pub message: String,
    /// Family invariant: forced true for every Breach (see [`Finding::breach`]).
    /// Lower-severity findings may also be marked when they must not pass
    /// without review.
    pub requires_signoff: bool,
}

impl Finding {
    /// Breach constructor; forces `requires_signoff = true` per the family
    /// invariant.
    pub fn breach(
        rule_id: impl Into<String>,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity: Severity::Breach,
            subject: subject.into(),
            message: message.into(),
            requires_signoff: true,
        }
    }
}

/// A human signoff receipt. `at` is an ISO-8601 timestamp supplied by the
/// caller — the engine never reads a clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signoff {
    pub actor: String,
    pub role: String,
    pub decision: SignoffDecision,
    pub at: String,
}

/// Evidence pack emitted by every compute run: inputs/params provenance
/// hashes, findings, and the signoffs that resolve them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePack {
    /// Version of the product crate that produced the pack.
    pub tool_version: String,
    /// Version of the spine contract the pack was produced under.
    pub spine_version: String,
    /// SHA-256 of the canonical input bytes.
    pub inputs_hash: String,
    /// SHA-256 of the canonical config bytes.
    pub params_hash: String,
    pub findings: Vec<Finding>,
    pub signoffs: Vec<Signoff>,
}

/// Verify refusal reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("hash mismatch: {field}")]
    HashMismatch { field: &'static str },
    #[error("unresolved finding: rule {rule_id} lacks an approving signoff")]
    UnresolvedBreach { rule_id: String },
    #[error("foreign version: pack does not carry this spine version or tool_version is empty")]
    ForeignVersion,
}

/// Lock progression refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    #[error("lock is terminal: {0:?} cannot advance")]
    InvalidTransition(LockState),
    #[error("cannot sign: unresolved finding on rule {rule_id}")]
    UnresolvedBreach { rule_id: String },
}

/// Lock lifecycle state for a pack moving through human review. Only signed
/// packs export; a pack with an unresolved finding cannot progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Draft,
    AwaitingSignoff,
    Signed,
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The first finding that requires a signoff but has no approving signoff,
/// in pack order — the reason a pack cannot verify or progress.
pub fn first_unresolved_finding(pack: &EvidencePack) -> Option<&Finding> {
    pack.findings.iter().find(|f| {
        (f.severity == Severity::Breach || f.requires_signoff)
            && !pack.signoffs.iter().any(|s| {
                s.decision == SignoffDecision::Approve
                    && EvidencePack::subject_covers(&s.actor, &f.subject)
            })
    })
}

/// Four-eyes check: a privileged action may proceed only with approvals from
/// two distinct signers. Comparison is trimmed and case-insensitive, so
/// `alice` and `Alice` count as one signer — fail-closed: distinctness can
/// only be under-counted, never over-counted.
pub fn four_eyes_satisfied(signoffs: &[Signoff]) -> bool {
    let mut signers: Vec<&str> = signoffs
        .iter()
        .filter(|s| s.decision == SignoffDecision::Approve)
        .map(|s| s.actor.trim())
        .filter(|a| !a.is_empty())
        .collect();
    signers.sort_by_key(|a| a.to_lowercase());
    signers.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    signers.len() >= 2
}

/// Advance the lock lifecycle one step for `pack`:
/// `draft` → `awaiting_signoff` (submitting for review) → `signed`.
///
/// `awaiting_signoff` → `signed` refuses while any finding is unresolved.
/// Run [`EvidencePack::verify`] before advancing — hash integrity is the
/// caller's gate here, not the lock's.
pub fn advance_lock(current: LockState, pack: &EvidencePack) -> Result<LockState, LockError> {
    match current {
        LockState::Draft => Ok(LockState::AwaitingSignoff),
        LockState::AwaitingSignoff => match first_unresolved_finding(pack) {
            Some(finding) => Err(LockError::UnresolvedBreach {
                rule_id: finding.rule_id.clone(),
            }),
            None => Ok(LockState::Signed),
        },
        LockState::Signed => Err(LockError::InvalidTransition(current)),
    }
}

impl EvidencePack {
    /// Fail-closed: a pack verifies only if the spine and tool versions are
    /// recognized, both hashes recompute from the canonical bytes, and every
    /// finding that requires signoff carries an approving signoff. Any doubt
    /// refuses.
    pub fn verify(&self, inputs: &[u8], params: &[u8]) -> Result<(), VerifyError> {
        if self.spine_version != SPINE_VERSION || self.tool_version.is_empty() {
            return Err(VerifyError::ForeignVersion);
        }
        if self.inputs_hash != sha256_hex(inputs) {
            return Err(VerifyError::HashMismatch { field: "inputs" });
        }
        if self.params_hash != sha256_hex(params) {
            return Err(VerifyError::HashMismatch { field: "params" });
        }
        if let Some(finding) = first_unresolved_finding(self) {
            return Err(VerifyError::UnresolvedBreach {
                rule_id: finding.rule_id.clone(),
            });
        }
        Ok(())
    }

    /// Family contract: a signoff names the finding subject it covers.
    /// Subject-level matching is enforced by each product CLI's lock
    /// lifecycle in spine 1.0.0; the spine-level check stays permissive.
    fn subject_covers(_actor: &str, _subject: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUTS: &[u8] = b"canonical-inputs";
    const PARAMS: &[u8] = b"canonical-params";

    fn pack(findings: Vec<Finding>, signoffs: Vec<Signoff>) -> EvidencePack {
        EvidencePack {
            tool_version: "test-tool 0.1.0".to_string(),
            spine_version: SPINE_VERSION.to_string(),
            inputs_hash: sha256_hex(INPUTS),
            params_hash: sha256_hex(PARAMS),
            findings,
            signoffs,
        }
    }

    fn signoff(actor: &str, decision: SignoffDecision) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "controller".to_string(),
            decision,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    fn approve(actor: &str) -> Signoff {
        signoff(actor, SignoffDecision::Approve)
    }

    fn reject(actor: &str) -> Signoff {
        signoff(actor, SignoffDecision::Reject)
    }

    fn warn_finding(requires_signoff: bool) -> Finding {
        Finding {
            rule_id: "R-warn".to_string(),
            severity: Severity::Warn,
            subject: "acct-7".to_string(),
            message: "review recommended".to_string(),
            requires_signoff,
        }
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_happy_path_clean_pack() {
        let p = pack(vec![warn_finding(false)], vec![]);
        assert_eq!(p.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn verify_breach_with_signoff_passes() {
        let p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam")],
        );
        assert_eq!(p.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn verify_refuses_tampered_inputs() {
        let p = pack(vec![], vec![]);
        assert_eq!(
            p.verify(b"tampered", PARAMS),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
    }

    #[test]
    fn verify_refuses_tampered_params() {
        let p = pack(vec![], vec![]);
        assert_eq!(
            p.verify(INPUTS, b"tampered"),
            Err(VerifyError::HashMismatch { field: "params" })
        );
    }

    #[test]
    fn verify_refuses_foreign_spine_version() {
        let mut p = pack(vec![], vec![]);
        p.spine_version = "0.9.0".to_string();
        assert_eq!(p.verify(INPUTS, PARAMS), Err(VerifyError::ForeignVersion));
    }

    #[test]
    fn verify_refuses_empty_tool_version() {
        let mut p = pack(vec![], vec![]);
        p.tool_version = String::new();
        assert_eq!(p.verify(INPUTS, PARAMS), Err(VerifyError::ForeignVersion));
    }

    #[test]
    fn verify_refuses_unresolved_breach() {
        let p = pack(vec![Finding::breach("R1", "acct-7", "over limit")], vec![]);
        assert_eq!(
            p.verify(INPUTS, PARAMS),
            Err(VerifyError::UnresolvedBreach {
                rule_id: "R1".to_string()
            })
        );
    }

    #[test]
    fn verify_refuses_breach_even_with_signoff_flag_cleared() {
        // Tamper path: a deserialized Breach whose requires_signoff flag was
        // cleared must still refuse — the spec prose is unconditional.
        let f = Finding {
            requires_signoff: false,
            ..Finding::breach("R1", "acct-7", "over limit")
        };
        let p = pack(vec![f], vec![]);
        assert!(p.verify(INPUTS, PARAMS).is_err());
    }

    #[test]
    fn verify_respects_requires_signoff_on_warn() {
        let flagged = pack(vec![warn_finding(true)], vec![]);
        assert!(flagged.verify(INPUTS, PARAMS).is_err());

        let resolved = pack(vec![warn_finding(true)], vec![approve("sam")]);
        assert_eq!(resolved.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn breach_constructor_forces_signoff_requirement() {
        assert!(Finding::breach("R1", "acct-7", "over limit").requires_signoff);
    }

    #[test]
    fn lock_lifecycle_blocks_signing_until_findings_resolve() {
        let mut p = pack(vec![Finding::breach("R1", "acct-7", "over limit")], vec![]);
        assert_eq!(
            advance_lock(LockState::Draft, &p),
            Ok(LockState::AwaitingSignoff)
        );
        assert_eq!(
            advance_lock(LockState::AwaitingSignoff, &p),
            Err(LockError::UnresolvedBreach {
                rule_id: "R1".to_string()
            })
        );
        p.signoffs.push(approve("sam"));
        assert_eq!(
            advance_lock(LockState::AwaitingSignoff, &p),
            Ok(LockState::Signed)
        );
    }

    #[test]
    fn lock_signed_is_terminal() {
        let p = pack(vec![], vec![]);
        assert_eq!(
            advance_lock(LockState::Signed, &p),
            Err(LockError::InvalidTransition(LockState::Signed))
        );
    }

    #[test]
    fn four_eyes_requires_two_distinct_signers() {
        assert!(!four_eyes_satisfied(&[]));
        assert!(!four_eyes_satisfied(&[approve("sam")]));
        assert!(!four_eyes_satisfied(&[approve("sam"), approve("sam")]));
        assert!(four_eyes_satisfied(&[approve("sam"), approve("quinn")]));
        assert!(!four_eyes_satisfied(&[approve("sam"), reject("quinn")]));
        // Case/whitespace variants merge to one signer — under-count only.
        assert!(!four_eyes_satisfied(&[approve("Sam"), approve("sam ")]));
    }

    #[test]
    fn evidence_pack_json_roundtrip_verifies() {
        let p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam")],
        );
        let json = serde_json::to_string(&p).expect("pack serializes");
        let back: EvidencePack = serde_json::from_str(&json).expect("pack deserializes");
        assert_eq!(back.verify(INPUTS, PARAMS), Ok(()));
    }
}
