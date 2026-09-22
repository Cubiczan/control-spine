//! Canonical governance crate for the control-spine family.
//!
//! Every department engine crate in this workspace depends on `spine` by path
//! and ships the same contract: typed findings, human signoff receipts, the
//! lock lifecycle, and evidence packs with SHA-256 provenance and envelope
//! hashes that fail closed — a pack either proves itself or
//! [`EvidencePack::verify`] refuses.
//!
//! Engine purity is a family rule: no clock reads, no network, no
//! filesystem; randomness only from a SHA-256-derived seed, and only in
//! engine crates that sample. Money is integer cents (i128). Time is an
//! input supplied by the caller.
//!
//! # Family conventions
//!
//! * Canonical contract: this crate is the canonical governance contract for
//!   new department engines; the Python `control_spine` package remains the
//!   substrate for the existing finance-engine family.
//! * Corrections: signed packs are immutable. A correction is a new pack
//!   computed on corrected inputs that records its predecessor's lineage
//!   (envelope hash) in its own tool metadata — never an edit to a signed
//!   pack. Supersede/Void lifecycle states are deferred to spine 1.1.
//! * Tamper evidence: the envelope hash covers the full pack body (the
//!   SHA-256 seal of the Python spine's envelope). Verify recomputes it
//!   from the pack's actual contents and refuses altered packs; the
//!   envelope hash is a pack's identity for lineage references.
//! * Version migration: a pack verifies only under the spine version that
//!   produced it. After a spine version bump, the recovery path for 1.0.0
//!   packs is to re-run the engine on the original inputs — the pack's
//!   provenance hashes make that run bit-for-bit reproducible.

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
/// caller — the engine never reads a clock. `subject` names the finding
/// subject the receipt covers: an approval resolves findings on the subject
/// it names, and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signoff {
    pub actor: String,
    pub role: String,
    pub subject: String,
    pub decision: SignoffDecision,
    pub at: String,
}

/// Evidence pack emitted by every compute run: inputs/params provenance
/// hashes, findings, and the signoffs that resolve them. The full body is
/// sealed by an envelope hash — see [`EvidencePack::sealed`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePack {
    /// Identity of the engine that produced the pack. Separation of duties:
    /// an approving signoff whose actor matches `engine_id` is void — an
    /// engine cannot countersign its own pack (mirrors the Python spine's
    /// owner-signoff-must-differ-from-preparer rule).
    pub engine_id: String,
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
    /// SHA-256 over the canonical serialization of every other field — the
    /// envelope hash (the Seal gate's Rust implementation). Empty on a pack
    /// that has not been sealed yet; [`EvidencePack::verify`] refuses packs
    /// whose envelope hash does not recompute.
    pub envelope_hash: String,
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
///
/// Crosswalk to the documented lock progression (`EXPLORING` → `ADVISORY` /
/// `PROVISIONAL_LOCK` → `LOCKED`, or `HALT`): `Draft` ≡ pre-`ADVISORY`
/// drafting, `AwaitingSignoff` ≡ `ADVISORY`/`PROVISIONAL_LOCK` (submitted for
/// human review), `Signed` ≡ `LOCKED` — the only state that qualifies as
/// evidence — and the unresolved-finding refusal in [`advance_lock`] ≡
/// `HALT`. The documented constraint holds by crosswalk: `LOCKED` is the
/// only state that is evidence, and only `Signed` packs export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    Draft,
    AwaitingSignoff,
    Signed,
}

/// Canonical serialization of the pack body for the envelope hash: fixed
/// field order, strings and slices only — byte-deterministic for identical
/// contents.
#[derive(Serialize)]
struct EnvelopeBody<'a> {
    engine_id: &'a str,
    tool_version: &'a str,
    spine_version: &'a str,
    inputs_hash: &'a str,
    params_hash: &'a str,
    findings: &'a [Finding],
    signoffs: &'a [Signoff],
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
            && !pack.signoffs.iter().any(|s| pack.approval_covers(s, f))
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
    /// recognized, the envelope hash recomputes from the pack's own contents
    /// (no post-production body edits), both provenance hashes recompute
    /// from the canonical bytes, and every finding that requires signoff
    /// carries an approving signoff naming its subject. Any doubt refuses.
    pub fn verify(&self, inputs: &[u8], params: &[u8]) -> Result<(), VerifyError> {
        if self.spine_version != SPINE_VERSION || self.tool_version.is_empty() {
            return Err(VerifyError::ForeignVersion);
        }
        // Seal gate first: the stored inputs/params hashes only mean
        // something if the body that carries them is intact.
        if self.envelope_hash != sha256_hex(&self.envelope_body_bytes()) {
            return Err(VerifyError::HashMismatch { field: "envelope" });
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

    /// Seal the pack: compute and store the envelope hash over the current
    /// body. Call once findings and signoffs are final — any later mutation
    /// of the pack breaks the seal and [`EvidencePack::verify`] refuses.
    /// Sealing is idempotent.
    pub fn sealed(mut self) -> Self {
        let body = self.envelope_body_bytes();
        self.envelope_hash = sha256_hex(&body);
        self
    }

    fn envelope_body_bytes(&self) -> Vec<u8> {
        let body = EnvelopeBody {
            engine_id: &self.engine_id,
            tool_version: &self.tool_version,
            spine_version: &self.spine_version,
            inputs_hash: &self.inputs_hash,
            params_hash: &self.params_hash,
            findings: &self.findings,
            signoffs: &self.signoffs,
        };
        serde_json::to_vec(&body)
            .expect("EnvelopeBody is a fixed-shape struct; serialization cannot fail")
    }

    /// True when `s` is a valid human approval covering `finding.subject`:
    /// an `Approve` decision, a non-empty actor, an actor distinct from the
    /// producing engine (an engine cannot countersign its own pack), and a
    /// subject naming the finding's subject exactly.
    fn approval_covers(&self, s: &Signoff, finding: &Finding) -> bool {
        let actor = s.actor.trim();
        s.decision == SignoffDecision::Approve
            && !actor.is_empty()
            && !actor.eq_ignore_ascii_case(self.engine_id.trim())
            && s.subject == finding.subject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUTS: &[u8] = b"canonical-inputs";
    const PARAMS: &[u8] = b"canonical-params";

    fn pack(findings: Vec<Finding>, signoffs: Vec<Signoff>) -> EvidencePack {
        pack_with_engine("engine-under-test", findings, signoffs).sealed()
    }

    fn pack_with_engine(
        engine_id: &str,
        findings: Vec<Finding>,
        signoffs: Vec<Signoff>,
    ) -> EvidencePack {
        EvidencePack {
            engine_id: engine_id.to_string(),
            tool_version: "test-tool 0.1.0".to_string(),
            spine_version: SPINE_VERSION.to_string(),
            inputs_hash: sha256_hex(INPUTS),
            params_hash: sha256_hex(PARAMS),
            findings,
            signoffs,
            envelope_hash: String::new(),
        }
    }

    fn signoff(actor: &str, subject: &str, decision: SignoffDecision) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "controller".to_string(),
            subject: subject.to_string(),
            decision,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    fn approve(actor: &str, subject: &str) -> Signoff {
        signoff(actor, subject, SignoffDecision::Approve)
    }

    fn reject(actor: &str, subject: &str) -> Signoff {
        signoff(actor, subject, SignoffDecision::Reject)
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
            vec![approve("sam", "acct-7")],
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

        let resolved = pack(vec![warn_finding(true)], vec![approve("sam", "acct-7")]);
        assert_eq!(resolved.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn breach_constructor_forces_signoff_requirement() {
        assert!(Finding::breach("R1", "acct-7", "over limit").requires_signoff);
    }

    #[test]
    fn verify_requires_signoff_on_the_finding_subject() {
        // An approval naming subject A must not clear a breach on subject B.
        let p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam", "acct-9")],
        );
        assert_eq!(
            p.verify(INPUTS, PARAMS),
            Err(VerifyError::UnresolvedBreach {
                rule_id: "R1".to_string()
            })
        );

        let matched = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam", "acct-7")],
        );
        assert_eq!(matched.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn verify_multi_breach_pack_requires_per_subject_approvals() {
        let findings = vec![
            Finding::breach("R1", "acct-7", "over limit"),
            Finding::breach("R2", "vendor-3", "over-billed"),
        ];
        // One subject's approval resolves only that subject's breach.
        let p = pack(findings.clone(), vec![approve("sam", "acct-7")]);
        assert_eq!(
            p.verify(INPUTS, PARAMS),
            Err(VerifyError::UnresolvedBreach {
                rule_id: "R2".to_string()
            })
        );
        let resolved = pack(
            findings,
            vec![approve("sam", "acct-7"), approve("quinn", "vendor-3")],
        );
        assert_eq!(resolved.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn verify_refuses_engine_countersign() {
        // Separation of duties: an engine cannot countersign its own pack —
        // an approval whose actor matches engine_id (case-insensitively) is
        // void.
        let engine_id = "payroll-spine";
        let breach = vec![Finding::breach("R1", "acct-7", "over limit")];
        let only_engine = pack_with_engine(
            engine_id,
            breach.clone(),
            vec![approve(engine_id, "acct-7")],
        )
        .sealed();
        assert!(only_engine.verify(INPUTS, PARAMS).is_err());

        let case_variant = pack_with_engine(
            engine_id,
            breach.clone(),
            vec![approve("Payroll-Spine", "acct-7")],
        )
        .sealed();
        assert!(case_variant.verify(INPUTS, PARAMS).is_err());

        // The void receipt is powerless; a distinct human approval resolves.
        let with_human = pack_with_engine(
            engine_id,
            breach,
            vec![approve(engine_id, "acct-7"), approve("sam", "acct-7")],
        )
        .sealed();
        assert_eq!(with_human.verify(INPUTS, PARAMS), Ok(()));
    }

    #[test]
    fn verify_refuses_anonymous_approval() {
        // A receipt with no actor is not a human signoff and cannot resolve.
        let p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("", "acct-7")],
        );
        assert!(p.verify(INPUTS, PARAMS).is_err());
    }

    #[test]
    fn verify_refuses_pack_body_tampering() {
        // Seal gate: the pack body is envelope-hash protected. Altering a
        // resolved pack after the fact — here, downgrading a breach to a
        // warning — must refuse even with the original inputs presented.
        let mut p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam", "acct-7")],
        );
        assert_eq!(p.verify(INPUTS, PARAMS), Ok(()));

        p.findings[0].severity = Severity::Warn;
        p.findings[0].requires_signoff = false;
        assert_eq!(
            p.verify(INPUTS, PARAMS),
            Err(VerifyError::HashMismatch { field: "envelope" })
        );

        // Deleting a finding is the same refusal.
        let mut q = pack(
            vec![
                Finding::breach("R1", "acct-7", "over limit"),
                Finding::breach("R2", "acct-9", "over limit"),
            ],
            vec![approve("sam", "acct-7"), approve("quinn", "acct-9")],
        );
        assert_eq!(q.verify(INPUTS, PARAMS), Ok(()));
        q.findings.pop();
        assert!(q.verify(INPUTS, PARAMS).is_err());
    }

    #[test]
    fn verify_refuses_unsealed_pack() {
        // An unsealed pack carries an empty envelope hash and cannot verify —
        // fail-closed, no bypass path for unsigned bodies.
        let p = pack_with_engine("engine-under-test", vec![], vec![]);
        assert_eq!(
            p.verify(INPUTS, PARAMS),
            Err(VerifyError::HashMismatch { field: "envelope" })
        );
    }

    #[test]
    fn sealed_is_idempotent_and_hash_tracks_body() {
        let a = pack(vec![Finding::breach("R1", "acct-7", "over limit")], vec![]);
        let b = a.clone().sealed();
        assert_eq!(a.envelope_hash, b.envelope_hash);

        let mut c = a.clone();
        c.signoffs.push(approve("sam", "acct-7"));
        let c = c.sealed();
        assert_ne!(a.envelope_hash, c.envelope_hash);
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
        p.signoffs.push(approve("sam", "acct-7"));
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
        let s = "subj-1";
        assert!(!four_eyes_satisfied(&[]));
        assert!(!four_eyes_satisfied(&[approve("sam", s)]));
        assert!(!four_eyes_satisfied(&[
            approve("sam", s),
            approve("sam", s)
        ]));
        assert!(four_eyes_satisfied(&[
            approve("sam", s),
            approve("quinn", s)
        ]));
        assert!(!four_eyes_satisfied(&[
            approve("sam", s),
            reject("quinn", s)
        ]));
        // Case/whitespace variants merge to one signer — under-count only.
        assert!(!four_eyes_satisfied(&[
            approve("Sam", s),
            approve("sam ", s)
        ]));
    }

    #[test]
    fn evidence_pack_json_roundtrip_verifies() {
        let p = pack(
            vec![Finding::breach("R1", "acct-7", "over limit")],
            vec![approve("sam", "acct-7")],
        );
        let json = serde_json::to_string(&p).expect("pack serializes");
        let back: EvidencePack = serde_json::from_str(&json).expect("pack deserializes");
        assert_eq!(back.verify(INPUTS, PARAMS), Ok(()));
    }
}
