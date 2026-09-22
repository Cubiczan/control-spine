//! Evidence-pack assembly, lock progression, fail-closed verification, and
//! the human-readable explain renderer.
//!
//! Packs carry SHA-256 provenance hashes over the exact input/config bytes
//! and are sealed at `Signed` (the family Seal gate). Verification runs
//! three gates in order: lock state, the spine contract (seal, provenance
//! hashes, subject-scoped signoffs), and a full recomputation of the
//! findings from the supplied inputs. Any doubt refuses.

use serde::{Deserialize, Serialize};
use spine::{
    advance_lock, first_unresolved_finding, four_eyes_satisfied, sha256_hex, EvidencePack, Finding,
    LockError, LockState, Severity, Signoff, SignoffDecision, VerifyError, SPINE_VERSION,
};

use crate::engine::{
    self, RULE_LEAVER_ACTIVE, RULE_ORPHAN_MANAGER, RULE_ORPHAN_SYSTEM, RULE_PRIVILEGED_FOUR_EYES,
    RULE_QUARANTINE, RULE_STALE_AUTH,
};
use crate::model::{CampaignInput, RecertConfig};

/// Engine identity. Separation of duties: signoff receipts from this actor
/// cannot resolve findings on packs this engine produced.
pub const ENGINE_ID: &str = "access-recert-spine";

/// A pack document as written to disk: the spine [`EvidencePack`] plus the
/// lock state the product CLI manages around it. Only `Signed` packs are
/// evidence (family crosswalk: `Signed` ≡ `LOCKED`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackDocument {
    pub lock_state: LockState,
    pub pack: EvidencePack,
}

/// The first finding that cannot resolve under this product's lock gate:
/// the spine floor (a gated finding with no covering human approval) plus
/// the product's four-eyes policy — a `privileged-four-eyes` finding
/// resolves only when two distinct humans approve its subject, so a single
/// post-compute attestation cannot launder a four-eyes gap into signed
/// evidence. Cover criteria mirror the spine contract's private
/// `approval_covers` (approve decision, human actor distinct from the
/// producing engine, exact finding subject); distinctness is delegated to
/// the spine's public [`four_eyes_satisfied`].
fn first_unresolved_finding_strict(pack: &EvidencePack) -> Option<&Finding> {
    if let Some(finding) = first_unresolved_finding(pack) {
        return Some(finding);
    }
    pack.findings
        .iter()
        .filter(|f| f.rule_id == RULE_PRIVILEGED_FOUR_EYES)
        .find(|f| {
            let covering: Vec<Signoff> = pack
                .signoffs
                .iter()
                .filter(|s| approval_covers(pack, s, f))
                .cloned()
                .collect();
            !four_eyes_satisfied(&covering)
        })
}

fn approval_covers(pack: &EvidencePack, s: &Signoff, finding: &Finding) -> bool {
    let actor = s.actor.trim();
    s.decision == SignoffDecision::Approve
        && !actor.is_empty()
        && !actor.eq_ignore_ascii_case(pack.engine_id.trim())
        && s.subject == finding.subject
}

/// Build the pack for a computed campaign and run the lock lifecycle:
/// `draft` → `awaiting_signoff`, then → `signed` (sealed) when every gated
/// finding is resolved by a subject-scoped approval. Packs with unresolved
/// gated findings park at `awaiting_signoff`.
pub fn build_pack(
    input: &CampaignInput,
    config: &RecertConfig,
    inputs_bytes: &[u8],
    params_bytes: &[u8],
    signoffs: Vec<Signoff>,
) -> Result<PackDocument, LockError> {
    let findings = engine::evaluate(input, config, ENGINE_ID);
    let mut pack = EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: format!("access-recert-spine v{}", env!("CARGO_PKG_VERSION")),
        spine_version: SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(inputs_bytes),
        params_hash: sha256_hex(params_bytes),
        findings,
        signoffs,
        body_hash: String::new(),
    };
    let mut state = advance_lock(LockState::Draft, &mut pack)?;
    if first_unresolved_finding_strict(&pack).is_none() {
        state = advance_lock(state, &mut pack)?; // seals the pack at Signed
    }
    Ok(PackDocument {
        lock_state: state,
        pack,
    })
}

/// Verification refusal reasons beyond the spine contract's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackVerificationError {
    /// The pack is not `Signed`. Only signed packs are evidence; packs
    /// with unresolved gated findings park at `awaiting_signoff`.
    NotSigned,
    /// The spine contract refused the pack (seal, hashes, signoffs).
    Spine(VerifyError),
    /// The pack's findings do not reproduce from the inputs: the recorded
    /// findings were not produced by this engine from these inputs.
    RecomputationMismatch,
    /// The pack claims `Signed` but a gated finding is unresolved under the
    /// lock gate — including a `privileged-four-eyes` finding with fewer
    /// than two distinct approvers.
    UnresolvedGate { rule_id: String },
}

impl std::fmt::Display for PackVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSigned => write!(
                f,
                "pack is not Signed — only signed packs are evidence (unresolved gated findings park at awaiting_signoff)"
            ),
            Self::Spine(error) => write!(f, "{error}"),
            Self::RecomputationMismatch => write!(
                f,
                "findings do not reproduce from inputs — pack body does not match engine output"
            ),
            Self::UnresolvedGate { rule_id } => write!(
                f,
                "finding {rule_id} is unresolved under the lock gate — gated findings need \
                 covering signoffs and four-eyes findings need two distinct approvers"
            ),
        }
    }
}

/// Fail-closed verification: lock state, spine contract (seal, provenance
/// hashes, signoffs), and a full recomputation of the findings from the
/// supplied inputs under the pack's own engine identity. Any doubt refuses.
pub fn verify_pack(
    document: &PackDocument,
    input: &CampaignInput,
    config: &RecertConfig,
    inputs_bytes: &[u8],
    params_bytes: &[u8],
) -> Result<(), PackVerificationError> {
    if document.lock_state != LockState::Signed {
        return Err(PackVerificationError::NotSigned);
    }
    document
        .pack
        .verify(inputs_bytes, params_bytes)
        .map_err(PackVerificationError::Spine)?;
    if let Some(finding) = first_unresolved_finding_strict(&document.pack) {
        return Err(PackVerificationError::UnresolvedGate {
            rule_id: finding.rule_id.clone(),
        });
    }
    let recomputed = engine::evaluate(input, config, &document.pack.engine_id);
    let recorded = serde_json::to_value(&document.pack.findings)
        .expect("Finding is a plain struct; serialization cannot fail");
    let reproduced = serde_json::to_value(&recomputed)
        .expect("Finding is a plain struct; serialization cannot fail");
    if reproduced != recorded {
        return Err(PackVerificationError::RecomputationMismatch);
    }
    Ok(())
}

/// The pack document's lock state in the serde JSON vocabulary the pack
/// file itself uses, so `explain` output greps like the JSON. Exhaustive
/// match: a new spine variant breaks compilation here instead of drifting.
fn lock_label(state: LockState) -> &'static str {
    match state {
        LockState::Draft => "draft",
        LockState::AwaitingSignoff => "awaiting_signoff",
        LockState::Signed => "signed",
    }
}

/// Human-readable explanation of a pack: provenance, queues, recorded
/// signoffs, and the rule catalog. Informational — this is not a check.
pub fn render_explain(document: &PackDocument) -> String {
    let pack = &document.pack;
    let mut out = String::new();
    out.push_str("access-recert-spine evidence pack\n");
    out.push_str(&format!(
        "  engine:       {engine} ({tool})\n",
        engine = pack.engine_id,
        tool = pack.tool_version
    ));
    out.push_str(&format!(
        "  spine:        {version}\n",
        version = pack.spine_version
    ));
    out.push_str(&format!(
        "  lock state:   {state}\n",
        state = lock_label(document.lock_state)
    ));
    out.push_str(&format!(
        "  inputs hash:  {hash}\n",
        hash = pack.inputs_hash
    ));
    out.push_str(&format!(
        "  params hash:  {hash}\n",
        hash = pack.params_hash
    ));
    out.push_str(&format!("  body hash:    {hash}\n", hash = pack.body_hash));

    let breaches: Vec<&Finding> = pack
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .collect();
    let quarantine: Vec<&Finding> = pack
        .findings
        .iter()
        .filter(|f| f.rule_id == RULE_QUARANTINE)
        .collect();
    let gated: Vec<&Finding> = pack
        .findings
        .iter()
        .filter(|f| {
            f.severity != Severity::Breach && f.requires_signoff && f.rule_id != RULE_QUARANTINE
        })
        .collect();
    let review: Vec<&Finding> = pack
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Breach && !f.requires_signoff)
        .collect();

    push_section(
        &mut out,
        "REVOCATION QUEUE (breach — revoke access or obtain signoff)",
        &breaches,
    );
    push_section(
        &mut out,
        "QUARANTINE QUEUE (unmatched identity — manual attribution required)",
        &quarantine,
    );
    push_section(
        &mut out,
        "SIGNOFF REQUIRED (gated warnings — cannot pass without review)",
        &gated,
    );
    push_section(&mut out, "REVIEW QUEUE (warnings)", &review);

    out.push_str(&format!(
        "\nSIGNOFFS RECORDED ({count})\n",
        count = pack.signoffs.len()
    ));
    for signoff in &pack.signoffs {
        out.push_str(&format!(
            "  - {actor} ({role}) {decision:?} subject {subject} at {at}\n",
            actor = signoff.actor,
            role = signoff.role,
            decision = signoff.decision,
            subject = signoff.subject,
            at = signoff.at
        ));
    }

    out.push_str("\nRULE CATALOG\n");
    for (rule, description) in RULE_CATALOG {
        out.push_str(&format!("  {rule:<26} {description}\n"));
    }
    out
}

fn push_section(out: &mut String, title: &str, findings: &[&Finding]) {
    out.push_str(&format!(
        "\n{title} ({count})\n",
        title = title,
        count = findings.len()
    ));
    if findings.is_empty() {
        out.push_str("  (none)\n");
        return;
    }
    for finding in findings {
        out.push_str(&format!(
            "  - {subject} [{rule}] {message}\n",
            subject = finding.subject,
            rule = finding.rule_id,
            message = finding.message
        ));
    }
}

const RULE_CATALOG: &[(&str, &str)] = &[
    (
        RULE_LEAVER_ACTIVE,
        "breach — active entitlement for an identity separated before the campaign date",
    ),
    (
        RULE_ORPHAN_SYSTEM,
        "breach — entitlement on a system with no managed-system record",
    ),
    (
        RULE_ORPHAN_MANAGER,
        "warn — identity's manager of record is missing or unresolvable (grace-exempt)",
    ),
    (
        RULE_STALE_AUTH,
        "warn — no successful authentication within the configured window (grace-exempt)",
    ),
    (
        RULE_PRIVILEGED_FOUR_EYES,
        "warn — privileged entitlement retained without two distinct approvers",
    ),
    (
        RULE_QUARANTINE,
        "warn — entitlement unmatched to HR by employee_id; never matched by email",
    ),
];
