//! Evidence-pack glue: canonical bytes, provenance hashes, and the pack
//! builder against the canonical `spine` governance crate (path dependency —
//! never vendored).

use spine::{EvidencePack, Finding};

use crate::config::PayrollConfig;
use crate::engine::{PayrollError, PayrollInput, PayrollOutcome};

/// Identity of this engine inside evidence packs. Separation of duties: a
/// signoff whose actor matches this id cannot resolve this pack's breaches —
/// an engine cannot countersign its own pack.
pub const ENGINE_ID: &str = "payroll-spine";

/// Canonical input bytes: the typed input re-serialized by serde in fixed
/// field order (struct order; BTreeMap keys sorted). Formatting and key
/// order of the source JSON do not matter — the same run always hashes the
/// same.
pub fn canonical_input_bytes(inputs: &PayrollInput) -> Result<Vec<u8>, PayrollError> {
    serde_json::to_vec(inputs).map_err(|e| PayrollError::Serialization(e.to_string()))
}

/// Canonical config bytes — same canonicalization rule as inputs.
pub fn canonical_param_bytes(config: &PayrollConfig) -> Result<Vec<u8>, PayrollError> {
    serde_json::to_vec(config).map_err(|e| PayrollError::Serialization(e.to_string()))
}

/// Field-by-field equality for findings — spine::Finding intentionally has
/// no PartialEq, so verify's reproduction check compares each field.
pub fn findings_match(a: &[Finding], b: &[Finding]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(x, y)| {
            x.rule_id == y.rule_id
                && x.severity == y.severity
                && x.subject == y.subject
                && x.message == y.message
                && x.requires_signoff == y.requires_signoff
        })
}

/// Build the pack for a computed run: SHA-256 provenance over canonical
/// inputs and config bytes, findings as emitted, no signoffs yet, sealed.
///
/// A pack with breach findings (negative net pay) verifies only after a
/// human signoff naming the subject is recorded and the pack re-seals — the
/// spine lock lifecycle seals again on the transition to Signed. A clean
/// pack verifies immediately.
pub fn build_pack(
    inputs: &PayrollInput,
    config: &PayrollConfig,
    outcome: &PayrollOutcome,
) -> Result<EvidencePack, PayrollError> {
    Ok(EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: spine::sha256_hex(&canonical_input_bytes(inputs)?),
        params_hash: spine::sha256_hex(&canonical_param_bytes(config)?),
        findings: outcome.findings.clone(),
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
    .sealed())
}
