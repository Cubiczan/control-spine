//! Evidence pack construction for bankrec-spine.
//!
//! Packs bind the reconciliation outcome to the exact bytes consumed:
//! `inputs_hash` is the SHA-256 of the inputs document as read,
//! `params_hash` the SHA-256 of the config document as read. Packs are
//! sealed at production (body hash over the pack body), and breach
//! findings require a human signoff receipt naming the finding's subject
//! — the producing engine cannot countersign its own pack.

use spine::{sha256_hex, EvidencePack, Signoff};

use crate::engine::ReconciliationReport;

/// Engine identity stamped into packs. Separation of duties: an approval
/// whose actor matches this id cannot resolve a finding.
pub const ENGINE_ID: &str = "bankrec-spine";

/// Full output of a `compute` run: the reconciliation report plus the
/// sealed evidence pack that vouches for it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeOutput {
    pub engine_id: String,
    pub tool_version: String,
    pub as_of: String,
    pub report: ReconciliationReport,
    pub evidence_pack: EvidencePack,
}

/// Build a sealed evidence pack for `report` from the canonical input and
/// config bytes. Signoffs, if any, are embedded as supplied.
pub fn build_pack(
    report: &ReconciliationReport,
    engine_id: &str,
    tool_version: &str,
    inputs_bytes: &[u8],
    params_bytes: &[u8],
    signoffs: Vec<Signoff>,
) -> EvidencePack {
    EvidencePack {
        engine_id: engine_id.to_string(),
        tool_version: tool_version.to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(inputs_bytes),
        params_hash: sha256_hex(params_bytes),
        findings: report.findings.clone(),
        signoffs,
        body_hash: String::new(),
    }
    .sealed()
}
