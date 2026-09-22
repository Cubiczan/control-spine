//! capa-spine — the Quality/EHS control spine.
//!
//! Deterministic corrective/preventive-action (CAPA) governance over
//! nonconformances: severity from a configured matrix, containment windows
//! and aging thresholds over a caller-supplied clock, duplicate detection on
//! normalized descriptions, reopen-cycle linkage, and human-locked closure.
//! Every compute run emits a sealed [`spine::EvidencePack`]; verification is
//! fail-closed.
//!
//! Purity: the engine is a pure function of (records, config, clock). No
//! clock reads, filesystem, network, or RNG — time enters only as the
//! caller-supplied `as_of` instant.

mod config;
mod engine;
mod explain;
mod model;

pub use config::{AgingRules, CapaConfig, ConfigError, ContainmentHours, SeverityCell};
pub use engine::{
    description_hash, evaluate, normalize_description, severity_label, CapaEvaluation,
    RULE_AGING_BREACH, RULE_AGING_WARN, RULE_BROKEN_REOPEN_LINK, RULE_CLOSURE_BLOCKED,
    RULE_CONTAINMENT_LATE, RULE_CONTAINMENT_OVERDUE, RULE_DUPLICATE_DESCRIPTION,
    RULE_EFFECTIVENESS_OVERDUE,
};
pub use explain::explain_one;
pub use model::{CapaRecord, Category, Detectability, EffectivenessCheck, Status};

use spine::{sha256_hex, EvidencePack, Finding};

/// Identity of this engine in the evidence-pack contract. Separation of
/// duties: signoffs whose actor matches this id are void.
pub const ENGINE_ID: &str = "capa-spine";

/// Version of this tool, from the package manifest.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build a sealed evidence pack for a compute run: provenance hashes over
/// the exact input/config bytes, findings sorted by (subject, rule id) for
/// byte-deterministic packs, seal computed over the body.
///
/// The pack leaves with no signoffs; breach findings refuse to verify — and
/// the pack cannot reach `Signed` — until subject-scoped receipts are
/// appended and the pack is re-sealed.
pub fn build_pack(
    engine_id: &str,
    mut findings: Vec<Finding>,
    inputs: &[u8],
    params: &[u8],
) -> EvidencePack {
    findings.sort_by(|a, b| (&a.subject, &a.rule_id).cmp(&(&b.subject, &b.rule_id)));
    EvidencePack {
        engine_id: engine_id.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(inputs),
        params_hash: sha256_hex(params),
        findings,
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
    .sealed()
}
