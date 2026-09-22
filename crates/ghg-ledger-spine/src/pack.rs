//! The evidence pack envelope for this product: the canonical
//! [`spine::EvidencePack`] flattened together with the product body — the
//! emission lines and the optional restatement block.
//!
//! The spine seal covers the spine fields (versions, provenance hashes,
//! findings, signoffs). The product body is held to the same tamper-evidence
//! bar by recomputation: [`verify`] re-runs the engine on the presented
//! inputs and config and refuses any pack whose findings, lines, period, or
//! restatement block differ from what those inputs deterministically
//! produce. Like the spine gate, any doubt refuses.

use crate::engine::{canonical_json, compute_inventory, ComputeError};
use crate::model::{ActivityInputs, GhgConfig};
use serde::{Deserialize, Serialize};

/// Identity of the producing engine. Separation of duties: an approval whose
/// actor matches this id is void — the engine cannot countersign its own
/// pack.
pub const ENGINE_ID: &str = "ghg-ledger-spine";

/// The full evidence pack emitted by a compute run and consumed by verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhgEvidencePack {
    /// Canonical spine governance fields, sealed by the spine body hash.
    #[serde(flatten)]
    pub pack: spine::EvidencePack,
    /// Reporting period (from config), part of the recomputed body.
    pub period: String,
    /// The append-only ledger lines for this pack.
    pub lines: Vec<crate::engine::EmissionLine>,
    /// Present only on restatement packs — corrections of a predecessor,
    /// never edits of it.
    #[serde(default)]
    pub restatement: Option<crate::engine::RestatementBlock>,
}

/// Why [`verify`] refused. `Spine` wraps the spine contract's own refusal;
/// `BodyMismatch` means the pack's product body does not match what its
/// inputs deterministically produce.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyRefusal {
    #[error("spine verify refused: {0}")]
    Spine(#[from] spine::VerifyError),
    #[error("could not recompute pack body: {0}")]
    Recompute(#[from] ComputeError),
    #[error("pack body mismatch: {what} do not match the inputs they claim")]
    BodyMismatch { what: &'static str },
    #[error("pack carries a restatement but no predecessor pack was presented")]
    RestatementRequiresPriorPack,
}

/// A restatement request: the predecessor pack plus the mandatory reason.
#[derive(Debug, Clone)]
pub struct RestatementRequest {
    pub prior: GhgEvidencePack,
    pub reason: String,
}

/// Check a pack's lineage claim on a predecessor: spine version match and
/// the predecessor's own seal intact (its body hash recomputes from its
/// stored fields). Tampered predecessors cannot seed a restatement.
pub fn check_predecessor(prior: &GhgEvidencePack) -> Result<(), ComputeError> {
    if prior.pack.spine_version != spine::SPINE_VERSION {
        return Err(ComputeError::Restatement(format!(
            "predecessor pack spine version {} is not {}",
            prior.pack.spine_version,
            spine::SPINE_VERSION
        )));
    }
    let resealed = prior.pack.clone().sealed();
    if resealed.body_hash != prior.pack.body_hash {
        return Err(ComputeError::Restatement(
            "predecessor pack body hash does not recompute — refusing to restate from a tampered pack"
                .to_string(),
        ));
    }
    Ok(())
}

/// Build the restatement block for a corrected run: reason (mandatory),
/// predecessor lineage, and per-ledger-key deltas current minus prior.
pub fn build_restatement(
    prior: &GhgEvidencePack,
    reason: &str,
    current_lines: &[crate::engine::EmissionLine],
    period: &str,
) -> Result<crate::engine::RestatementBlock, ComputeError> {
    if reason.trim().is_empty() {
        return Err(ComputeError::Restatement(
            "a restatement requires a non-empty reason".to_string(),
        ));
    }
    check_predecessor(prior)?;
    if prior.period != period {
        return Err(ComputeError::Restatement(format!(
            "predecessor pack covers period {}, not {} — restatements link versions of the same period",
            prior.period, period
        )));
    }
    let prior_totals = crate::engine::ledger_totals(&prior.lines)?;
    let current_totals = crate::engine::ledger_totals(current_lines)?;
    let mut keys: Vec<String> = prior_totals.keys().cloned().collect();
    for k in current_totals.keys() {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    keys.sort();
    let mut deltas = Vec::new();
    for key in keys {
        let prior_grams = prior_totals.get(&key).copied().unwrap_or(0);
        let current_grams = current_totals.get(&key).copied().unwrap_or(0);
        let delta = (current_grams as i128) - (prior_grams as i128);
        let delta_grams = i64::try_from(delta)
            .map_err(|_| ComputeError::Arithmetic("restatement delta exceeds i64".into()))?;
        deltas.push(crate::engine::RestatementDelta {
            ledger_key: key,
            prior_grams,
            current_grams,
            delta_grams,
        });
    }
    Ok(crate::engine::RestatementBlock {
        reason: reason.to_string(),
        predecessor_body_hash: prior.pack.body_hash.clone(),
        predecessor_inputs_hash: prior.pack.inputs_hash.clone(),
        deltas,
    })
}

/// Compute a full evidence pack from raw input/config JSON bytes.
///
/// `restatement` upgrades the pack to a correction of a predecessor: new
/// ledger version, mandatory reason, predecessor lineage, deltas — the
/// predecessor itself is never modified (append-only ledger; signed packs
/// are immutable).
pub fn compute(
    inputs_bytes: &[u8],
    params_bytes: &[u8],
    restatement: Option<RestatementRequest>,
) -> Result<GhgEvidencePack, ComputeError> {
    let canonical_inputs = canonical_json(inputs_bytes, "inputs")?;
    let canonical_params = canonical_json(params_bytes, "config")?;

    let inputs: ActivityInputs =
        serde_json::from_slice(inputs_bytes).map_err(|e| ComputeError::Parse {
            what: "inputs",
            message: e.to_string(),
        })?;
    let config: GhgConfig =
        serde_json::from_slice(params_bytes).map_err(|e| ComputeError::Parse {
            what: "config",
            message: e.to_string(),
        })?;
    config
        .validate()
        .map_err(|e| ComputeError::ConfigSchema(e.to_string()))?;

    let inventory = compute_inventory(&inputs, &config)?;

    let restatement_block = match restatement {
        Some(req) => Some(build_restatement(
            &req.prior,
            &req.reason,
            &inventory.lines,
            &config.period,
        )?),
        None => None,
    };

    let evidence = spine::EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: spine::sha256_hex(&canonical_inputs),
        params_hash: spine::sha256_hex(&canonical_params),
        findings: inventory.findings,
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
    .sealed();

    Ok(GhgEvidencePack {
        pack: evidence,
        period: config.period.clone(),
        lines: inventory.lines,
        restatement: restatement_block,
    })
}

/// Fail-closed verification: the spine gate (version, seal, provenance
/// hashes, subject-scoped signoffs), then a full recompute of the product
/// body from the presented inputs — findings, lines, period, and
/// restatement block must match the pack exactly. Signoffs are excluded
/// from the comparison: they are human receipts added after production.
pub fn verify(
    pack: &GhgEvidencePack,
    inputs_bytes: &[u8],
    params_bytes: &[u8],
    prior: Option<&GhgEvidencePack>,
) -> Result<(), VerifyRefusal> {
    let canonical_inputs = canonical_json(inputs_bytes, "inputs")?;
    let canonical_params = canonical_json(params_bytes, "config")?;

    pack.pack.verify(&canonical_inputs, &canonical_params)?;

    let inputs: ActivityInputs =
        serde_json::from_slice(inputs_bytes).map_err(|e| ComputeError::Parse {
            what: "inputs",
            message: e.to_string(),
        })?;
    let config: GhgConfig =
        serde_json::from_slice(params_bytes).map_err(|e| ComputeError::Parse {
            what: "config",
            message: e.to_string(),
        })?;
    config
        .validate()
        .map_err(|e| ComputeError::ConfigSchema(e.to_string()))?;

    let inventory = compute_inventory(&inputs, &config)?;

    if pack.period != config.period {
        return Err(VerifyRefusal::BodyMismatch { what: "period" });
    }
    if json_bytes(&pack.pack.findings)? != json_bytes(&inventory.findings)? {
        return Err(VerifyRefusal::BodyMismatch { what: "findings" });
    }
    if json_bytes(&pack.lines)? != json_bytes(&inventory.lines)? {
        return Err(VerifyRefusal::BodyMismatch { what: "lines" });
    }

    match (&pack.restatement, prior) {
        (None, _) => {}
        (Some(_), None) => return Err(VerifyRefusal::RestatementRequiresPriorPack),
        (Some(stored), Some(p)) => {
            let recomputed =
                build_restatement(p, &stored.reason, &inventory.lines, &config.period)?;
            if json_bytes(stored)? != json_bytes(&recomputed)? {
                return Err(VerifyRefusal::BodyMismatch {
                    what: "restatement",
                });
            }
        }
    }

    Ok(())
}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ComputeError> {
    serde_json::to_vec(value)
        .map_err(|e| ComputeError::Arithmetic(format!("serialization failed: {e}")))
}
