//! Product-level fail-closed verification, layered on the spine contract.

use crate::engine::{self, RULE_NO_GR_NO_PAY};
use crate::error::ProductVerifyError;
use crate::model::{InvoiceLine, MatchConfig, MatchInputs};
use spine::{four_eyes_satisfied, EvidencePack, Signoff, SignoffDecision};

/// Verify `pack` against the presented inputs and config. Three layers:
///
/// 1. **Spine verify** — version identity, the seal, provenance hashes, and
///    per-subject approving signoffs for every finding that requires one
///    (the producing engine's own approvals are void).
/// 2. **Findings recompute** — the pack's findings must equal a fresh
///    compute over the presented inputs; a pack carrying findings this rule
///    set would not emit from these inputs refuses (the family "verify
///    recomputes from inputs" rule).
/// 3. **No-GR-no-pay overrides** — each such breach resolves only when its
///    invoice line carries the `no_gr_override` flag AND four-eyes approvals
///    (two distinct signers, the producing engine excluded) cover its
///    subject.
pub fn verify_pack(
    pack: &EvidencePack,
    inputs: &MatchInputs,
    config: &MatchConfig,
) -> Result<(), ProductVerifyError> {
    config.validate()?;
    inputs.validate()?;
    pack.verify(
        &engine::canonical_inputs_bytes(inputs),
        &engine::canonical_params_bytes(config),
    )?;

    let recomputed = crate::engine::compute(
        inputs,
        config,
        &pack.engine_id,
        &pack.tool_version,
        Vec::new(),
    )?;
    let recomputed_findings =
        serde_json::to_value(&recomputed.findings).expect("findings are serializable");
    let presented_findings =
        serde_json::to_value(&pack.findings).expect("findings are serializable");
    if recomputed_findings != presented_findings {
        return Err(ProductVerifyError::FindingsDiverged);
    }

    for finding in &pack.findings {
        if finding.rule_id != RULE_NO_GR_NO_PAY {
            continue;
        }
        let line = locate_invoice_line(inputs, &finding.subject)
            .ok_or(ProductVerifyError::FindingsDiverged)?;
        if !line.no_gr_override {
            return Err(ProductVerifyError::NoGrOverrideMissing {
                subject: finding.subject.clone(),
            });
        }
        let approvers: Vec<Signoff> = pack
            .signoffs
            .iter()
            .filter(|s| {
                s.decision == SignoffDecision::Approve
                    && s.subject == finding.subject
                    && !s.actor.trim().is_empty()
                    && !s.actor.trim().eq_ignore_ascii_case(pack.engine_id.trim())
            })
            .cloned()
            .collect();
        if !four_eyes_satisfied(&approvers) {
            return Err(ProductVerifyError::FourEyesMissing {
                subject: finding.subject.clone(),
            });
        }
    }
    Ok(())
}

/// Locate the invoice line a `vendor:invoice_number:line_id` subject names.
/// Ids are validated free of `:` so the split is unambiguous.
fn locate_invoice_line<'a>(inputs: &'a MatchInputs, subject: &str) -> Option<&'a InvoiceLine> {
    let mut parts = subject.split(':');
    let vendor = parts.next()?;
    let number = parts.next()?;
    let line_id = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    inputs
        .invoices
        .iter()
        .find(|i| i.vendor_id == vendor && i.invoice_number == number)
        .and_then(|i| i.lines.iter().find(|l| l.line_id == line_id))
}
