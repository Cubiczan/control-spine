//! Error vocabulary for the procurement engine and its product-level verify.

use thiserror::Error;

/// Refusals raised while computing a pack: schema- or range-invalid config
/// and inputs. Fail-closed — the engine never degrades malformed data into
/// findings or silence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EngineError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Product-level verify refusals, layered on top of the spine contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProductVerifyError {
    /// The presented config or inputs themselves failed validation.
    #[error("{0}")]
    Engine(#[from] EngineError),
    /// Spine verify refused the pack: version identity, seal, provenance
    /// hashes, or an unresolved breach.
    #[error("spine verify refused the pack: {0}")]
    Spine(#[from] spine::VerifyError),
    /// The pack's findings do not match a fresh compute over the presented
    /// inputs — the pack was not produced by this rule set from these inputs.
    #[error("findings diverge from a fresh compute over the presented inputs")]
    FindingsDiverged,
    /// A no-GR-no-pay breach resolves only when its invoice line carries the
    /// `no_gr_override` flag; a bare signoff is not enough.
    #[error("no-GR-no-pay breach on {subject} lacks the no_gr_override flag on its invoice line")]
    NoGrOverrideMissing { subject: String },
    /// Overriding no-GR-no-pay is a privileged action: two distinct human
    /// approvers (the producing engine excluded) must cover the subject.
    #[error(
        "no-GR-no-pay override on {subject} requires four-eyes approval (two distinct signers)"
    )]
    FourEyesMissing { subject: String },
}
