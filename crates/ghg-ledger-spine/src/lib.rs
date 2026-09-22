//! `ghg-ledger-spine` — the ESG/Sustainability department control spine.
//!
//! Deterministic Scope 1/2/3 greenhouse-gas inventory with factor lineage, a
//! dual-method Scope 2, Scope 3 category tagging, and a restatement-safe
//! append-only ledger, emitting sealed evidence packs under the canonical
//! [`spine`] governance contract.
//!
//! Engine purity: no clock, no filesystem, no network, no RNG. Fixed-point
//! integers throughout — floats are never parsed. Missing factors and
//! malformed records are fail-closed gap findings, never silent zeros.
//!
//! # Family contract
//!
//! * [`pack::GhgEvidencePack`] flattens the canonical
//!   [`spine::EvidencePack`]: provenance hashes over canonical JSON bytes,
//!   typed findings, subject-scoped human signoffs, and the seal-at-`Signed`
//!   body hash.
//! * The product body (lines, period, restatement block) is held to the same
//!   tamper-evidence bar by recompute-and-compare in [`pack::verify`].
//! * Corrections are new packs referencing the predecessor's body hash —
//!   the predecessor is never modified.

pub mod cli;
pub mod engine;
pub mod model;
pub mod pack;

/// Re-export of the canonical governance crate so consumers (and tests) can
/// reach spine types through this crate's dependency on the family contract.
pub use spine;

pub use engine::{
    compute_inventory, ledger_key, ledger_totals, mul_round_half_up, ComputeError, EmissionLine,
    RestatementBlock, RestatementDelta,
};
pub use model::{
    ActivityInputs, ActivityRecord, DqTier, FactorRow, GhgConfig, Method, Scaled, Scope,
    Scope3Category, UnitConversion,
};
pub use pack::{compute, verify, GhgEvidencePack, RestatementRequest, VerifyRefusal, ENGINE_ID};
