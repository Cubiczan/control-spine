//! coi-spine — vendor certificate-of-insurance coverage-gap detection.
//!
//! Risk/Insurance member of the control-spine family: a deterministic
//! engine, evidence packs with SHA-256 provenance, subject-scoped human
//! signoff, and fail-closed verification, all on the canonical [`spine`]
//! crate by path dependency.
//!
//! # Boundary
//!
//! The engine consumes **typed certificate data** — manually maintained
//! JSON — not document extraction; a future extraction layer feeds it (the
//! same boundary as the contract-obligation product). Certificates that do
//! not match the schema are refused, never coerced.
//!
//! The lockout finding is a **recommendation**: breach-severity gaps on a
//! critical vendor category recommend a hold on new purchase orders, and a
//! human executes any hold outside this engine.
//!
//! Engine purity: no clock (the `--as-of` date is caller input), no
//! filesystem or network, no RNG; money is integer cents (i128).

pub mod cert;
pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod pack;

pub use cert::{Certificate, PolicyLine};
pub use config::{
    CarrierRating, CategoryRequirement, Coverage, CoverageRequirement, Endorsement,
    RequirementsConfig,
};
pub use engine::{evaluate, format_cents, Evaluation};
pub use error::CoiError;
pub use pack::{build_pack, canonical_json, ENGINE_ID};
