//! Contract obligation spine — the Legal department control spine.
//!
//! A typed obligation register with deterministic deadline and renewal-window
//! arithmetic over a caller-supplied clock, shipped as part of the
//! control-spine family: pure domain engine, evidence pack with SHA-256
//! provenance and body hashes, human signoff on every breach-severity
//! finding, fail-closed verification.
//!
//! # What it computes
//!
//! * **Due dates** for `payment`, `delivery`, `indemnity`, and
//!   `termination_for_convenience` obligations — either contract-stated
//!   explicit dates or dependent dates: an explicit anchor obligation's due
//!   (or completion) date shifted by clamped month and day offsets, then
//!   business-day rolled per jurisdiction calendar.
//! * **Renewal windows** for `renewal_opt_out` obligations: the opt-out
//!   deadline is `renewal_date - notice_days` (business-day rolled), with
//!   auto-renew detection — a window that closes without an opt-out is a
//!   breach while it can still be escalated, and an already-renewed contract
//!   is a breach on its own.
//! * **SLA credits** for `sla` obligations: each measured period lands in a
//!   tier from the params credit-tier table (basis points, never floats);
//!   a period below every tier floor is a breach; a stale measurement is a
//!   warn.
//! * **Append-only corrections**: a correction is a new record version that
//!   supersedes the prior one — never a mutation. Findings are computed
//!   against the latest version, and verifying a pack over a corrected
//!   register requires four-eyes signoff per corrected obligation.
//!
//! # Family contract
//!
//! * Depends on `spine` by path; the governance contract (findings,
//!   signoffs, evidence packs, lock lifecycle, verification) is the spine's,
//!   not re-implemented here.
//! * The engine is pure: no clock, filesystem, network, or randomness.
//!   Time is caller input (`--clock YYYY-MM-DD`). Money is integer cents
//!   (i128); percentages are basis points.
//! * Config tables (calendars, SLA credit tiers) are schema-checked JSON and
//!   labeled seed data — see the crate README.
//! * `verify` refuses anything it cannot prove: tampered pack bodies
//!   (body-hash seal), foreign spine versions, input/params hash mismatches,
//!   unresolved breaches, and unsigned corrections.

pub mod engine;
pub mod model;
pub mod pack;

pub use engine::{
    add_months, credit_cents, evaluate, tier_for, DeadlineResolution, Evaluation, ResolutionKind,
};
pub use model::{
    AnchorEvent, Calendar, ConfigError, DateSpec, ObligationRecord, ObligationType, PolicyParams,
    RegisterInputs, RenewalTerms, RollMode, SlaMeasurement, SlaTerms, SlaTier,
};
pub use pack::{
    build_pack, canonical_inputs_bytes, canonical_params_bytes, corrected_obligation_ids,
    finalize_lock, verify_pack, VerifyFailure, ENGINE_ID,
};
pub use spine::{EvidencePack, Finding, LockState, Severity, Signoff, SignoffDecision};
