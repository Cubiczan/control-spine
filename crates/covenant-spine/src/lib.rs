//! Treasury/Finance covenant control spine.
//!
//! Deterministic debt-covenant testing over normalized financials: typed
//! covenants (max leverage, min interest coverage, min current ratio, min
//! fixed-charge coverage), effective-dated amendment resolution, equity-cure
//! adjustments, headroom with explicit units, and a deterministic
//! linear-trend breach projection. Every compute run emits a spine
//! [`spine::EvidencePack`]; the governance contract — seal gate,
//! subject-scoped signoffs, four-eyes, fail-closed verification — lives in
//! the canonical `spine` crate and is used by path dependency, never
//! re-implemented here.
//!
//! Engine purity is a family rule: no clock, no filesystem, no network, no
//! unseeded randomness. Time is caller input (`measurement_date`), money is
//! integer cents ([`units::Cents`], i128), and ratios are integers scaled
//! by millionths ([`units::Ratio`]) — there are no floats anywhere.

pub mod config;
pub mod engine;
pub mod input;
pub mod pack;
pub mod units;

/// Identity of this engine in evidence packs. Separation of duties: a
/// signoff whose actor matches this id cannot countersign a pack, and the
/// four-eyes gate excludes it from the distinct-signer count.
pub const ENGINE_ID: &str = "covenant-spine";
