//! commission-spine — deterministic sales commission control spine.
//!
//! Computes rep commissions from plan config and typed transactions with
//! effective-dated plan versions, marginal or cliff accelerator bands,
//! priority-based credit collision resolution, largest-remainder role
//! splits, windfall caps, and immutable clawback reversals — integer cents
//! throughout, no clock or network reads, output independent of input
//! order. Emits spine evidence packs that fail closed under verify.
//!
//! Contract: this crate depends on the canonical `spine` governance crate
//! by path and never re-implements signoff matching, sealing, or locks.

pub mod config;
pub mod engine;
pub mod evidence;
pub mod input;
