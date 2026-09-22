//! bankrec-spine — Treasury bank reconciliation control spine.
//!
//! Deterministic matching of bank statement lines to cash-account ledger
//! entries: an exact tier (amount + reference), a tolerance tier (amount
//! within a configured cent window, same reference), and a many-to-one tier
//! (N ledger lines summing to one statement line within tolerance), plus
//! duplicate statement-line detection and stale-item severity escalation.
//! The result is an unmatched-items ledger, adjustment proposals, and a
//! fail-closed [`spine::EvidencePack`] with SHA-256 provenance hashes.
//!
//! Family contract (see the workspace `crates/spine` docs): the engine is
//! pure — no clock, no filesystem, no network, no randomness; money is
//! integer cents (i128); time enters only as caller-supplied dates. I/O,
//! argument parsing, and clock reads (none) live in the binary, never here.
//!
//! # Scope (v1)
//!
//! * Single currency: amounts carry no currency field and are never
//!   converted. Multi-currency is out of scope for this version.
//! * Typed inputs only: the engine consumes structured statement lines and
//!   ledger entries (JSON), not document extraction. Sign conventions are
//!   normalized at the input boundary — see [`inputs`].

pub mod cli;
pub mod config;
pub mod engine;
pub mod inputs;
pub mod pack;

pub use config::{parse_config, BankrecConfig};
pub use engine::{
    compute, fmt_cents, AdjustmentProposal, MatchRecord, MatchTier, ProposalKind,
    ReconciliationReport, Side, UnmatchedItem, RULE_LEDGER_UNMATCHED, RULE_STMT_DUPLICATE,
    RULE_STMT_UNMATCHED,
};
pub use inputs::{
    parse_inputs, CanonicalLedger, CanonicalStatement, LedgerEntry, LedgerSide,
    ReconciliationInputs, StatementLine, ValidatedInputs,
};
pub use pack::{build_pack, ComputeOutput, ENGINE_ID};

/// Version of this product crate, stamped into every evidence pack.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate error type. Engine computation itself is infallible — errors are
/// confined to malformed or invalid inputs and config.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("config invalid: {0}")]
    Config(String),
    #[error("inputs invalid: {0}")]
    Inputs(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
