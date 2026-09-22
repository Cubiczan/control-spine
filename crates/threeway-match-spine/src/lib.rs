//! Procurement control spine: deterministic three-way (purchase order ↔
//! goods receipt ↔ invoice) and two-way (purchase order ↔ invoice) matching
//! with typed exception queues and fail-closed evidence packs.
//!
//! Family contract: the engine is pure — no clock, filesystem, or network,
//! no unseeded randomness; money is integer cents (i128); every date and
//! timestamp is caller input. All governance (findings, signoff receipts,
//! evidence packs, the seal, fail-closed verification, the lock lifecycle)
//! comes from the canonical [`spine`] crate by path dependency. This crate
//! adds only the procurement rule set.
//!
//! Boundary: the engine consumes typed purchase orders, receipt lines, and
//! invoices (schema-checked JSON). Document extraction — reading PDFs or
//! emails into typed invoices — is out of scope by design.
//!
//! See README.md for the rule tables, config reference, and honest-claims
//! statement.

pub mod engine;
pub mod error;
pub mod model;
pub mod verify;

pub use engine::{
    canonical_inputs_bytes, canonical_params_bytes, compute, RULE_DUPLICATE_INVOICE,
    RULE_NO_GR_NO_PAY, RULE_OVER_BILLING, RULE_PO_LINE_NOT_FOUND, RULE_PRICE_VARIANCE,
    RULE_QTY_VARIANCE, RULE_UNMATCHED_RECEIPT, RULE_VERSION_NOT_IN_FORCE,
};
pub use error::{EngineError, ProductVerifyError};
pub use model::{
    GoodsReceiptLine, Invoice, InvoiceLine, LineKind, MatchConfig, MatchInputs, PoLine,
    PoLineVersion, PurchaseOrder,
};
pub use verify::verify_pack;
