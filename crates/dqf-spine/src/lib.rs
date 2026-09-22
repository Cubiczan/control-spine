//! dqf-spine — the Fleet/Logistics control spine.
//!
//! Deterministic DOT driver-qualification-file (DQF) compliance: checklist
//! expiry detection, out-of-service risk flags, and fail-closed evidence
//! packs, per the Department Control-Spine Products spec (Fleet/Logistics
//! block).
//!
//! * The engine is pure — the campaign date is an input (`as_of`), and the
//!   engine never reads a clock, the filesystem, or the network.
//! * Every compute run emits a sealed [`spine::EvidencePack`] with SHA-256
//!   provenance over the exact input/param bytes; [`spine::EvidencePack::verify`]
//!   recomputes everything and refuses any doubt.
//! * Breach findings (out-of-service risk on an actively driving driver)
//!   resolve only with a human signoff naming the driver — and never the
//!   engine itself.
//! * This crate depends on the canonical `spine` governance crate by path;
//!   subject-level signoff matching and separation of duties are enforced
//!   there, never re-implemented here.
//!
//! CLI: `dqf-spine compute | verify | explain` (see the crate README).

pub mod config;
pub mod engine;
pub mod error;
pub mod model;

/// Re-export of the canonical governance contract. Product code depends on
/// `spine` only through this path — never vendored.
pub use spine;

use chrono::NaiveDate;
use spine::EvidencePack;

pub use config::DqfConfig;
pub use engine::evaluate;
pub use error::DqfError;
pub use model::{Document, DriverFile, DriverRecord, Rehire};

/// Identity of this engine in produced packs. Separation of duties: an
/// approving signoff whose actor matches this id is void — an engine cannot
/// countersign its own pack.
pub const ENGINE_ID: &str = "dqf-spine";

/// Parse, validate, and evaluate a driver file; emit a sealed evidence pack.
///
/// `drivers_bytes` and `config_bytes` are hashed exactly as provided — the
/// canonical input/param bytes — so verification is a byte-exact
/// recomputation rather than a semantic comparison. The pack is emitted
/// sealed (Draft lock state): tamper-evident from birth, with signoffs to be
/// applied through the human lock flow, which re-seals on Signed.
pub fn build_pack(
    drivers_bytes: &[u8],
    config_bytes: &[u8],
    as_of: NaiveDate,
) -> Result<EvidencePack, DqfError> {
    let file: DriverFile = serde_json::from_slice(drivers_bytes).map_err(|e| DqfError::Schema {
        file: "drivers",
        detail: e.to_string(),
    })?;
    let config: DqfConfig = serde_json::from_slice(config_bytes).map_err(|e| DqfError::Schema {
        file: "config",
        detail: e.to_string(),
    })?;
    let findings = evaluate(&file.drivers, &config, as_of)?;
    let pack = EvidencePack {
        engine_id: ENGINE_ID.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: spine::sha256_hex(drivers_bytes),
        params_hash: spine::sha256_hex(config_bytes),
        findings,
        signoffs: Vec::new(),
        body_hash: String::new(),
    };
    Ok(pack.sealed())
}

/// Four-eyes gate for the privileged action of resolving an out-of-service
/// breach: two distinct human signers must approve the driver's subject.
///
/// Distinctness arithmetic is delegated to the spine; this helper scopes the
/// receipts to the subject and voids engine-actor signoffs (separation of
/// duties) before delegating.
pub fn four_eyes_ok_for_subject(pack: &EvidencePack, subject: &str) -> bool {
    let covering: Vec<spine::Signoff> = pack
        .signoffs
        .iter()
        .filter(|s| {
            s.subject == subject && !s.actor.trim().eq_ignore_ascii_case(pack.engine_id.trim())
        })
        .cloned()
        .collect();
    spine::four_eyes_satisfied(&covering)
}
