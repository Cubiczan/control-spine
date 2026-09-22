//! access-recert-spine — quarterly access recertification control spine
//! (IT/IAM).
//!
//! Detects entitlements that must not exist and emits revocation queues
//! with receipts: leavers still holding access, entitlements on unmanaged
//! systems, identities without a resolvable manager of record, stale
//! authentication, privileged access retained without four-eyes approval,
//! and records that cannot be matched to HR at all (quarantined, never
//! dropped).
//!
//! Family contract (see `crates/spine`): the engine is pure — no clock, no
//! filesystem, no network, no unseeded RNG; every date is caller input.
//! Findings are deterministic and sorted. Evidence packs carry SHA-256
//! provenance hashes over the exact input/config bytes, a body-hash seal,
//! and subject-scoped signoff receipts; `verify` fails closed. Identity
//! matching is by `employee_id` only — emails are never used (mailboxes
//! are recycled).

pub mod engine;
pub mod model;
pub mod pack;
