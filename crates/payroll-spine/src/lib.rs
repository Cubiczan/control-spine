//! Payroll control spine — the HR/payroll member of the department
//! control-spine family (spec: Department Control-Spine Products, rev 2,
//! product block "payroll-spine").
//!
//! The engine recomputes gross-to-net from pay components and config tables
//! and flags variances against a payroll provider register before funds
//! move. It is pure: no clock, no filesystem, no network, no unseeded RNG.
//! Time is caller input (period dates); money is integer cents (i128); every
//! money division rounds half-up. The `chrono` dependency disables its
//! `clock` feature at the dependency level, so reading a clock cannot even
//! be spelled in this crate.
//!
//! Module map:
//!
//! * [`engine`] — the deterministic gross-to-net computation and findings.
//! * [`config`] — schema-checked JSON config tables (unknown fields refuse
//!   to parse).
//! * [`pack`] — canonical bytes, provenance hashes, evidence-pack builder.
//! * [`cli`] — the `compute | verify | explain` command surface. The CLI is
//!   the I/O shim; the purity contract applies to the engine modules.
//!
//! Evidence packs are built on the canonical [`spine`] governance crate by
//! path dependency — never vendored. Breach findings (negative net pay)
//! require a human signoff receipt naming the employee subject before the
//! pack verifies, and an approval whose actor matches this engine's id is
//! void — an engine cannot countersign its own pack.
#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod engine;
pub mod pack;
