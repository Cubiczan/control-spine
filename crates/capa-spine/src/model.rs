//! Typed input records for capa-spine.
//!
//! These types are the schema-checked JSON contract between the caller and
//! the engine: every field is explicit, unknown fields are refused, and time
//! enters only as ordinary caller-supplied data — never a clock read.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Nonconformance category — one axis of the severity matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Safety,
    Regulatory,
    Quality,
}

impl Category {
    /// Every category, for matrix completeness validation.
    pub const ALL: [Category; 3] = [Category::Safety, Category::Regulatory, Category::Quality];

    pub fn label(self) -> &'static str {
        match self {
            Category::Safety => "safety",
            Category::Regulatory => "regulatory",
            Category::Quality => "quality",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How readily the nonconformance is caught before it escapes — the other
/// severity-matrix axis. Lower detectability drives higher severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detectability {
    High,
    Medium,
    Low,
}

impl Detectability {
    /// Every level, for matrix completeness validation.
    pub const ALL: [Detectability; 3] = [
        Detectability::High,
        Detectability::Medium,
        Detectability::Low,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Detectability::High => "high",
            Detectability::Medium => "medium",
            Detectability::Low => "low",
        }
    }
}

impl fmt::Display for Detectability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Lifecycle status as recorded by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Closed,
}

/// Effectiveness-verification record for a CAPA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivenessCheck {
    pub completed: bool,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

/// One CAPA record as consumed by the engine. All timestamps are
/// caller-supplied data; the engine never reads a clock.
///
/// Enforced invariant: `id` is unique within the population — the engine
/// refuses a population where an id appears more than once, because findings
/// and signoff receipts are keyed by subject and one receipt must evidence
/// exactly one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapaRecord {
    pub id: String,
    pub description: String,
    pub category: Category,
    pub detectability: Detectability,
    /// When the CAPA was opened — the anchor for containment and aging clocks.
    pub opened_at: DateTime<Utc>,
    #[serde(default)]
    pub containment_recorded_at: Option<DateTime<Utc>>,
    pub status: Status,
    /// Effective closure date; required for a closure to be honored.
    #[serde(default)]
    pub closed_at: Option<DateTime<Utc>>,
    /// Root-cause narrative; required (non-empty) for a closure to be honored.
    #[serde(default)]
    pub root_cause: Option<String>,
    #[serde(default)]
    pub effectiveness_check: Option<EffectivenessCheck>,
    /// Parent cycle for a reopened CAPA: a reopen is a new cycle linked to
    /// its parent, with fresh clocks anchored at this record's `opened_at`.
    #[serde(default)]
    pub parent_id: Option<String>,
}
