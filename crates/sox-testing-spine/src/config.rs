//! Test-plan configuration — the `params` side of the evidence contract:
//! the sample-size table keyed by control frequency × risk tier, plus the
//! deterministic deficiency-classification thresholds.
//!
//! Config tables are schema-checked JSON: unknown fields are refused
//! (`deny_unknown_fields`), every frequency × risk tier combination must
//! appear exactly once (the table is a total function, so a lookup can
//! never silently fall back), and the thresholds must be ordered. Values
//! shipped in the crate README are SEED DATA — illustrative defaults, not
//! audited or regulatory figures.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// How often a control operates in a period. Serialized snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Annual,
}

/// Engagement risk tier of a control. Serialized snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

/// The sample-size table must cover every frequency × risk tier exactly
/// once (5 × 3): a missing combination would force a silent fallback, a
/// duplicate would make the sample ambiguous — both are refused.
pub const EXPECTED_TABLE_ROWS: usize = 15;

/// One cell of the sample-size table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SampleSizeRule {
    pub frequency: Frequency,
    pub risk_tier: RiskTier,
    /// Minimum instances to test in the cycle; must be at least 1.
    pub sample_size: u32,
}

/// Test-plan configuration for one SOX control-testing engagement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestPlanConfig {
    pub sample_size_table: Vec<SampleSizeRule>,
    /// Impact strictly above this (integer cents) upgrades an exception to a
    /// significant deficiency.
    pub significance_threshold_cents: i128,
    /// Impact strictly above this (integer cents) upgrades an exception to a
    /// material-weakness candidate. Must exceed the significance threshold.
    pub materiality_threshold_cents: i128,
}

/// Config validation refusals. All are fail-closed: an invalid table or
/// threshold pair never runs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("sample size must be at least 1 for {frequency:?} x {risk_tier:?}")]
    ZeroSampleSize {
        frequency: Frequency,
        risk_tier: RiskTier,
    },
    #[error("duplicate sample size rule for {frequency:?} x {risk_tier:?}")]
    DuplicateSampleRule {
        frequency: Frequency,
        risk_tier: RiskTier,
    },
    #[error("sample size table must cover every frequency x risk tier exactly once: found {rows} rows, expected {expected}")]
    IncompleteMatrix { rows: usize, expected: usize },
    #[error("significance threshold must be at least 1 cent")]
    ZeroSignificanceThreshold,
    #[error(
        "materiality threshold ({materiality} cents) must exceed significance threshold ({significance} cents)"
    )]
    ThresholdOrdering {
        significance: i128,
        materiality: i128,
    },
}

impl TestPlanConfig {
    /// Semantic validation: full matrix exactly once, sizes >= 1, ordered
    /// thresholds. Call before any engine run; [`crate::evaluate`] does.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::new();
        for rule in &self.sample_size_table {
            if rule.sample_size < 1 {
                return Err(ConfigError::ZeroSampleSize {
                    frequency: rule.frequency,
                    risk_tier: rule.risk_tier,
                });
            }
            if !seen.insert((rule.frequency, rule.risk_tier)) {
                return Err(ConfigError::DuplicateSampleRule {
                    frequency: rule.frequency,
                    risk_tier: rule.risk_tier,
                });
            }
        }
        if seen.len() != EXPECTED_TABLE_ROWS {
            return Err(ConfigError::IncompleteMatrix {
                rows: seen.len(),
                expected: EXPECTED_TABLE_ROWS,
            });
        }
        if self.significance_threshold_cents < 1 {
            return Err(ConfigError::ZeroSignificanceThreshold);
        }
        if self.materiality_threshold_cents <= self.significance_threshold_cents {
            return Err(ConfigError::ThresholdOrdering {
                significance: self.significance_threshold_cents,
                materiality: self.materiality_threshold_cents,
            });
        }
        Ok(())
    }

    /// Sample size for a control frequency × risk tier. `None` only for a
    /// config that never validated (the table is required to be total).
    pub fn sample_size(&self, frequency: Frequency, risk_tier: RiskTier) -> Option<u32> {
        self.sample_size_table
            .iter()
            .find(|r| r.frequency == frequency && r.risk_tier == risk_tier)
            .map(|r| r.sample_size)
    }
}
