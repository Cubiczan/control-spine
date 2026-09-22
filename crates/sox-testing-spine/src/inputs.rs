//! Engine inputs — the typed SOX control-testing population: what ran, how
//! often it should have run, and the append-only history of prior testing
//! cycles. Schema-checked JSON (`deny_unknown_fields` on every type), with
//! fail-closed semantic validation: malformed or self-contradictory inputs
//! are refused, never silently coerced.
//!
//! Dates (`executed_on`) are opaque caller-supplied labels: this engine
//! performs no calendar arithmetic, so it never reads a clock.

use crate::config::Frequency;
use crate::config::RiskTier;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// One prior testing cycle, carried into the inputs as immutable history.
/// A retest after remediation starts a new cycle; it never rewrites a
/// prior one. `envelope_hash` is the prior pack's body hash — the lineage
/// pointer that keeps cycles chained.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorCycle {
    pub cycle: u32,
    pub sampled: u32,
    pub passed: u32,
    pub failed: u32,
    /// Body hash of the prior cycle's evidence pack (64 lowercase hex).
    pub envelope_hash: String,
}

/// Result of one control operation instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceResult {
    Pass,
    Fail,
}

/// One recorded operation of the control.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlInstance {
    /// Stable business key; the subject of any finding raised on this
    /// instance.
    pub instance_id: String,
    pub performed_by: String,
    /// Caller-supplied label (e.g. `2026-07-15`) — opaque to the engine.
    pub executed_on: String,
    pub result: InstanceResult,
    /// Monetary impact of the exception in integer cents. Only valid on a
    /// failed instance; a failure without one is treated as zero impact.
    pub impact_cents: Option<i128>,
    /// Identifier of a compensating control that mitigates the exception.
    /// Only valid on a failed instance.
    pub compensating_control: Option<String>,
}

/// One control-testing population for one period and cycle.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPopulation {
    pub population_id: String,
    /// Period label (e.g. `FY2026-Q3`) — opaque to the engine, part of the
    /// sampling seed.
    pub period: String,
    pub frequency: Frequency,
    pub risk_tier: RiskTier,
    /// How many times the control should have operated in the period.
    pub expected_frequency: u32,
    /// Testing cycle number, starting at 1. Must be exactly one past the
    /// last prior cycle — history is append-only.
    pub cycle: u32,
    #[serde(default)]
    pub prior_cycles: Vec<PriorCycle>,
    /// Observed operation instances for the current cycle.
    pub instances: Vec<ControlInstance>,
}

/// Input validation refusals. Fail-closed: any of these means the
/// population is malformed or its history is inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InputError {
    #[error("population_id must be non-empty")]
    EmptyPopulationId,
    #[error("period must be non-empty")]
    EmptyPeriod,
    #[error("cycle must be at least 1")]
    InvalidCycle,
    #[error("instance_id must be non-empty")]
    EmptyInstanceId,
    #[error("performed_by must be non-empty")]
    EmptyPerformedBy,
    #[error("executed_on must be non-empty")]
    EmptyExecutedOn,
    #[error("duplicate instance_id {0}: instance ids are finding subjects and sample keys")]
    DuplicateInstanceId(String),
    #[error("instance {0}: impact_cents must be non-negative")]
    NegativeImpact(String),
    #[error("instance {0}: a passed instance must not carry impact_cents or compensating_control")]
    PassCarriesExceptionFields(String),
    #[error("instance {0}: compensating_control id must be non-empty")]
    EmptyCompensatingControl(String),
    #[error("prior cycle {0}: envelope_hash must be 64 lowercase hex characters")]
    BadPriorEnvelope(u32),
    #[error(
        "prior cycles must be strictly increasing (append-only history); violation at cycle {0}"
    )]
    NonIncreasingPriorCycle(u32),
    #[error("cycle {cycle} must equal the prior cycle count + 1 (expected {expected}): retesting starts a new cycle, history is immutable")]
    DiscontinuousCycle { cycle: u32, expected: u32 },
    #[error("prior cycle {cycle}: inconsistent counts (passed {passed} + failed {failed} != sampled {sampled})")]
    InconsistentPriorCounts {
        cycle: u32,
        passed: u32,
        failed: u32,
        sampled: u32,
    },
}

fn is_envelope_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl ControlPopulation {
    /// Semantic validation of the population and its cycle history.
    pub fn validate(&self) -> Result<(), InputError> {
        if self.population_id.trim().is_empty() {
            return Err(InputError::EmptyPopulationId);
        }
        if self.period.trim().is_empty() {
            return Err(InputError::EmptyPeriod);
        }
        if self.cycle < 1 {
            return Err(InputError::InvalidCycle);
        }

        let mut previous: Option<u32> = None;
        for prior in &self.prior_cycles {
            if prior.cycle < 1 {
                return Err(InputError::InvalidCycle);
            }
            if let Some(prev) = previous {
                if prior.cycle <= prev {
                    return Err(InputError::NonIncreasingPriorCycle(prior.cycle));
                }
            }
            previous = Some(prior.cycle);
            if !is_envelope_hash(&prior.envelope_hash) {
                return Err(InputError::BadPriorEnvelope(prior.cycle));
            }
            let total = prior.passed.checked_add(prior.failed);
            if total.as_ref().map(|t| *t != prior.sampled).unwrap_or(true) {
                return Err(InputError::InconsistentPriorCounts {
                    cycle: prior.cycle,
                    passed: prior.passed,
                    failed: prior.failed,
                    sampled: prior.sampled,
                });
            }
        }
        // The current cycle must continue the history exactly: with no
        // prior cycles it is the first cycle (1); otherwise one past the
        // last recorded cycle.
        let expected = self.prior_cycles.last().map_or(1, |p| p.cycle + 1);
        if self.cycle != expected {
            return Err(InputError::DiscontinuousCycle {
                cycle: self.cycle,
                expected,
            });
        }

        let mut seen: HashSet<&str> = HashSet::new();
        for instance in &self.instances {
            if instance.instance_id.trim().is_empty() {
                return Err(InputError::EmptyInstanceId);
            }
            if !seen.insert(instance.instance_id.as_str()) {
                return Err(InputError::DuplicateInstanceId(
                    instance.instance_id.clone(),
                ));
            }
            if instance.performed_by.trim().is_empty() {
                return Err(InputError::EmptyPerformedBy);
            }
            if instance.executed_on.trim().is_empty() {
                return Err(InputError::EmptyExecutedOn);
            }
            if let Some(impact) = instance.impact_cents {
                if impact < 0 {
                    return Err(InputError::NegativeImpact(instance.instance_id.clone()));
                }
            }
            if let Some(cc) = &instance.compensating_control {
                if cc.trim().is_empty() {
                    return Err(InputError::EmptyCompensatingControl(
                        instance.instance_id.clone(),
                    ));
                }
            }
            if instance.result == InstanceResult::Pass
                && (instance.impact_cents.is_some() || instance.compensating_control.is_some())
            {
                return Err(InputError::PassCarriesExceptionFields(
                    instance.instance_id.clone(),
                ));
            }
        }
        Ok(())
    }
}
