//! Pure engine for reproducible SOX control testing.
//!
//! Purity contract (family rule): no clock reads, no filesystem, no
//! network, no unseeded randomness; every business fact — including time —
//! arrives through the caller's inputs. Money (impact, thresholds) is
//! integer cents (i128).
//!
//! Rules, in evaluation order:
//!
//! 1. **Zero population** — expected frequency > 0 with no observed
//!    instances means the control did not operate at all: an automatic
//!    failure finding (`SOX-002`, breach severity, signoff required).
//! 2. **Completeness** — observed below expected is a gap finding
//!    (`SOX-001`, warn); a control not scheduled for the period but with
//!    observed instances is flagged (`SOX-020`, warn) and its instances are
//!    still tested.
//! 3. **Seeded sampling** — sample size from the config table
//!    (frequency × risk tier); selection per [`crate::sampling`].
//! 4. **Classification** — deterministic thresholds per failed instance:
//!    impact over external materiality → material-weakness candidate
//!    (`SOX-012`, breach, final label stays human); over the significance
//!    threshold → significant deficiency (`SOX-011`, breach); otherwise
//!    failure without a compensating control → deficiency (`SOX-010`,
//!    warn); with one → compensated exception (`SOX-013`, info).

use crate::config::TestPlanConfig;
use crate::inputs::{ControlInstance, ControlPopulation, InstanceResult};
use crate::sampling::{select_sample, testing_seed};
use spine::{Finding, Severity};
use thiserror::Error;

pub const RULE_COMPLETENESS_GAP: &str = "SOX-001";
pub const RULE_ZERO_POPULATION: &str = "SOX-002";
pub const RULE_DEFICIENCY: &str = "SOX-010";
pub const RULE_SIGNIFICANT_DEFICIENCY: &str = "SOX-011";
pub const RULE_MATERIAL_WEAKNESS_CANDIDATE: &str = "SOX-012";
pub const RULE_COMPENSATED_EXCEPTION: &str = "SOX-013";
pub const RULE_UNEXPECTED_INSTANCES: &str = "SOX-020";

/// Engine evaluation errors: the config or inputs were never validated.
/// `MissingSampleSize` is unreachable for a validated config (the table is
/// required to be a full matrix) but is typed rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvaluateError {
    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("inputs: {0}")]
    Input(#[from] crate::inputs::InputError),
    #[error("no sample size configured for {frequency:?} x {risk_tier:?}")]
    MissingSampleSize {
        frequency: crate::config::Frequency,
        risk_tier: crate::config::RiskTier,
    },
}

/// Deterministic classification of one failed control instance. Precedence
/// is fixed: impact above materiality dominates, then impact above the
/// significance threshold; the compensating-control distinction applies
/// only at or below significance — a compensating control never downgrades
/// an impact over materiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeficiencyClass {
    Deficiency,
    SignificantDeficiency,
    MaterialWeaknessCandidate,
    CompensatedException,
}

/// Outcome of the testing cycle's roll-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    Pass,
    Exceptions,
    Breach,
}

/// Deterministic roll-up of one testing cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollup {
    pub expected_frequency: u32,
    pub observed_instances: u32,
    pub sample_size_requested: u32,
    pub sampled: u32,
    pub passed: u32,
    pub failed: u32,
    pub outcome: CycleOutcome,
}

/// The pure engine result: findings (in evaluation order — deterministic),
/// the selected sample in selection order, and the roll-up.
#[derive(Debug, Clone)]
pub struct EngineResult {
    pub findings: Vec<Finding>,
    pub sample: Vec<String>,
    pub rollup: Rollup,
}

/// Validate config and inputs, then run the engine. This is the one public
/// entry point; both sides are checked so no rule ever runs on
/// unvalidated data.
pub fn evaluate(
    population: &ControlPopulation,
    config: &TestPlanConfig,
) -> Result<EngineResult, EvaluateError> {
    config.validate()?;
    population.validate()?;
    let sample_size = config
        .sample_size(population.frequency, population.risk_tier)
        .ok_or(EvaluateError::MissingSampleSize {
            frequency: population.frequency,
            risk_tier: population.risk_tier,
        })?;
    Ok(run(population, config, sample_size))
}

fn run(population: &ControlPopulation, config: &TestPlanConfig, sample_size: u32) -> EngineResult {
    let observed = population.instances.len() as u32;

    // Zero-instance population with an expected frequency: the control was
    // not performed at all — automatic failure, no sampling to do.
    if population.expected_frequency > 0 && observed == 0 {
        return EngineResult {
            findings: vec![Finding::breach(
                RULE_ZERO_POPULATION,
                &population.population_id,
                format!(
                    "control not performed at all: 0 of expected {} instance(s) observed in period {}",
                    population.expected_frequency, population.period
                ),
            )],
            sample: Vec::new(),
            rollup: Rollup {
                expected_frequency: population.expected_frequency,
                observed_instances: 0,
                sample_size_requested: sample_size,
                sampled: 0,
                passed: 0,
                failed: 0,
                outcome: CycleOutcome::Breach,
            },
        };
    }

    let mut findings: Vec<Finding> = Vec::new();
    if population.expected_frequency == 0 && observed > 0 {
        findings.push(Finding {
            rule_id: RULE_UNEXPECTED_INSTANCES.into(),
            severity: Severity::Warn,
            subject: population.population_id.clone(),
            message: format!(
                "control not scheduled for period (expected 0 instances) but {observed} instance(s) observed"
            ),
            requires_signoff: false,
        });
    } else if observed < population.expected_frequency {
        findings.push(Finding {
            rule_id: RULE_COMPLETENESS_GAP.into(),
            severity: Severity::Warn,
            subject: population.population_id.clone(),
            message: format!(
                "population completeness gap: expected {} instance(s), observed {observed}",
                population.expected_frequency
            ),
            requires_signoff: false,
        });
    }

    let take = sample_size.min(observed) as usize;
    let seed = testing_seed(&population.population_id, &population.period);
    let sampled = select_sample(&population.instances, take, seed);

    let mut passed = 0u32;
    let mut failed = 0u32;
    for instance in &sampled {
        match instance.result {
            InstanceResult::Pass => passed += 1,
            InstanceResult::Fail => {
                failed += 1;
                let class = classify_failure(
                    instance.impact_cents.unwrap_or(0),
                    instance.compensating_control.as_deref(),
                    config,
                );
                findings.push(finding_for_failure(instance, class, config));
            }
        }
    }

    let outcome = if findings.iter().any(|f| f.severity == Severity::Breach) {
        CycleOutcome::Breach
    } else if findings.iter().any(|f| f.severity == Severity::Warn) {
        CycleOutcome::Exceptions
    } else {
        CycleOutcome::Pass
    };

    EngineResult {
        findings,
        sample: sampled.iter().map(|i| i.instance_id.clone()).collect(),
        rollup: Rollup {
            expected_frequency: population.expected_frequency,
            observed_instances: observed,
            sample_size_requested: sample_size,
            sampled: sampled.len() as u32,
            passed,
            failed,
            outcome,
        },
    }
}

/// Classification ladder for one failed instance. "Over" is strictly
/// greater than the threshold, so each boundary itself stays in the lower
/// class — the exact boundary behavior the test anchors pin.
pub fn classify_failure(
    impact_cents: i128,
    compensating_control: Option<&str>,
    config: &TestPlanConfig,
) -> DeficiencyClass {
    if impact_cents > config.materiality_threshold_cents {
        DeficiencyClass::MaterialWeaknessCandidate
    } else if impact_cents > config.significance_threshold_cents {
        DeficiencyClass::SignificantDeficiency
    } else if compensating_control.is_none() {
        DeficiencyClass::Deficiency
    } else {
        DeficiencyClass::CompensatedException
    }
}

fn finding_for_failure(
    instance: &ControlInstance,
    class: DeficiencyClass,
    config: &TestPlanConfig,
) -> Finding {
    let impact = instance.impact_cents.unwrap_or(0);
    match class {
        DeficiencyClass::MaterialWeaknessCandidate => {
            let compensated = instance
                .compensating_control
                .as_deref()
                .map(|c| {
                    format!("; compensating control {c} recorded — it does not reduce a classification above materiality")
                })
                .unwrap_or_default();
            Finding::breach(
                RULE_MATERIAL_WEAKNESS_CANDIDATE,
                &instance.instance_id,
                format!(
                    "impact {impact} cents exceeds external materiality threshold {} cents; classified material-weakness candidate — the final label is a human determination{compensated}",
                    config.materiality_threshold_cents
                ),
            )
        }
        DeficiencyClass::SignificantDeficiency => Finding::breach(
            RULE_SIGNIFICANT_DEFICIENCY,
            &instance.instance_id,
            format!(
                "impact {impact} cents exceeds significance threshold {} cents; classified significant deficiency — human signoff required",
                config.significance_threshold_cents
            ),
        ),
        DeficiencyClass::Deficiency => Finding {
            rule_id: RULE_DEFICIENCY.into(),
            severity: Severity::Warn,
            subject: instance.instance_id.clone(),
            message: format!(
                "control exception without compensating control; impact {impact} cents at or below significance threshold {} cents; classified deficiency",
                config.significance_threshold_cents
            ),
            requires_signoff: false,
        },
        DeficiencyClass::CompensatedException => {
            let cc = instance.compensating_control.as_deref().unwrap_or("-");
            Finding {
                rule_id: RULE_COMPENSATED_EXCEPTION.into(),
                severity: Severity::Info,
                subject: instance.instance_id.clone(),
                message: format!(
                    "control exception compensated by {cc}; impact {impact} cents at or below significance threshold {} cents",
                    config.significance_threshold_cents
                ),
                requires_signoff: false,
            }
        }
    }
}
