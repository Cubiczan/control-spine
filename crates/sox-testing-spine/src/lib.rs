//! # sox-testing-spine — Internal Audit control spine
//!
//! Reproducible SOX control testing as a department product crate of the
//! control-spine family: seeded deterministic sampling, population
//! completeness checks, deficiency classification against config
//! thresholds, and evidence packs that fail closed.
//!
//! Contract, per the family architecture (spec: Department Control-Spine
//! Products, rev 2):
//!
//! * The engine is pure — no clock reads, no filesystem, no network, no
//!   unseeded randomness. Time and every business fact are inputs.
//! * Money (impact, thresholds) is integer cents (i128).
//! * Config and inputs are schema-checked JSON (serde, unknown fields
//!   refused) with fail-closed semantic validation.
//! * Evidence packs depend on the canonical [`spine`] crate by path:
//!   SHA-256 provenance hashes over the exact input/config bytes, typed
//!   findings, and a body-hash seal — [`EvidencePack::verify`] recomputes
//!   everything and refuses on any doubt.
//! * Breach findings (zero-population failure, significant deficiency,
//!   material-weakness candidate) cannot resolve without an approving
//!   signoff naming the finding's subject; the producing engine cannot
//!   countersign its own pack.
//! * Retesting after remediation starts a new cycle; prior results are
//!   immutable history carried forward, never rewritten.
//!
//! The CLI (`compute | verify | explain`) is the only place this crate
//! touches the filesystem.
//!
//! Lock lifecycle: [`compute_pack`] emits a sealed pack with no signoffs
//! (Draft); human receipts are recorded and the lock advanced to Signed via
//! [`finalize_signed`], which refuses while any finding is unresolved
//! (crosswalk: HALT). Only signed packs qualify as evidence.

pub mod config;
pub mod engine;
pub mod inputs;
pub mod sampling;

pub use config::{ConfigError, Frequency, RiskTier, SampleSizeRule, TestPlanConfig};
pub use engine::{
    classify_failure, evaluate, CycleOutcome, DeficiencyClass, EngineResult, EvaluateError, Rollup,
    RULE_COMPENSATED_EXCEPTION, RULE_COMPLETENESS_GAP, RULE_DEFICIENCY,
    RULE_MATERIAL_WEAKNESS_CANDIDATE, RULE_SIGNIFICANT_DEFICIENCY, RULE_UNEXPECTED_INSTANCES,
    RULE_ZERO_POPULATION,
};
pub use inputs::{ControlInstance, ControlPopulation, InputError, InstanceResult, PriorCycle};
pub use sampling::{rank_hex, testing_seed};

use spine::{advance_lock, sha256_hex, EvidencePack, LockError, LockState, Signoff, SPINE_VERSION};

/// Default producing-engine identity. Approving signoffs from this actor
/// are void (separation of duties: an engine cannot countersign its own
/// pack).
pub const DEFAULT_ENGINE_ID: &str = "sox-testing-spine";

/// Pack production errors.
#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("engine id must be non-empty")]
    EmptyEngineId,
    #[error("inputs JSON: {0}")]
    InputsJson(serde_json::Error),
    #[error("config JSON: {0}")]
    ConfigJson(serde_json::Error),
    #[error("{0}")]
    Evaluation(#[from] EvaluateError),
}

/// Compute the evidence pack for one control-testing population.
///
/// `inputs_bytes` and `params_bytes` are the exact canonical input/config
/// file bytes — their SHA-256 digests pin the pack's provenance, so verify
/// reproduces the run bit-for-bit. The returned pack is sealed
/// (tamper-evident) with no signoffs recorded; human receipts are attached
/// and the lock advanced to Signed via [`finalize_signed`].
pub fn compute_pack(
    inputs_bytes: &[u8],
    params_bytes: &[u8],
    engine_id: &str,
) -> Result<EvidencePack, ComputeError> {
    let engine_id = engine_id.trim();
    if engine_id.is_empty() {
        return Err(ComputeError::EmptyEngineId);
    }
    let population: ControlPopulation =
        serde_json::from_slice(inputs_bytes).map_err(ComputeError::InputsJson)?;
    let config: TestPlanConfig =
        serde_json::from_slice(params_bytes).map_err(ComputeError::ConfigJson)?;
    let result = evaluate(&population, &config)?;
    Ok(EvidencePack {
        engine_id: engine_id.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        spine_version: SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(inputs_bytes),
        params_hash: sha256_hex(params_bytes),
        findings: result.findings,
        signoffs: Vec::new(),
        body_hash: String::new(),
    }
    .sealed())
}

/// Record human signoff receipts on a freshly computed pack and advance the
/// lock lifecycle `Draft → AwaitingSignoff → Signed`.
///
/// Signing refuses while any finding requiring signoff is unresolved
/// (crosswalk: HALT). On success the pack is sealed over its final body —
/// signed packs are immutable, and a correction is a new pack computed on
/// corrected inputs with the predecessor's lineage recorded, never an edit
/// to a signed pack.
pub fn finalize_signed(
    mut pack: EvidencePack,
    signoffs: Vec<Signoff>,
) -> Result<(EvidencePack, LockState), LockError> {
    let mut state = advance_lock(LockState::Draft, &mut pack)?;
    pack.signoffs = signoffs;
    state = advance_lock(state, &mut pack)?;
    Ok((pack, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spine::{Severity, SignoffDecision, VerifyError};

    const SIGNIFICANCE: i128 = 10_000_000; // seed data: $100,000
    const MATERIALITY: i128 = 50_000_000; // seed data: $500,000

    fn config() -> TestPlanConfig {
        let mut table = Vec::new();
        for (frequency, sizes) in [
            (Frequency::Daily, (25u32, 15u32, 5u32)),
            (Frequency::Weekly, (20, 10, 4)),
            (Frequency::Monthly, (3, 3, 2)),
            (Frequency::Quarterly, (2, 2, 1)),
            (Frequency::Annual, (1, 1, 1)),
        ] {
            for (risk_tier, sample_size) in [
                (RiskTier::High, sizes.0),
                (RiskTier::Medium, sizes.1),
                (RiskTier::Low, sizes.2),
            ] {
                table.push(SampleSizeRule {
                    frequency,
                    risk_tier,
                    sample_size,
                });
            }
        }
        TestPlanConfig {
            sample_size_table: table,
            significance_threshold_cents: SIGNIFICANCE,
            materiality_threshold_cents: MATERIALITY,
        }
    }

    fn instance(id: &str, result: InstanceResult) -> ControlInstance {
        ControlInstance {
            instance_id: id.to_string(),
            performed_by: "jdoe".to_string(),
            executed_on: "2026-07-15".to_string(),
            result,
            impact_cents: None,
            compensating_control: None,
        }
    }

    fn fail_instance(id: &str, impact_cents: i128, compensating: Option<&str>) -> ControlInstance {
        ControlInstance {
            result: InstanceResult::Fail,
            impact_cents: Some(impact_cents),
            compensating_control: compensating.map(str::to_string),
            ..instance(id, InstanceResult::Fail)
        }
    }

    fn population_with(instances: Vec<ControlInstance>, expected: u32) -> ControlPopulation {
        ControlPopulation {
            population_id: "CTRL-DEMO-001".to_string(),
            period: "FY2026-Q3".to_string(),
            frequency: Frequency::Monthly,
            risk_tier: RiskTier::High,
            expected_frequency: expected,
            cycle: 1,
            prior_cycles: Vec::new(),
            instances,
        }
    }

    fn population(instances: Vec<ControlInstance>) -> ControlPopulation {
        population_with(instances, 3)
    }

    fn signoff(actor: &str, subject: &str, decision: SignoffDecision) -> Signoff {
        Signoff {
            actor: actor.to_string(),
            role: "internal-audit-director".to_string(),
            subject: subject.to_string(),
            decision,
            at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    fn bytes(v: &ControlPopulation) -> Vec<u8> {
        serde_json::to_vec(v).expect("population serialization cannot fail")
    }

    fn config_bytes(c: &TestPlanConfig) -> Vec<u8> {
        serde_json::to_vec(c).expect("config serialization cannot fail")
    }

    // --- sampling anchors -------------------------------------------------

    #[test]
    fn seed_is_sha256_of_canonical_population_and_period() {
        let seed = testing_seed("CTRL-DEMO-001", "FY2026-Q3");
        // Golden vector pinned independently with sha256sum: the hex is
        // SHA-256 over the seed's raw digest bytes (seed = SHA-256 of
        // canonical JSON `{"population_id":"CTRL-DEMO-001","period":"FY2026-Q3"}`).
        assert_eq!(
            spine::sha256_hex(&seed),
            "ac53cc0cdd9bca3beb15a08011fc958c885382ced1d19d017a52e2196c90764e"
        );
        // Same seed inputs → same seed, different inputs → different seed.
        assert_eq!(seed, testing_seed("CTRL-DEMO-001", "FY2026-Q3"));
        assert_ne!(seed, testing_seed("CTRL-DEMO-001", "FY2026-Q4"));
        assert_ne!(seed, testing_seed("CTRL-DEMO-002", "FY2026-Q3"));
    }

    #[test]
    fn sample_selection_is_order_independent_and_reproducible() {
        let cfg = config();
        let mut instances: Vec<_> = (1..=9)
            .map(|i| instance(&format!("INST-{i:03}"), InstanceResult::Pass))
            .collect();
        let first = evaluate(&population(instances.clone()), &cfg).unwrap();
        let rerun = evaluate(&population(instances.clone()), &cfg).unwrap();
        assert_eq!(first.sample, rerun.sample);
        instances.reverse();
        let reordered = evaluate(&population(instances), &cfg).unwrap();
        assert_eq!(first.sample, reordered.sample);
    }

    #[test]
    fn sample_size_comes_from_table_and_caps_at_population() {
        let cfg = config();
        // Monthly × high → 3 of 9.
        let nine: Vec<_> = (1..=9)
            .map(|i| instance(&format!("INST-{i:03}"), InstanceResult::Pass))
            .collect();
        let result = evaluate(&population(nine.clone()), &cfg).unwrap();
        assert_eq!(result.rollup.sample_size_requested, 3);
        assert_eq!(result.rollup.sampled, 3);
        // Annual × low → 1.
        let mut annual = population(nine);
        annual.frequency = Frequency::Annual;
        annual.risk_tier = RiskTier::Low;
        let result = evaluate(&annual, &cfg).unwrap();
        assert_eq!(result.rollup.sample_size_requested, 1);
        assert_eq!(result.rollup.sampled, 1);
        // Requested size caps at the observed population (daily × high → 25).
        let mut small = population(vec![instance("INST-001", InstanceResult::Pass)]);
        small.frequency = Frequency::Daily;
        small.risk_tier = RiskTier::High;
        let result = evaluate(&small, &cfg).unwrap();
        assert_eq!(result.rollup.sample_size_requested, 25);
        assert_eq!(result.rollup.sampled, 1);
    }

    // --- completeness anchors --------------------------------------------

    #[test]
    fn shortfall_below_expected_frequency_is_a_gap_finding() {
        let cfg = config();
        let instances = vec![
            instance("INST-001", InstanceResult::Pass),
            instance("INST-002", InstanceResult::Pass),
        ];
        let pop = population_with(instances, 5); // observed 2 of 5
        let result = evaluate(&pop, &cfg).unwrap();
        let gap = result
            .findings
            .iter()
            .find(|f| f.rule_id == RULE_COMPLETENESS_GAP)
            .expect("completeness gap finding required");
        assert_eq!(gap.severity, Severity::Warn);
        assert_eq!(gap.subject, "CTRL-DEMO-001");
        assert!(!gap.requires_signoff);
        assert_eq!(result.rollup.outcome, CycleOutcome::Exceptions);
        // Observed == expected → no gap finding.
        let pop = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                instance("INST-002", InstanceResult::Pass),
            ],
            2,
        );
        assert!(evaluate(&pop, &cfg)
            .unwrap()
            .findings
            .iter()
            .all(|f| f.rule_id != RULE_COMPLETENESS_GAP));
    }

    #[test]
    fn zero_instance_population_is_an_automatic_failure_finding() {
        let cfg = config();
        let pop = population_with(Vec::new(), 3);
        let result = evaluate(&pop, &cfg).unwrap();
        assert_eq!(result.findings.len(), 1);
        let finding = &result.findings[0];
        assert_eq!(finding.rule_id, RULE_ZERO_POPULATION);
        assert_eq!(finding.severity, Severity::Breach);
        assert_eq!(finding.subject, "CTRL-DEMO-001");
        assert!(finding.requires_signoff);
        assert_eq!(result.rollup.outcome, CycleOutcome::Breach);
        assert_eq!(result.rollup.sampled, 0);
        // Pack-level fail-closed: an uncountersigned breach pack refuses.
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        assert_eq!(
            pack.verify(&inputs, &params),
            Err(VerifyError::UnresolvedBreach {
                rule_id: RULE_ZERO_POPULATION.to_string()
            })
        );
    }

    #[test]
    fn unexpected_instances_when_not_scheduled_are_flagged_but_tested() {
        let cfg = config();
        let pop = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                fail_instance("INST-002", 1_000, None),
            ],
            0,
        );
        let result = evaluate(&pop, &cfg).unwrap();
        let flagged = result
            .findings
            .iter()
            .find(|f| f.rule_id == RULE_UNEXPECTED_INSTANCES)
            .expect("unexpected-instances finding required");
        assert_eq!(flagged.severity, Severity::Warn);
        // The observed instances are still sampled and classified.
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id == RULE_DEFICIENCY && f.subject == "INST-002"));
        assert_eq!(result.rollup.sampled, 2);
    }

    // --- classification anchors -------------------------------------------

    #[test]
    fn classification_threshold_boundaries_are_strictly_greater() {
        let cfg = config();
        let cases = [
            (9_999_999, None, DeficiencyClass::Deficiency),
            (SIGNIFICANCE, None, DeficiencyClass::Deficiency),
            (
                SIGNIFICANCE + 1,
                None,
                DeficiencyClass::SignificantDeficiency,
            ),
            (MATERIALITY, None, DeficiencyClass::SignificantDeficiency),
            (
                MATERIALITY + 1,
                None,
                DeficiencyClass::MaterialWeaknessCandidate,
            ),
            (
                1_000_000,
                Some("CC-7"),
                DeficiencyClass::CompensatedException,
            ),
            (
                MATERIALITY + 1,
                Some("CC-7"),
                DeficiencyClass::MaterialWeaknessCandidate,
            ),
            (0, None, DeficiencyClass::Deficiency),
        ];
        for (impact, compensating, expected) in cases {
            assert_eq!(
                classify_failure(impact, compensating, &cfg),
                expected,
                "impact {impact} with compensating {compensating:?}"
            );
        }
    }

    #[test]
    fn failed_instances_classify_end_to_end() {
        let cfg = config();
        // Deficiency: uncompensated, impact at the significance boundary.
        let pop = population_with(vec![fail_instance("INST-002", SIGNIFICANCE, None)], 1);
        let result = evaluate(&pop, &cfg).unwrap();
        let finding = &result.findings[0];
        assert_eq!(finding.rule_id, RULE_DEFICIENCY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(!finding.requires_signoff);
        // Significant deficiency: one cent over — breach, signoff required.
        let pop = population_with(vec![fail_instance("INST-002", SIGNIFICANCE + 1, None)], 1);
        let result = evaluate(&pop, &cfg).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == RULE_SIGNIFICANT_DEFICIENCY)
            .unwrap();
        assert_eq!(finding.severity, Severity::Breach);
        assert!(finding.requires_signoff);
        assert_eq!(finding.subject, "INST-002");
        // Material-weakness candidate: one cent over materiality — the
        // final label stays human, the finding still breaches.
        let pop = population_with(vec![fail_instance("INST-003", MATERIALITY + 1, None)], 1);
        let result = evaluate(&pop, &cfg).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == RULE_MATERIAL_WEAKNESS_CANDIDATE)
            .unwrap();
        assert_eq!(finding.severity, Severity::Breach);
        assert!(finding.requires_signoff);
        // Compensated exception: mitigated and below significance — info.
        let pop = population_with(vec![fail_instance("INST-004", 5_000, Some("CC-77"))], 1);
        let result = evaluate(&pop, &cfg).unwrap();
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == RULE_COMPENSATED_EXCEPTION)
            .unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert!(!finding.requires_signoff);
    }

    #[test]
    fn clean_population_produces_no_findings_and_verifies() {
        let cfg = config();
        let pop = population_with(
            (1..=3)
                .map(|i| instance(&format!("INST-{i:03}"), InstanceResult::Pass))
                .collect::<Vec<_>>(),
            3,
        );
        let result = evaluate(&pop, &cfg).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.rollup.outcome, CycleOutcome::Pass);
        assert_eq!(result.rollup.passed, 3);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        assert_eq!(pack.verify(&inputs, &params), Ok(()));
    }

    // --- evidence pack + governance anchors --------------------------------

    #[test]
    fn breach_pack_signs_and_verifies_with_subject_scoped_signoffs() {
        let cfg = config();
        let pop = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                fail_instance("INST-002", 20_000_000, None),
            ],
            2,
        );
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let (signed, state) = finalize_signed(
            pack,
            vec![signoff("sam", "INST-002", SignoffDecision::Approve)],
        )
        .unwrap();
        assert_eq!(state, LockState::Signed);
        assert_eq!(signed.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn verify_refuses_tampered_pack_body() {
        let cfg = config();
        let pop = population_with(vec![fail_instance("INST-001", 20_000_000, None)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let (mut signed, _) = finalize_signed(
            compute_pack(&inputs, &params, "audit-clerk-1").unwrap(),
            vec![signoff("sam", "INST-001", SignoffDecision::Approve)],
        )
        .unwrap();
        signed.findings[0].message = "tampered after signature".to_string();
        assert_eq!(
            signed.verify(&inputs, &params),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn verify_refuses_tampered_inputs_and_params() {
        let cfg = config();
        let pop = population_with(vec![instance("INST-001", InstanceResult::Pass)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let mut tampered_inputs = inputs.clone();
        tampered_inputs[0] ^= 0x01;
        assert_eq!(
            pack.verify(&tampered_inputs, &params),
            Err(VerifyError::HashMismatch { field: "inputs" })
        );
        let mut tampered_params = params.clone();
        tampered_params[0] ^= 0x01;
        assert_eq!(
            pack.verify(&inputs, &tampered_params),
            Err(VerifyError::HashMismatch { field: "params" })
        );
    }

    #[test]
    fn verify_refuses_unsealed_pack() {
        let cfg = config();
        let pop = population_with(vec![instance("INST-001", InstanceResult::Pass)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let unsealed = EvidencePack {
            engine_id: "audit-clerk-1".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            spine_version: spine::SPINE_VERSION.to_string(),
            inputs_hash: spine::sha256_hex(&inputs),
            params_hash: spine::sha256_hex(&params),
            findings: Vec::new(),
            signoffs: Vec::new(),
            body_hash: String::new(),
        };
        assert_eq!(
            unsealed.verify(&inputs, &params),
            Err(VerifyError::BodyHashMismatch)
        );
    }

    #[test]
    fn engine_cannot_countersign_its_own_pack() {
        let cfg = config();
        let pop = population_with(vec![fail_instance("INST-001", 20_000_000, None)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        // Approving signoff from the producing engine's actor is void.
        let attempt = finalize_signed(
            pack,
            vec![signoff(
                "audit-clerk-1",
                "INST-001",
                SignoffDecision::Approve,
            )],
        );
        assert!(matches!(
            attempt,
            Err(LockError::UnresolvedBreach { rule_id })
                if rule_id == RULE_SIGNIFICANT_DEFICIENCY
        ));
    }

    #[test]
    fn signoff_covers_only_the_subject_it_names() {
        let cfg = config();
        let pop = population_with(vec![fail_instance("INST-001", 20_000_000, None)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let attempt = finalize_signed(
            pack,
            vec![signoff(
                "sam",
                "SOME-OTHER-INSTANCE",
                SignoffDecision::Approve,
            )],
        );
        assert!(matches!(
            attempt,
            Err(LockError::UnresolvedBreach { rule_id })
                if rule_id == RULE_SIGNIFICANT_DEFICIENCY
        ));
    }

    #[test]
    fn multi_breach_packs_need_one_signoff_per_subject() {
        let cfg = config();
        let pop = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                fail_instance("INST-002", 20_000_000, None),
                fail_instance("INST-003", 60_000_000, None),
            ],
            3,
        );
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        // Only one of two breach subjects covered — still unresolved.
        let partial = finalize_signed(
            pack,
            vec![signoff("sam", "INST-002", SignoffDecision::Approve)],
        );
        assert!(partial.is_err());
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let (signed, state) = finalize_signed(
            pack,
            vec![
                signoff("sam", "INST-002", SignoffDecision::Approve),
                signoff("alex", "INST-003", SignoffDecision::Approve),
            ],
        )
        .unwrap();
        assert_eq!(state, LockState::Signed);
        assert_eq!(signed.verify(&inputs, &params), Ok(()));
    }

    #[test]
    fn lock_progression_blocks_unsigned_packs() {
        let cfg = config();
        let pop = population_with(vec![fail_instance("INST-001", 20_000_000, None)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        // No signoffs at all → signing refuses (HALT crosswalk).
        let unsigned = finalize_signed(pack, Vec::new());
        assert!(matches!(
            unsigned,
            Err(LockError::UnresolvedBreach { rule_id })
                if rule_id == RULE_SIGNIFICANT_DEFICIENCY
        ));
        // A rejecting signoff does not resolve the breach either.
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let rejected = finalize_signed(
            pack,
            vec![signoff("sam", "INST-001", SignoffDecision::Reject)],
        );
        assert!(rejected.is_err());
        // Resolved findings sign and seal; verify accepts the sealed pack.
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let (signed, state) = finalize_signed(
            pack,
            vec![signoff("sam", "INST-001", SignoffDecision::Approve)],
        )
        .unwrap();
        assert_eq!(state, LockState::Signed);
        assert!(!signed.body_hash.is_empty());
        assert_eq!(signed.verify(&inputs, &params), Ok(()));
    }

    // --- cycle history: retesting and immutability anchors ------------------

    #[test]
    fn cycle_history_is_append_only() {
        let instances = vec![instance("INST-001", InstanceResult::Pass)];
        let good_prior = PriorCycle {
            cycle: 1,
            sampled: 2,
            passed: 1,
            failed: 1,
            envelope_hash: "a".repeat(64),
        };

        // First cycle must be cycle 1.
        let mut pop = population_with(instances, 1);
        pop.cycle = 2;
        assert_eq!(
            pop.validate(),
            Err(InputError::DiscontinuousCycle {
                cycle: 2,
                expected: 1
            })
        );
        // Retest continues the history exactly one past the last cycle.
        pop.cycle = 2;
        pop.prior_cycles = vec![good_prior.clone()];
        assert!(pop.validate().is_ok());
        pop.cycle = 3; // gap: skipping a cycle rewrites history
        assert_eq!(
            pop.validate(),
            Err(InputError::DiscontinuousCycle {
                cycle: 3,
                expected: 2
            })
        );
        pop.cycle = 2;
        pop.prior_cycles = vec![good_prior.clone(), good_prior.clone()]; // duplicate
        assert_eq!(pop.validate(), Err(InputError::NonIncreasingPriorCycle(1)));
        pop.prior_cycles = vec![PriorCycle {
            envelope_hash: "XYZ".to_string(),
            ..good_prior.clone()
        }];
        assert_eq!(pop.validate(), Err(InputError::BadPriorEnvelope(1)));
        pop.prior_cycles = vec![PriorCycle {
            sampled: 5,
            passed: 3,
            failed: 1,
            ..good_prior
        }];
        assert_eq!(
            pop.validate(),
            Err(InputError::InconsistentPriorCounts {
                cycle: 1,
                passed: 3,
                failed: 1,
                sampled: 5
            })
        );
    }

    #[test]
    fn retest_starts_a_new_cycle_and_prior_packs_stay_immutable() {
        let cfg = config();
        let pop1 = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                fail_instance("INST-002", 20_000_000, None),
            ],
            2,
        );
        let inputs1 = bytes(&pop1);
        let params = config_bytes(&cfg);
        let pack1 = compute_pack(&inputs1, &params, "audit-clerk-1").unwrap();
        let (signed1, _) = finalize_signed(
            pack1,
            vec![signoff("sam", "INST-002", SignoffDecision::Approve)],
        )
        .unwrap();

        // Retest after remediation: a new cycle chained to the prior pack's
        // body hash, with fresh facts — a new pack, never an edit.
        let mut pop2 = pop1.clone();
        pop2.cycle = 2;
        pop2.prior_cycles = vec![PriorCycle {
            cycle: 1,
            sampled: 2,
            passed: 1,
            failed: 1,
            envelope_hash: signed1.body_hash.clone(),
        }];
        pop2.instances[1].result = InstanceResult::Pass; // remediated
        pop2.instances[1].impact_cents = None;
        let inputs2 = bytes(&pop2);
        let pack2 = compute_pack(&inputs2, &params, "audit-clerk-1").unwrap();
        assert_ne!(pack2.inputs_hash, signed1.inputs_hash);
        assert_ne!(pack2.body_hash, signed1.body_hash);
        assert!(pack2.findings.is_empty());
        // Prior cycle's signed pack still verifies unchanged — immutability.
        assert_eq!(signed1.verify(&inputs1, &params), Ok(()));
    }

    // --- input and config schema anchors ------------------------------------

    #[test]
    fn malformed_inputs_are_refused() {
        // Duplicate instance ids.
        let dup = population_with(
            vec![
                instance("INST-001", InstanceResult::Pass),
                instance("INST-001", InstanceResult::Pass),
            ],
            1,
        );
        assert_eq!(
            dup.validate(),
            Err(InputError::DuplicateInstanceId("INST-001".to_string()))
        );
        // A pass must not carry exception fields.
        let mut carry = instance("INST-001", InstanceResult::Pass);
        carry.impact_cents = Some(100);
        assert_eq!(
            population_with(vec![carry], 1).validate(),
            Err(InputError::PassCarriesExceptionFields(
                "INST-001".to_string()
            ))
        );
        // Negative impact is refused outright.
        assert_eq!(
            population_with(vec![fail_instance("INST-001", -1, None)], 1).validate(),
            Err(InputError::NegativeImpact("INST-001".to_string()))
        );
        // Empty compensating control id on a failure.
        assert_eq!(
            population_with(vec![fail_instance("INST-001", 1, Some(" "))], 1).validate(),
            Err(InputError::EmptyCompensatingControl("INST-001".to_string()))
        );
        // Unknown fields are refused at the schema boundary.
        let json = r#"{
            "population_id": "C", "period": "P", "frequency": "monthly",
            "risk_tier": "high", "expected_frequency": 1, "cycle": 1,
            "instances": [], "surprise_field": true
        }"#;
        let parsed: Result<ControlPopulation, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
        // Expected-0/observed-0 runs clean with no findings.
        let cfg = config();
        let empty = population_with(Vec::new(), 0);
        assert!(evaluate(&empty, &cfg).unwrap().findings.is_empty());
    }

    #[test]
    fn config_validation_refusals() {
        let base = config();
        // Incomplete matrix: drop one row.
        let mut incomplete = base.clone();
        incomplete.sample_size_table.pop();
        assert_eq!(
            incomplete.validate(),
            Err(ConfigError::IncompleteMatrix {
                rows: 14,
                expected: 15
            })
        );
        // Duplicate row.
        let mut duplicated = base.clone();
        let last = *duplicated.sample_size_table.last().unwrap();
        duplicated.sample_size_table.push(last);
        assert_eq!(
            duplicated.validate(),
            Err(ConfigError::DuplicateSampleRule {
                frequency: last.frequency,
                risk_tier: last.risk_tier
            })
        );
        // Zero sample size.
        let mut zeroed = base.clone();
        zeroed.sample_size_table[0].sample_size = 0;
        assert!(matches!(
            zeroed.validate(),
            Err(ConfigError::ZeroSampleSize { .. })
        ));
        // Threshold ordering.
        let mut ordered = base.clone();
        ordered.materiality_threshold_cents = ordered.significance_threshold_cents;
        assert_eq!(
            ordered.validate(),
            Err(ConfigError::ThresholdOrdering {
                significance: SIGNIFICANCE,
                materiality: SIGNIFICANCE
            })
        );
        // Zero significance threshold.
        let mut zero_threshold = base;
        zero_threshold.significance_threshold_cents = 0;
        assert_eq!(
            zero_threshold.validate(),
            Err(ConfigError::ZeroSignificanceThreshold)
        );
        // Unknown config field refused at the schema boundary.
        let json = r#"{"sample_size_table": [], "significance_threshold_cents": 1,
                       "materiality_threshold_cents": 2, "extra": 1}"#;
        let parsed: Result<TestPlanConfig, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn pack_json_roundtrip_preserves_verification() {
        let cfg = config();
        let pop = population_with(vec![instance("INST-001", InstanceResult::Pass)], 1);
        let inputs = bytes(&pop);
        let params = config_bytes(&cfg);
        let pack = compute_pack(&inputs, &params, "audit-clerk-1").unwrap();
        let json = serde_json::to_string(&pack).unwrap();
        let reparsed: EvidencePack = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed.verify(&inputs, &params), Ok(()));
        assert_eq!(reparsed.engine_id, "audit-clerk-1");
        assert_eq!(reparsed.spine_version, spine::SPINE_VERSION);
        assert_eq!(reparsed.tool_version, env!("CARGO_PKG_VERSION"));
    }
}
