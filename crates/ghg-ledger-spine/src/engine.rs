//! The pure inventory engine: fixed-point arithmetic, no clock, no
//! filesystem, no network, no RNG. Everything is a function of the explicit
//! inputs — the caller supplies the period, the config carries the rule
//! tables, and every output line carries the factor version it used.

use crate::model::{
    method_tag, scaled_cmp, scaled_sub, ActivityInputs, ActivityRecord, FactorRow, GhgConfig,
    Method, Scaled, Scope, MAX_SCALE,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RULE_INPUT_INVALID: &str = "GHG-INPUT-INVALID";
pub const RULE_INPUT_DUPLICATE: &str = "GHG-INPUT-DUPLICATE";
pub const RULE_FACTOR_MISSING: &str = "GHG-FACTOR-MISSING";
pub const RULE_SCOPE3_UNMAPPED: &str = "GHG-SCOPE3-UNMAPPED";
pub const RULE_SCOPE2_DIVERGENCE: &str = "GHG-SCOPE2-DIVERGENCE";

/// In-pack disclosure label carried on every market-based Scope 2 line. The
/// market-based method models quantity-level contractual coverage only —
/// residual-mix factors are not modeled (see the crate README, Honest
/// claims). Carrying the limitation on the line itself keeps the pack
/// self-describing without the README at hand.
pub const MARKET_SCOPE2_DISCLOSURE: &str =
    "market-based scope 2: figure covers contractual instruments only and excludes residual-mix factors";

/// One computed emission line. `factor_version` + `factor` are the lineage
/// contract: the exact versioned factor row used, recorded per line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmissionLine {
    pub record_id: String,
    pub scope: u8,
    /// `Some` only for Scope 2 dual-method lines.
    pub method: Option<Method>,
    /// `Some` only for Scope 3 lines (category 1–15 from config).
    pub scope3_category: Option<u8>,
    pub activity: String,
    pub region: String,
    pub year: i32,
    pub canonical_unit: String,
    pub canonical_quantity: Scaled,
    pub factor_version: String,
    pub factor: Scaled,
    /// Grams CO2e, rounded half-up from the exact product.
    pub emission_grams: i64,
    /// Data-quality confidence label from the config tiers.
    pub confidence: String,
    /// Disclosure label: `Some` only on market-based Scope 2 lines — the
    /// figure covers contractual instruments only and excludes residual-mix
    /// factors (see [`MARKET_SCOPE2_DISCLOSURE`]). `None` elsewhere.
    pub disclosure: Option<String>,
}

/// A restatement delta for one ledger key: current minus prior. Prior
/// periods are never overwritten — a restatement is a new pack that records
/// its predecessor's lineage and the deltas it introduces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestatementDelta {
    pub ledger_key: String,
    pub prior_grams: i64,
    pub current_grams: i64,
    pub delta_grams: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestatementBlock {
    pub reason: String,
    /// Body (envelope) hash of the predecessor pack — its identity for
    /// lineage references.
    pub predecessor_body_hash: String,
    pub predecessor_inputs_hash: String,
    pub deltas: Vec<RestatementDelta>,
}

/// Engine output before pack assembly: the lines and the findings. Compared
/// through canonical JSON bytes (spine findings do not implement `Eq`).
#[derive(Debug, Clone)]
pub struct ComputedInventory {
    pub lines: Vec<EmissionLine>,
    pub findings: Vec<spine::Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComputeError {
    #[error("failed to parse {what}: {message}")]
    Parse { what: &'static str, message: String },
    #[error("config schema violation: {0}")]
    ConfigSchema(String),
    #[error("restatement refused: {0}")]
    Restatement(String),
    #[error("arithmetic overflow: {0}")]
    Arithmetic(String),
}

/// Parse and canonicalize JSON bytes: sorted keys, compact. This is the
/// canonical byte form that provenance hashes are taken over, so equal data
/// in different key order or whitespace hashes identically.
pub fn canonical_json(bytes: &[u8], what: &'static str) -> Result<Vec<u8>, ComputeError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ComputeError::Parse {
            what,
            message: e.to_string(),
        })?;
    serde_json::to_vec(&value).map_err(|e| ComputeError::Parse {
        what,
        message: format!("canonicalization failed: {e}"),
    })
}

/// Exact product of two fixed-point values rounded half-up to an integer.
/// Inputs are non-negative (validated upstream), so half-up means ties go
/// up. Returns an error instead of ever rounding through floats.
pub fn mul_round_half_up(q: i64, f: i64, frac_pow: u32) -> Result<i64, ComputeError> {
    if frac_pow > 2 * MAX_SCALE {
        return Err(ComputeError::Arithmetic(format!(
            "scale {frac_pow} exceeds bound"
        )));
    }
    let num = (q as i128) * (f as i128);
    let d = 10i128
        .checked_pow(frac_pow)
        .ok_or_else(|| ComputeError::Arithmetic(format!("scale {frac_pow} too large")))?;
    let quotient = num / d;
    let rem = num % d;
    let rounded = if rem * 2 >= d { quotient + 1 } else { quotient };
    i64::try_from(rounded).map_err(|_| ComputeError::Arithmetic("result exceeds i64".into()))
}

/// Emission in grams for a canonical quantity and a factor row.
fn emission_grams(quantity: &Scaled, factor: &FactorRow) -> Result<i64, ComputeError> {
    mul_round_half_up(
        quantity.value,
        factor.factor.value,
        quantity.scale + factor.factor.scale,
    )
}

/// Factor lookup: exact key match (activity, unit, region, year, method).
/// No silent fallback to other years or regions — a miss is a gap finding.
fn find_factor<'a>(
    config: &'a GhgConfig,
    activity: &str,
    unit: &str,
    region: &str,
    year: i32,
    method: Option<Method>,
) -> Option<&'a FactorRow> {
    config.factors.iter().find(|f| {
        f.activity == activity
            && f.unit == unit
            && f.region == region
            && f.year == year
            && f.method == method
    })
}

/// Unit conversion happens once, here, at the boundary. A unit with no
/// conversion row passes through unchanged; the engine interior is canonical.
fn canonicalize_quantity(
    record: &ActivityRecord,
    config: &GhgConfig,
) -> Result<(Scaled, String), ComputeError> {
    match config
        .conversions
        .iter()
        .find(|c| c.from_unit == record.unit)
    {
        Some(c) => {
            let raw = (record.quantity.value as i128) * (c.factor.value as i128);
            let value = i64::try_from(raw)
                .map_err(|_| ComputeError::Arithmetic(format!("record {}", record.record_id)))?;
            Ok((
                Scaled {
                    value,
                    scale: record.quantity.scale + c.factor.scale,
                },
                c.to_unit.clone(),
            ))
        }
        None => Ok((record.quantity, record.unit.clone())),
    }
}

/// Confidence label for a line: the first DQ tier whose min_score the record
/// clears. Records without a score report `not_reported`.
pub fn confidence_label(dq_score: Option<i64>, config: &GhgConfig) -> String {
    let score = match dq_score {
        Some(s) => s,
        None => return "not_reported".to_string(),
    };
    config
        .dq_tiers
        .iter()
        .find(|t| score >= t.min_score)
        .map(|t| t.label.clone())
        .unwrap_or_else(|| "not_reported".to_string())
}

/// Input-shape validation. Any violation is a breach-severity gap finding on
/// the record's subject — fail-closed, the record never produces a line.
fn input_shape_finding(record: &ActivityRecord) -> Option<spine::Finding> {
    let subject = record.record_id.clone();
    if record.quantity.value <= 0 {
        return Some(spine::Finding::breach(
            RULE_INPUT_INVALID,
            subject,
            format!("quantity must be positive, got {}", record.quantity.value),
        ));
    }
    if record.quantity.scale > MAX_SCALE {
        return Some(spine::Finding::breach(
            RULE_INPUT_INVALID,
            subject,
            format!("quantity scale exceeds {MAX_SCALE}"),
        ));
    }
    if let Some(score) = record.dq_score {
        if !(0..=100).contains(&score) {
            return Some(spine::Finding::breach(
                RULE_INPUT_INVALID,
                subject,
                format!("dq_score {score} outside 0..=100"),
            ));
        }
    }
    if let Some(covered) = record.market_covered {
        if record.scope != Scope::Scope2 {
            return Some(spine::Finding::breach(
                RULE_INPUT_INVALID,
                subject,
                "market_covered is only valid on scope 2 records".to_string(),
            ));
        }
        if covered.value <= 0 || covered.scale > MAX_SCALE {
            return Some(spine::Finding::breach(
                RULE_INPUT_INVALID,
                subject,
                format!("market_covered must be positive with scale <= {MAX_SCALE}"),
            ));
        }
        if scaled_cmp(covered, record.quantity) == std::cmp::Ordering::Greater {
            return Some(spine::Finding::breach(
                RULE_INPUT_INVALID,
                subject,
                "market_covered exceeds the record quantity".to_string(),
            ));
        }
    }
    None
}

fn scope3_category(config: &GhgConfig, activity: &str) -> Option<u8> {
    config
        .scope3_categories
        .iter()
        .find(|c| c.activities.iter().any(|a| a == activity))
        .map(|c| c.category)
}

fn line_sort_key(line: &EmissionLine) -> (String, Option<Method>, Option<u8>) {
    (line.record_id.clone(), line.method, line.scope3_category)
}

/// Ledger key for a line: the append-only ledger aggregates by these keys.
pub fn ledger_key(line: &EmissionLine) -> String {
    match line.scope {
        1 => "scope1".to_string(),
        2 => format!(
            "scope2:{}",
            line.method.map(|m| m.as_tag()).unwrap_or("location")
        ),
        _ => format!("scope3:cat-{}", line.scope3_category.unwrap_or(0)),
    }
}

/// Sum emissions per ledger key (deterministic BTreeMap order).
pub fn ledger_totals(lines: &[EmissionLine]) -> Result<BTreeMap<String, i64>, ComputeError> {
    let mut totals: BTreeMap<String, i128> = BTreeMap::new();
    for line in lines {
        let key = ledger_key(line);
        let entry = totals.entry(key).or_insert(0);
        *entry = entry
            .checked_add(line.emission_grams as i128)
            .ok_or_else(|| ComputeError::Arithmetic("ledger total overflow".into()))?;
    }
    totals
        .into_iter()
        .map(|(k, v)| {
            i64::try_from(v)
                .map(|v| (k, v))
                .map_err(|_| ComputeError::Arithmetic("ledger total exceeds i64".into()))
        })
        .collect()
}

/// Compute the inventory (lines + findings) from validated inputs and config.
/// Deterministic: output order is sorted, never input order.
pub fn compute_inventory(
    inputs: &ActivityInputs,
    config: &GhgConfig,
) -> Result<ComputedInventory, ComputeError> {
    let mut lines = Vec::new();
    let mut findings: Vec<spine::Finding> = Vec::new();
    let mut scope2_factor_gap = false;

    // Duplicate record ids make the population ambiguous: two records share
    // an identity but may carry different quantities, so "keep the first" is
    // an order-dependent guess. The whole input set is refused instead —
    // fail-closed, never a partial inventory over a defective population.
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut duplicates = false;
    for record in &inputs.records {
        if !seen_ids.insert(record.record_id.as_str()) {
            duplicates = true;
            findings.push(spine::Finding::breach(
                RULE_INPUT_DUPLICATE,
                record.record_id.clone(),
                "duplicate record_id; the input set is refused, no lines computed".to_string(),
            ));
        }
    }
    if duplicates {
        return Ok(ComputedInventory { lines, findings });
    }

    for record in &inputs.records {
        if let Some(f) = input_shape_finding(record) {
            findings.push(f);
            continue;
        }

        let (quantity, canonical_unit) = canonicalize_quantity(record, config)?;

        match record.scope {
            Scope::Scope1 => {
                let factor = find_factor(
                    config,
                    &record.activity,
                    &canonical_unit,
                    &record.region,
                    record.year,
                    None,
                );
                match factor {
                    Some(row) => lines.push(build_line(
                        record,
                        config,
                        None,
                        None,
                        quantity,
                        canonical_unit,
                        row,
                    )?),
                    None => findings.push(factor_missing(record, method_tag(None))),
                }
            }
            Scope::Scope2 => {
                let covered = record.market_covered.unwrap_or(Scaled {
                    value: 0,
                    scale: quantity.scale,
                });
                let uncovered = scaled_sub(quantity, covered).ok_or_else(|| {
                    ComputeError::Arithmetic(format!(
                        "record {}: uncovered quantity",
                        record.record_id
                    ))
                })?;

                let location = find_factor(
                    config,
                    &record.activity,
                    &canonical_unit,
                    &record.region,
                    record.year,
                    Some(Method::Location),
                );
                match location {
                    Some(row) => lines.push(build_line(
                        record,
                        config,
                        Some(Method::Location),
                        None,
                        quantity,
                        canonical_unit.clone(),
                        row,
                    )?),
                    None => {
                        scope2_factor_gap = true;
                        findings.push(factor_missing(record, "location"));
                    }
                }

                let market = find_factor(
                    config,
                    &record.activity,
                    &canonical_unit,
                    &record.region,
                    record.year,
                    Some(Method::Market),
                );
                match market {
                    Some(row) => lines.push(build_line(
                        record,
                        config,
                        Some(Method::Market),
                        None,
                        uncovered,
                        canonical_unit,
                        row,
                    )?),
                    None => {
                        scope2_factor_gap = true;
                        findings.push(factor_missing(record, "market"));
                    }
                }
            }
            Scope::Scope3 => match scope3_category(config, &record.activity) {
                Some(category) => {
                    let factor = find_factor(
                        config,
                        &record.activity,
                        &canonical_unit,
                        &record.region,
                        record.year,
                        None,
                    );
                    match factor {
                        Some(row) => lines.push(build_line(
                            record,
                            config,
                            None,
                            Some(category),
                            quantity,
                            canonical_unit,
                            row,
                        )?),
                        None => findings.push(factor_missing(record, method_tag(None))),
                    }
                }
                None => findings.push(spine::Finding::breach(
                    RULE_SCOPE3_UNMAPPED,
                    record.record_id.clone(),
                    format!(
                        "activity {} is not mapped to a scope 3 category (1-15) in config",
                        record.activity
                    ),
                )),
            },
        }
    }

    divergence_finding(&lines, config, scope2_factor_gap, &mut findings);

    lines.sort_by_key(line_sort_key);
    findings.sort_by(|a, b| {
        (&a.rule_id, &a.subject, &a.message).cmp(&(&b.rule_id, &b.subject, &b.message))
    });

    Ok(ComputedInventory { lines, findings })
}

/// Scope 2 dual-method divergence: a Warn (never a breach — the methods are
/// both valid views) when the market-based total strays beyond the config's
/// basis-point threshold of the location-based total.
fn divergence_finding(
    lines: &[EmissionLine],
    config: &GhgConfig,
    scope2_factor_gap: bool,
    findings: &mut Vec<spine::Finding>,
) {
    if scope2_factor_gap {
        return; // incomplete method totals would make the divergence meaningless
    }
    let location = lines
        .iter()
        .filter(|l| l.method == Some(Method::Location))
        .map(|l| l.emission_grams as i128)
        .sum::<i128>();
    let market = lines
        .iter()
        .filter(|l| l.method == Some(Method::Market))
        .map(|l| l.emission_grams as i128)
        .sum::<i128>();
    let divergent = if location == 0 {
        market != 0
    } else {
        let bps = (location - market).abs() * 10_000 / location;
        bps > config.scope2_divergence_warn_bps as i128
    };
    if divergent {
        findings.push(spine::Finding {
            rule_id: RULE_SCOPE2_DIVERGENCE.to_string(),
            severity: spine::Severity::Warn,
            subject: config.period.clone(),
            message: format!(
                "scope 2 methods diverge: location-based {location} g vs market-based {market} g exceeds threshold {} bps",
                config.scope2_divergence_warn_bps
            ),
            requires_signoff: false,
        });
    }
}

fn build_line(
    record: &ActivityRecord,
    config: &GhgConfig,
    method: Option<Method>,
    scope3_category: Option<u8>,
    quantity: Scaled,
    canonical_unit: String,
    row: &FactorRow,
) -> Result<EmissionLine, ComputeError> {
    Ok(EmissionLine {
        record_id: record.record_id.clone(),
        scope: record.scope.as_number(),
        method,
        scope3_category,
        activity: record.activity.clone(),
        region: record.region.clone(),
        year: record.year,
        canonical_unit,
        canonical_quantity: quantity,
        factor_version: row.factor_version.clone(),
        factor: row.factor,
        emission_grams: emission_grams(&quantity, row)?,
        confidence: confidence_label(record.dq_score, config),
        disclosure: if method == Some(Method::Market) {
            Some(MARKET_SCOPE2_DISCLOSURE.to_string())
        } else {
            None
        },
    })
}

fn factor_missing(record: &ActivityRecord, method: &str) -> spine::Finding {
    spine::Finding::breach(
        RULE_FACTOR_MISSING,
        record.record_id.clone(),
        format!(
            "no {} emission factor for activity {} unit {} region {} year {} — the line is not computed, never zeroed",
            method, record.activity, record.unit, record.region, record.year
        ),
    )
}
