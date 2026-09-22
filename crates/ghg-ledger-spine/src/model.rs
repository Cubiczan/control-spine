//! Input records and config tables for the GHG ledger engine.
//!
//! Everything here is schema-checked JSON: `deny_unknown_fields` plus
//! [`GhgConfig::validate`] refuse any shape the engine cannot interpret
//! deterministically. Quantities and factors are fixed-point integers
//! (`value / 10^scale`) — floats are never parsed. Scales are capped at
//! [`MAX_SCALE`] so intermediate products stay inside i128 with headroom
//! for half-up rounding.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Maximum fixed-point scale accepted on quantities, factors, and
/// conversions. Keeps `10^scale` and the half-up rounding step far inside
/// i128.
pub const MAX_SCALE: u32 = 18;

/// GHG protocol scope of an activity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Scope1,
    Scope2,
    Scope3,
}

impl Scope {
    pub fn as_number(self) -> u8 {
        match self {
            Scope::Scope1 => 1,
            Scope::Scope2 => 2,
            Scope::Scope3 => 3,
        }
    }
}

/// Scope 2 computation method. Scope 1 and Scope 3 factors carry no method
/// (`Option<Method>` is `None` there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Location,
    Market,
}

impl Method {
    pub fn as_tag(self) -> &'static str {
        match self {
            Method::Location => "location",
            Method::Market => "market",
        }
    }
}

/// Fixed-point decimal: `value / 10^scale`. Integers only, never floats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scaled {
    pub value: i64,
    pub scale: u32,
}

/// One activity record in the input file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityRecord {
    pub record_id: String,
    pub scope: Scope,
    pub activity: String,
    pub quantity: Scaled,
    pub unit: String,
    pub region: String,
    pub year: i32,
    /// Scope 2 only: quantity covered by contractual instruments (RECs /
    /// PPAs). Instrument-covered quantity is treated as zero-emission under
    /// the market-based method; the remainder draws the residual-mix factor.
    #[serde(default)]
    pub market_covered: Option<Scaled>,
    /// Data-quality score 0–100; rendered through the config's DQ tiers.
    #[serde(default)]
    pub dq_score: Option<i64>,
}

/// Root of the inputs file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityInputs {
    pub records: Vec<ActivityRecord>,
}

/// Unit conversion applied once, at the input boundary. After conversion the
/// engine only ever sees canonical units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitConversion {
    pub from_unit: String,
    pub to_unit: String,
    pub factor: Scaled,
}

/// One versioned emission-factor row. `method` is `None` for Scope 1/3
/// factors and `Some(Location | Market)` for Scope 2 grid factors.
/// `factor_version` is recorded verbatim on every line the row produces —
/// that is the lineage contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorRow {
    pub activity: String,
    pub unit: String,
    pub region: String,
    pub year: i32,
    #[serde(default)]
    pub method: Option<Method>,
    pub factor: Scaled,
    pub factor_version: String,
    /// Free-text provenance label for seed data (e.g. `"seed:epa-style"`).
    #[serde(default)]
    pub source: Option<String>,
}

/// Scope 3 category assignment (categories 1–15) for named activities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope3Category {
    pub category: u8,
    pub activities: Vec<String>,
}

/// Data-quality tier: the first tier whose `min_score <= score` labels the
/// line. Tiers must be strictly descending and the last tier must reach 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DqTier {
    pub min_score: i64,
    pub label: String,
}

/// Root of the config file (the params side of the params hash).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhgConfig {
    /// Reporting period this ledger version covers (e.g. `"2025-FY"`).
    pub period: String,
    #[serde(default)]
    pub conversions: Vec<UnitConversion>,
    #[serde(default)]
    pub factors: Vec<FactorRow>,
    #[serde(default)]
    pub scope3_categories: Vec<Scope3Category>,
    pub dq_tiers: Vec<DqTier>,
    /// Warn when Scope 2 methods diverge by more than this many basis
    /// points of the location-based total (0–10_000).
    pub scope2_divergence_warn_bps: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("config schema violation: {0}")]
pub struct ConfigError(pub String);

impl GhgConfig {
    /// Schema check beyond shape: refuse anything ambiguous. A config that
    /// passes here makes every compute deterministic.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.period.trim().is_empty() {
            return Err(ConfigError("period must be non-empty".into()));
        }
        if !(0..=10_000).contains(&self.scope2_divergence_warn_bps) {
            return Err(ConfigError(
                "scope2_divergence_warn_bps must be within 0..=10000".into(),
            ));
        }

        let mut conversion_units = std::collections::BTreeSet::new();
        for c in &self.conversions {
            if c.from_unit.trim().is_empty() || c.to_unit.trim().is_empty() {
                return Err(ConfigError("conversion units must be non-empty".into()));
            }
            if c.from_unit == c.to_unit {
                return Err(ConfigError(format!(
                    "conversion from_unit == to_unit ({})",
                    c.from_unit
                )));
            }
            if c.factor.value <= 0 || c.factor.scale > MAX_SCALE {
                return Err(ConfigError(format!(
                    "conversion {}/{}: factor must be positive with scale <= {MAX_SCALE}",
                    c.from_unit, c.to_unit
                )));
            }
            if !conversion_units.insert(c.from_unit.clone()) {
                return Err(ConfigError(format!(
                    "duplicate conversion for from_unit {}",
                    c.from_unit
                )));
            }
        }

        let mut factor_keys = std::collections::BTreeSet::new();
        for f in &self.factors {
            if f.activity.trim().is_empty()
                || f.unit.trim().is_empty()
                || f.region.trim().is_empty()
                || f.factor_version.trim().is_empty()
            {
                return Err(ConfigError(
                    "factor rows need non-empty activity, unit, region, factor_version".into(),
                ));
            }
            if f.factor.value < 0 || f.factor.scale > MAX_SCALE {
                return Err(ConfigError(format!(
                    "factor {}/{}/{}: value must be >= 0 with scale <= {MAX_SCALE}",
                    f.activity, f.unit, f.region
                )));
            }
            let key = (
                f.activity.clone(),
                f.unit.clone(),
                f.region.clone(),
                f.year,
                f.method,
            );
            if !factor_keys.insert(key) {
                return Err(ConfigError(format!(
                    "duplicate factor row for {}/{}/{}/{} ({})",
                    f.activity,
                    f.unit,
                    f.region,
                    f.year,
                    method_tag(f.method),
                )));
            }
        }

        let mut seen_activities = std::collections::BTreeSet::new();
        for cat in &self.scope3_categories {
            if !(1..=15).contains(&cat.category) {
                return Err(ConfigError(format!(
                    "scope 3 category {} outside 1..=15",
                    cat.category
                )));
            }
            if cat.activities.is_empty() {
                return Err(ConfigError(format!(
                    "scope 3 category {} maps no activities",
                    cat.category
                )));
            }
            for a in &cat.activities {
                if a.trim().is_empty() {
                    return Err(ConfigError(
                        "scope 3 activity names must be non-empty".into(),
                    ));
                }
                if !seen_activities.insert(a.clone()) {
                    return Err(ConfigError(format!(
                        "activity {a} mapped to more than one scope 3 category"
                    )));
                }
            }
        }

        if self.dq_tiers.is_empty() {
            return Err(ConfigError("dq_tiers must not be empty".into()));
        }
        let mut labels = std::collections::BTreeSet::new();
        let mut prev: Option<i64> = None;
        for t in &self.dq_tiers {
            if !(0..=100).contains(&t.min_score) {
                return Err(ConfigError(format!(
                    "dq tier {} label {}: min_score outside 0..=100",
                    t.min_score, t.label
                )));
            }
            if t.label.trim().is_empty() {
                return Err(ConfigError("dq tier labels must be non-empty".into()));
            }
            if !labels.insert(t.label.clone()) {
                return Err(ConfigError(format!("duplicate dq tier label {}", t.label)));
            }
            if let Some(p) = prev {
                if t.min_score >= p {
                    return Err(ConfigError(
                        "dq tiers must have strictly descending min_score".into(),
                    ));
                }
            }
            prev = Some(t.min_score);
        }
        if self.dq_tiers.last().map(|t| t.min_score) != Some(0) {
            return Err(ConfigError("last dq tier must have min_score 0".into()));
        }
        Ok(())
    }
}

pub(crate) fn method_tag(method: Option<Method>) -> &'static str {
    method.map(|m| m.as_tag()).unwrap_or("direct")
}

/// Exact fixed-point comparison — never compares through floats.
pub(crate) fn scaled_cmp(a: Scaled, b: Scaled) -> Ordering {
    let scale = a.scale.max(b.scale);
    let av = (a.value as i128) * 10i128.pow(scale - a.scale);
    let bv = (b.value as i128) * 10i128.pow(scale - b.scale);
    av.cmp(&bv)
}

/// `a - b` at a common scale; `None` on overflow, a negative result, or a
/// value beyond i64 range. A negative difference (overcoverage) is rejected
/// upstream as an input breach — refusing here too keeps a negative-emission
/// line impossible rather than merely unlikely.
pub(crate) fn scaled_sub(a: Scaled, b: Scaled) -> Option<Scaled> {
    let scale = a.scale.max(b.scale);
    let av = (a.value as i128) * 10i128.pow(scale - a.scale);
    let bv = (b.value as i128) * 10i128.pow(scale - b.scale);
    let diff = av.checked_sub(bv)?;
    if diff < 0 {
        return None;
    }
    let value = i64::try_from(diff).ok()?;
    Some(Scaled { value, scale })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_cmp_across_scales() {
        assert_eq!(
            scaled_cmp(
                Scaled {
                    value: 25,
                    scale: 1
                },
                Scaled { value: 2, scale: 0 }
            ),
            Ordering::Greater
        );
        assert_eq!(
            scaled_cmp(
                Scaled {
                    value: 250,
                    scale: 1
                },
                Scaled {
                    value: 25,
                    scale: 0
                }
            ),
            Ordering::Equal
        );
        assert_eq!(
            scaled_cmp(
                Scaled { value: 1, scale: 0 },
                Scaled {
                    value: 11,
                    scale: 1
                }
            ),
            Ordering::Less
        );
    }

    #[test]
    fn scaled_sub_aligns_scales() {
        let a = Scaled {
            value: 1000,
            scale: 0,
        };
        let b = Scaled {
            value: 25,
            scale: 1,
        };
        assert_eq!(
            scaled_sub(a, b),
            Some(Scaled {
                value: 9975,
                scale: 1
            })
        );
        assert_eq!(
            scaled_sub(Scaled { value: 1, scale: 0 }, Scaled { value: 2, scale: 0 }),
            None
        );
    }
}
