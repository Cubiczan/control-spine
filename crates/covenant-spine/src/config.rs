//! Schema-checked covenant configuration (JSON via serde). Unknown keys are
//! rejected at the boundary — the schema is strict, fail-closed.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::units::{Cents, Ratio};

/// Typed covenant kinds. The kind fixes the formula and the comparison
/// direction; config supplies only the threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantKind {
    MaxLeverage,
    MinInterestCoverage,
    MinCurrentRatio,
    MinFixedChargeCoverage,
}

impl CovenantKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::MaxLeverage => "max leverage",
            Self::MinInterestCoverage => "min interest coverage",
            Self::MinCurrentRatio => "min current ratio",
            Self::MinFixedChargeCoverage => "min fixed-charge coverage",
        }
    }

    /// `true` when the ratio must stay at or below the threshold (a
    /// maximum); `false` when it must reach it (a minimum).
    pub fn is_maximum(self) -> bool {
        matches!(self, Self::MaxLeverage)
    }
}

/// Measurement basis: a single quarter or a trailing-four-quarter LTM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Ltm,
    Quarterly,
}

impl Basis {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ltm => "ltm",
            Self::Quarterly => "quarterly",
        }
    }
}

/// Number of quarterly rows a trailing LTM window spans.
pub const LTM_QUARTERS: usize = 4;

/// One version of a covenant's text. The same `id` may appear on multiple
/// rows — an amendment history. Exactly one row per id may be in force at
/// the measurement date; windows are half-open
/// `[effective_from, effective_to)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovenantRule {
    pub id: String,
    pub kind: CovenantKind,
    pub threshold: Ratio,
    pub basis: Basis,
    pub effective_from: NaiveDate,
    pub effective_to: Option<NaiveDate>,
}

impl CovenantRule {
    pub fn is_in_force(&self, date: NaiveDate) -> bool {
        self.effective_from <= date && self.effective_to.is_none_or(|to| date < to)
    }
}

/// A config-anchored equity-cure adjustment. A cure applies to the
/// measurement evaluation when the measurement date falls in its half-open
/// window; multiple matching cures sum in config order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquityCure {
    pub description: String,
    pub effective_from: NaiveDate,
    pub effective_to: Option<NaiveDate>,
    pub add_to_ebitda_cents: Cents,
    pub reduce_debt_cents: Cents,
}

impl EquityCure {
    pub fn is_in_force(&self, date: NaiveDate) -> bool {
        self.effective_from <= date && self.effective_to.is_none_or(|to| date < to)
    }
}

/// Deterministic linear-trend projection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionConfig {
    /// Warning horizon: flag a projected breach when the trend crosses the
    /// threshold within this many quarters.
    #[serde(default = "default_horizon_quarters")]
    pub horizon_quarters: u32,
    /// Minimum computable ratio points required to fit a trend.
    #[serde(default = "default_min_history_points")]
    pub min_history_points: u32,
}

fn default_horizon_quarters() -> u32 {
    4
}

fn default_min_history_points() -> u32 {
    2
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            horizon_quarters: default_horizon_quarters(),
            min_history_points: default_min_history_points(),
        }
    }
}

/// Top-level covenant configuration. Unknown JSON keys are rejected — the
/// schema is checked at the boundary, fail-closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CovenantConfig {
    #[serde(default)]
    pub covenants: Vec<CovenantRule>,
    #[serde(default)]
    pub equity_cures: Vec<EquityCure>,
    #[serde(default)]
    pub projection: ProjectionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("covenant {id:?}: id must not be empty")]
    EmptyId { id: String },
    #[error("covenant {id}: threshold must not be negative")]
    NegativeThreshold { id: String },
    #[error("covenant {id}: effective_to {to} precedes effective_from {from}")]
    InvalidWindow {
        id: String,
        from: NaiveDate,
        to: NaiveDate,
    },
    #[error("equity cure {description:?}: effective_to {to} precedes effective_from {from}")]
    InvalidCureWindow {
        description: String,
        from: NaiveDate,
        to: NaiveDate,
    },
    #[error("projection.horizon_quarters must be at least 1")]
    HorizonZero,
    #[error("projection.min_history_points must be at least 2 to fit a trend")]
    MinHistoryTooSmall,
}

/// Cross-field config validation that serde cannot express.
pub fn validate(config: &CovenantConfig) -> Result<(), ConfigError> {
    for rule in &config.covenants {
        if rule.id.trim().is_empty() {
            return Err(ConfigError::EmptyId {
                id: rule.id.clone(),
            });
        }
        if rule.threshold.scaled() < 0 {
            return Err(ConfigError::NegativeThreshold {
                id: rule.id.clone(),
            });
        }
        if let Some(to) = rule.effective_to {
            if to < rule.effective_from {
                return Err(ConfigError::InvalidWindow {
                    id: rule.id.clone(),
                    from: rule.effective_from,
                    to,
                });
            }
        }
    }
    for cure in &config.equity_cures {
        if let Some(to) = cure.effective_to {
            if to < cure.effective_from {
                return Err(ConfigError::InvalidCureWindow {
                    description: cure.description.clone(),
                    from: cure.effective_from,
                    to,
                });
            }
        }
    }
    if config.projection.horizon_quarters < 1 {
        return Err(ConfigError::HorizonZero);
    }
    if config.projection.min_history_points < 2 {
        return Err(ConfigError::MinHistoryTooSmall);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn rule(id: &str, threshold: &str, from: &str, to: Option<&str>) -> CovenantRule {
        CovenantRule {
            id: id.to_string(),
            kind: CovenantKind::MaxLeverage,
            threshold: Ratio::from_decimal_str(threshold).unwrap(),
            basis: Basis::Ltm,
            effective_from: date(from),
            effective_to: to.map(date),
        }
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let json = r#"{"covenants": [], "surprise": 1}"#;
        assert!(serde_json::from_str::<CovenantConfig>(json).is_err());
    }

    #[test]
    fn config_defaults_apply_when_sections_absent() {
        let cfg: CovenantConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.covenants.is_empty());
        assert_eq!(cfg.projection.horizon_quarters, 4);
        assert_eq!(cfg.projection.min_history_points, 2);
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn is_in_force_window_is_half_open() {
        let r = rule("LEV", "3.5", "2026-01-01", Some("2027-01-01"));
        assert!(!r.is_in_force(date("2025-12-31")));
        assert!(r.is_in_force(date("2026-01-01")));
        assert!(r.is_in_force(date("2026-12-31")));
        assert!(!r.is_in_force(date("2027-01-01")));

        let open = rule("LEV", "3.5", "2026-01-01", None);
        assert!(open.is_in_force(date("2999-12-31")));
    }

    #[test]
    fn validate_rejects_negative_thresholds_and_empty_ids() {
        let mut negative = rule("LEV", "3.5", "2020-01-01", None);
        negative.threshold = Ratio::from_scaled(-1);
        assert!(validate(&CovenantConfig {
            covenants: vec![negative],
            ..Default::default()
        })
        .is_err());

        let blank = rule("  ", "3.5", "2020-01-01", None);
        assert!(validate(&CovenantConfig {
            covenants: vec![blank],
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn validate_rejects_inverted_windows() {
        let bad = rule("LEV", "3.5", "2026-01-01", Some("2025-01-01"));
        assert!(validate(&CovenantConfig {
            covenants: vec![bad],
            ..Default::default()
        })
        .is_err());

        let cure = EquityCure {
            description: "cure".into(),
            effective_from: date("2026-01-01"),
            effective_to: Some(date("2025-01-01")),
            add_to_ebitda_cents: Cents::from_cents(0),
            reduce_debt_cents: Cents::from_cents(0),
        };
        assert!(validate(&CovenantConfig {
            equity_cures: vec![cure],
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn validate_rejects_degenerate_projection_settings() {
        let cfg = CovenantConfig {
            projection: ProjectionConfig {
                horizon_quarters: 0,
                min_history_points: 2,
            },
            ..Default::default()
        };
        assert!(validate(&cfg).is_err());

        let cfg = CovenantConfig {
            projection: ProjectionConfig {
                horizon_quarters: 4,
                min_history_points: 1,
            },
            ..Default::default()
        };
        assert!(validate(&cfg).is_err());
    }
}
