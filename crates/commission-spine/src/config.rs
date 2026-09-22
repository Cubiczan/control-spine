//! Plan configuration for the commission engine: schema-checked JSON tables
//! (serde, `deny_unknown_fields`) validated fail-closed at load. Config
//! tables shipped with this crate are seed data, not authoritative policy.
//!
//! Rates are integer basis points; money is integer cents (`i128`); quotas
//! are positive integer cents. Attainment is expressed in parts-per-million
//! of quota so every comparison is exact integer arithmetic.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// Attainment is expressed in parts-per-million of quota.
pub const ATTAINMENT_SCALE: i128 = 1_000_000;

/// Basis points per whole unit (rates are integer basis points).
pub const BASIS_POINTS: i128 = 10_000;

/// How accelerator bands apply to credited revenue.
///
/// * [`BandMode::Marginal`] — tax-bracket style: the attainment range is
///   sliced at band boundaries and each revenue slice is paid at its own
///   band rate.
/// * [`BandMode::Cliff`] — the band containing total attainment sets the
///   rate applied to all credited revenue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BandMode {
    Marginal,
    Cliff,
}

/// One accelerator band. The first band implicitly starts at zero attainment;
/// band boundaries are exclusive upper bounds, so attainment exactly at
/// `up_to_ppm` belongs to the next band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Band {
    /// Exclusive upper attainment bound in ppm; `None` (unbounded) is only
    /// allowed on the last band.
    pub up_to_ppm: Option<u64>,
    /// Commission rate on credited revenue, in basis points (1..=10_000).
    pub rate_bps: u32,
}

/// Split weight for one role. A version's weights must sum to exactly
/// 10_000 bps so a transaction splits fully across its credited roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleWeight {
    pub role: String,
    pub weight_bps: u32,
}

/// One version of the commission plan. Plan versions are effective-dated:
/// a transaction is computed under the version in force at its date.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanVersion {
    pub version: u32,
    pub effective_from: NaiveDate,
    /// Inclusive upper bound; `None` means open-ended.
    pub effective_to: Option<NaiveDate>,
    /// Positive quota in integer cents.
    pub quota_cents: i128,
    pub band_mode: BandMode,
    /// Ascending accelerator bands; only the last band may be unbounded.
    pub bands: Vec<Band>,
    /// Attainment cap in ppm: commission basis is capped at this attainment.
    /// `None` = uncapped.
    #[serde(default)]
    pub windfall_cap_ppm: Option<u64>,
    /// Maximum allowed spread between the highest and lowest band rates, in
    /// bps. Config that exceeds the cap fails validation (fail-closed).
    #[serde(default)]
    pub max_spread_bps: Option<u32>,
    /// Role split weights for credited transactions; must sum to 10_000 bps.
    pub role_weights: Vec<RoleWeight>,
}

impl PlanVersion {
    /// True when `date` falls inside this version's effective range
    /// (inclusive on both ends).
    pub fn covers(&self, date: NaiveDate) -> bool {
        let to_ok = match self.effective_to {
            Some(to) => date <= to,
            None => true,
        };
        self.effective_from <= date && to_ok
    }

    /// Split weight for `role`, if this version configures it.
    pub fn role_weight(&self, role: &str) -> Option<u32> {
        self.role_weights
            .iter()
            .find(|w| w.role == role)
            .map(|w| w.weight_bps)
    }
}

/// Top-level plan config: one or more effective-dated versions, sorted
/// ascending by `effective_from`, non-overlapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanConfig {
    pub plan_id: String,
    pub versions: Vec<PlanVersion>,
}

/// Plan configuration refusals. All are load-time failures: the engine never
/// runs on a config that has not validated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("plan_id must be non-empty")]
    EmptyPlanId,
    #[error("plan has no versions")]
    EmptyVersions,
    #[error("plan versions are not sorted ascending by effective_from")]
    UnsortedVersions,
    #[error("plan version {version}: effective range is inverted ({from} after {to})")]
    InvertedRange {
        version: u32,
        from: NaiveDate,
        to: NaiveDate,
    },
    #[error("plan version {version}: effective range overlaps version {other}")]
    Overlap { version: u32, other: u32 },
    #[error("plan version {version}: duplicate version number")]
    DuplicateVersionNumber { version: u32 },
    #[error("plan version {version}: quota must be positive")]
    NonPositiveQuota { version: u32 },
    #[error("plan version {version}: bands must be non-empty")]
    EmptyBands { version: u32 },
    #[error("plan version {version}: band {index}: only the last band may be unbounded")]
    UnboundedNotLast { version: u32, index: usize },
    #[error("plan version {version}: band {index}: up_to_ppm must be positive")]
    NonPositiveBandBound { version: u32, index: usize },
    #[error("plan version {version}: band {index}: bands must ascend strictly by up_to_ppm")]
    BandsNotAscending { version: u32, index: usize },
    #[error("plan version {version}: band {index}: rate_bps must be 1..=10000")]
    RateOutOfRange { version: u32, index: usize },
    #[error(
        "plan version {version}: band rate spread {actual} bps exceeds max_spread_bps {allowed}"
    )]
    SpreadCapExceeded {
        version: u32,
        allowed: u32,
        actual: i64,
    },
    #[error("plan version {version}: windfall cap must be positive")]
    NonPositiveWindfallCap { version: u32 },
    #[error("plan version {version}: role weights must be non-empty")]
    EmptyRoleWeights { version: u32 },
    #[error("plan version {version}: duplicate role weight for role {role:?}")]
    DuplicateRole { version: u32, role: String },
    #[error("plan version {version}: role {role:?}: weight must be positive")]
    NonPositiveWeight { version: u32, role: String },
    #[error("plan version {version}: role weights sum to {sum} bps, expected 10000")]
    WeightSum { version: u32, sum: i64 },
}

impl PlanConfig {
    /// Fail-closed config validation. Returns the first refusal found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.plan_id.trim().is_empty() {
            return Err(ConfigError::EmptyPlanId);
        }
        if self.versions.is_empty() {
            return Err(ConfigError::EmptyVersions);
        }
        let mut seen_versions = std::collections::BTreeSet::new();
        for (i, v) in self.versions.iter().enumerate() {
            if !seen_versions.insert(v.version) {
                return Err(ConfigError::DuplicateVersionNumber { version: v.version });
            }
            if v.quota_cents <= 0 {
                return Err(ConfigError::NonPositiveQuota { version: v.version });
            }
            if let Some(to) = v.effective_to {
                if v.effective_from > to {
                    return Err(ConfigError::InvertedRange {
                        version: v.version,
                        from: v.effective_from,
                        to,
                    });
                }
            }
            if let Some(prev) = i.checked_sub(1).and_then(|p| self.versions.get(p)) {
                if v.effective_from < prev.effective_from {
                    return Err(ConfigError::UnsortedVersions);
                }
                let overlaps = prev.effective_to.is_some_and(|to| v.effective_from <= to);
                if overlaps {
                    return Err(ConfigError::Overlap {
                        version: v.version,
                        other: prev.version,
                    });
                }
            }
            self.validate_version(v)?;
        }
        Ok(())
    }

    fn validate_version(&self, v: &PlanVersion) -> Result<(), ConfigError> {
        if v.bands.is_empty() {
            return Err(ConfigError::EmptyBands { version: v.version });
        }
        for (index, band) in v.bands.iter().enumerate() {
            if band.up_to_ppm.is_none() && index != v.bands.len() - 1 {
                return Err(ConfigError::UnboundedNotLast {
                    version: v.version,
                    index,
                });
            }
            if let Some(up) = band.up_to_ppm {
                if up == 0 {
                    return Err(ConfigError::NonPositiveBandBound {
                        version: v.version,
                        index,
                    });
                }
                if index > 0 && up <= v.bands[index - 1].up_to_ppm.unwrap_or(0) {
                    return Err(ConfigError::BandsNotAscending {
                        version: v.version,
                        index,
                    });
                }
            }
            if band.rate_bps == 0 || band.rate_bps > 10_000 {
                return Err(ConfigError::RateOutOfRange {
                    version: v.version,
                    index,
                });
            }
        }
        if let Some(cap) = v.windfall_cap_ppm {
            if cap == 0 {
                return Err(ConfigError::NonPositiveWindfallCap { version: v.version });
            }
        }
        if let Some(allowed) = v.max_spread_bps {
            let rates = v.bands.iter().map(|b| i64::from(b.rate_bps));
            let spread = rates.clone().max().unwrap_or(0) - rates.min().unwrap_or(0);
            if spread > i64::from(allowed) {
                return Err(ConfigError::SpreadCapExceeded {
                    version: v.version,
                    allowed,
                    actual: spread,
                });
            }
        }
        if v.role_weights.is_empty() {
            return Err(ConfigError::EmptyRoleWeights { version: v.version });
        }
        let mut roles = std::collections::BTreeSet::new();
        let mut sum = 0i64;
        for w in &v.role_weights {
            if w.role.trim().is_empty() {
                return Err(ConfigError::NonPositiveWeight {
                    version: v.version,
                    role: w.role.clone(),
                });
            }
            if !roles.insert(w.role.clone()) {
                return Err(ConfigError::DuplicateRole {
                    version: v.version,
                    role: w.role.clone(),
                });
            }
            if w.weight_bps == 0 {
                return Err(ConfigError::NonPositiveWeight {
                    version: v.version,
                    role: w.role.clone(),
                });
            }
            sum += i64::from(w.weight_bps);
        }
        if sum != 10_000 {
            return Err(ConfigError::WeightSum {
                version: v.version,
                sum,
            });
        }
        Ok(())
    }

    /// Index of the version in force at `date`, if any. Transactions the
    /// config does not cover are never guessed at — the engine quarantines
    /// them with a breach finding.
    pub fn version_index_for_date(&self, date: NaiveDate) -> Option<usize> {
        self.versions.iter().position(|v| v.covers(date))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn band(up_to_ppm: Option<u64>, rate_bps: u32) -> Band {
        Band {
            up_to_ppm,
            rate_bps,
        }
    }

    fn version(version: u32, from: &str, to: Option<&str>) -> PlanVersion {
        PlanVersion {
            version,
            effective_from: NaiveDate::parse_from_str(from, "%Y-%m-%d").expect("valid date"),
            effective_to: to.map(|t| NaiveDate::parse_from_str(t, "%Y-%m-%d").expect("valid date")),
            quota_cents: 1_000_000,
            band_mode: BandMode::Marginal,
            bands: vec![band(Some(1_000_000), 200), band(None, 500)],
            windfall_cap_ppm: None,
            max_spread_bps: None,
            role_weights: vec![RoleWeight {
                role: "ae".to_string(),
                weight_bps: 10_000,
            }],
        }
    }

    #[test]
    fn valid_plan_passes_validation() {
        let plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-01-01", None)],
        };
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn overlapping_versions_are_rejected() {
        let plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![
                version(1, "2026-01-01", Some("2026-06-30")),
                version(2, "2026-06-30", None), // inclusive `to` collides
            ],
        };
        assert_eq!(
            plan.validate(),
            Err(ConfigError::Overlap {
                version: 2,
                other: 1
            })
        );
    }

    #[test]
    fn unsorted_versions_are_rejected() {
        let plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![
                version(1, "2026-07-01", None),
                version(2, "2026-01-01", None),
            ],
        };
        assert_eq!(plan.validate(), Err(ConfigError::UnsortedVersions));
    }

    #[test]
    fn inverted_range_is_rejected() {
        let plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-06-30", Some("2026-01-01"))],
        };
        assert!(matches!(
            plan.validate(),
            Err(ConfigError::InvertedRange { .. })
        ));
    }

    #[test]
    fn non_positive_quota_is_rejected() {
        let mut plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-01-01", None)],
        };
        plan.versions[0].quota_cents = 0;
        assert_eq!(
            plan.validate(),
            Err(ConfigError::NonPositiveQuota { version: 1 })
        );
    }

    #[test]
    fn band_rate_out_of_range_is_rejected() {
        let mut plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-01-01", None)],
        };
        plan.versions[0].bands[0].rate_bps = 10_001;
        assert!(matches!(
            plan.validate(),
            Err(ConfigError::RateOutOfRange { .. })
        ));
    }

    #[test]
    fn spread_cap_violation_is_rejected() {
        let mut plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-01-01", None)],
        };
        plan.versions[0].bands = vec![band(Some(1_000_000), 200), band(None, 550)];
        plan.versions[0].max_spread_bps = Some(300);
        assert_eq!(
            plan.validate(),
            Err(ConfigError::SpreadCapExceeded {
                version: 1,
                allowed: 300,
                actual: 350
            })
        );
    }

    #[test]
    fn role_weights_must_sum_to_10000() {
        let mut plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![version(1, "2026-01-01", None)],
        };
        plan.versions[0].role_weights = vec![
            RoleWeight {
                role: "ae".to_string(),
                weight_bps: 7_000,
            },
            RoleWeight {
                role: "se".to_string(),
                weight_bps: 2_000,
            },
        ];
        assert_eq!(
            plan.validate(),
            Err(ConfigError::WeightSum {
                version: 1,
                sum: 9_000
            })
        );
    }

    #[test]
    fn version_lookup_is_inclusive_on_both_ends() {
        let plan = PlanConfig {
            plan_id: "p".to_string(),
            versions: vec![
                version(1, "2026-01-01", Some("2026-06-30")),
                version(2, "2026-07-01", None),
            ],
        };
        let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("valid date");
        assert_eq!(plan.version_index_for_date(d("2026-01-01")), Some(0));
        assert_eq!(plan.version_index_for_date(d("2026-06-30")), Some(0));
        assert_eq!(plan.version_index_for_date(d("2026-07-01")), Some(1));
        assert_eq!(plan.version_index_for_date(d("2025-12-31")), None);
    }
}
