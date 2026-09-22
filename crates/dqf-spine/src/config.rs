//! Schema-checked JSON config tables (serde). Unknown fields are refused so
//! a stale or mistyped config fails loudly instead of silently loosening a
//! control.
//!
//! Shipped values are **seed data** — see the crate README. They are not
//! regulatory tables and make no compliance claim.

use serde::{Deserialize, Serialize};

use crate::error::DqfError;
use crate::model::DocKind;

/// Spec ceiling: a medical certificate's validity window may not exceed 24
/// months, per type.
pub const MAX_MEDICAL_VALIDITY_MONTHS: u32 = 24;

/// Top-level config: validity windows, checklist completeness flags, and
/// state-specific CDL rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DqfConfig {
    /// Warn when an expiry or window boundary falls within this many days of
    /// the campaign date, inclusive.
    pub expiring_warn_days: u32,
    /// An MVR satisfies the checklist for this many days after its pull date.
    pub mvr_validity_days: u32,
    /// An annual review satisfies the checklist for this many days after it
    /// is completed.
    pub annual_review_validity_days: u32,
    /// Medical certificate validity ceilings by certificate type, in months.
    pub medical: MedicalWindows,
    /// Per-kind checklist completeness flags.
    pub checklist: Checklist,
    /// State-specific CDL rules; at most one rule per state.
    #[serde(default)]
    pub state_cdl_rules: Vec<StateCdlRule>,
}

/// Medical certificate validity ceilings, in months, per certificate type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MedicalWindows {
    pub full_max_months: u32,
    pub variance_max_months: u32,
}

/// Per-kind completeness flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checklist {
    pub cdl: ItemConfig,
    pub medical_certificate: ItemConfig,
    pub mvr: ItemConfig,
    pub annual_review: ItemConfig,
    pub road_test: ItemConfig,
    pub employment_history: ItemConfig,
}

/// Completeness flag for one checklist item. `required` defaults to true —
/// an omitted flag means the item may not be missing (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemConfig {
    #[serde(default = "required_default")]
    pub required: bool,
}

fn required_default() -> bool {
    true
}

/// State-specific CDL rule: endorsements the state requires and an optional
/// per-state maximum CDL validity window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCdlRule {
    pub state: String,
    #[serde(default)]
    pub required_endorsements: Vec<String>,
    #[serde(default)]
    pub max_cdl_validity_months: Option<u32>,
}

impl DqfConfig {
    /// Semantic validation of the tables: positive windows, medical ceilings
    /// within the spec bound, and no ambiguous (duplicate) state rules.
    pub fn validate(&self) -> Result<(), DqfError> {
        if self.mvr_validity_days == 0 {
            return Err(DqfError::InvalidConfig {
                detail: "mvr_validity_days must be positive".to_string(),
            });
        }
        if self.annual_review_validity_days == 0 {
            return Err(DqfError::InvalidConfig {
                detail: "annual_review_validity_days must be positive".to_string(),
            });
        }
        self.medical.validate()?;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for rule in &self.state_cdl_rules {
            if rule.state.trim().is_empty() {
                return Err(DqfError::InvalidConfig {
                    detail: "state_cdl_rules entry has an empty state".to_string(),
                });
            }
            if !seen.insert(rule.state.trim().to_ascii_uppercase()) {
                return Err(DqfError::InvalidConfig {
                    detail: format!("duplicate state rule for {}", rule.state),
                });
            }
        }
        Ok(())
    }

    /// Whether the checklist requires this item kind to be present.
    pub fn required(&self, kind: DocKind) -> bool {
        match kind {
            DocKind::Cdl => self.checklist.cdl.required,
            DocKind::MedicalCertificate => self.checklist.medical_certificate.required,
            DocKind::Mvr => self.checklist.mvr.required,
            DocKind::AnnualReview => self.checklist.annual_review.required,
            DocKind::RoadTest => self.checklist.road_test.required,
            DocKind::EmploymentHistory => self.checklist.employment_history.required,
        }
    }

    /// The rule for `state`, if any. Match is trimmed and case-insensitive
    /// (under-counting a match is the fail-closed direction).
    pub fn state_rule(&self, state: &str) -> Option<&StateCdlRule> {
        self.state_cdl_rules
            .iter()
            .find(|r| r.state.trim().eq_ignore_ascii_case(state.trim()))
    }
}

impl MedicalWindows {
    fn validate(&self) -> Result<(), DqfError> {
        for (label, months) in [
            ("full_max_months", self.full_max_months),
            ("variance_max_months", self.variance_max_months),
        ] {
            if months == 0 || months > MAX_MEDICAL_VALIDITY_MONTHS {
                return Err(DqfError::InvalidConfig {
                    detail: format!(
                        "medical {label} is {months} months; the ceiling is {MAX_MEDICAL_VALIDITY_MONTHS} months per type"
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn all_required() -> Checklist {
    Checklist {
        cdl: ItemConfig { required: true },
        medical_certificate: ItemConfig { required: true },
        mvr: ItemConfig { required: true },
        annual_review: ItemConfig { required: true },
        road_test: ItemConfig { required: true },
        employment_history: ItemConfig { required: true },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(medical: MedicalWindows) -> DqfConfig {
        DqfConfig {
            expiring_warn_days: 30,
            mvr_validity_days: 365,
            annual_review_validity_days: 365,
            medical,
            checklist: crate::config::all_required(),
            state_cdl_rules: vec![],
        }
    }

    #[test]
    fn medical_ceiling_at_24_months_is_accepted() {
        let windows = MedicalWindows {
            full_max_months: 24,
            variance_max_months: 12,
        };
        assert_eq!(config(windows).validate(), Ok(()));
    }

    #[test]
    fn medical_ceiling_over_24_months_is_refused() {
        let windows = MedicalWindows {
            full_max_months: 25,
            variance_max_months: 12,
        };
        assert!(config(windows).validate().is_err());
    }

    #[test]
    fn medical_ceiling_zero_is_refused() {
        let windows = MedicalWindows {
            full_max_months: 24,
            variance_max_months: 0,
        };
        assert!(config(windows).validate().is_err());
    }

    #[test]
    fn zero_validity_windows_are_refused() {
        let mut cfg = config(MedicalWindows {
            full_max_months: 24,
            variance_max_months: 12,
        });
        cfg.mvr_validity_days = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn duplicate_state_rules_are_refused() {
        let mut cfg = config(MedicalWindows {
            full_max_months: 24,
            variance_max_months: 12,
        });
        cfg.state_cdl_rules = vec![
            StateCdlRule {
                state: "TX".to_string(),
                required_endorsements: vec![],
                max_cdl_validity_months: None,
            },
            StateCdlRule {
                state: "tx".to_string(),
                required_endorsements: vec![],
                max_cdl_validity_months: None,
            },
        ];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn unknown_config_field_fails_the_schema() {
        let json = r#"{
            "expiring_warn_days": 30,
            "bogus_field": 1,
            "mvr_validity_days": 365,
            "annual_review_validity_days": 365,
            "medical": {"full_max_months": 24, "variance_max_months": 12},
            "checklist": {
                "cdl": {}, "medical_certificate": {}, "mvr": {},
                "annual_review": {}, "road_test": {}, "employment_history": {}
            },
            "state_cdl_rules": []
        }"#;
        let result: Result<DqfConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields must refuse stale configs"
        );
    }

    #[test]
    fn item_config_required_defaults_to_true() {
        let item: ItemConfig = serde_json::from_str("{}").expect("empty object is valid");
        assert!(item.required);
    }
}
