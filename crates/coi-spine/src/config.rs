//! Schema-checked requirements matrix (the config table).
//!
//! The matrix is authored JSON: vendor category → required coverages with
//! minimum limits (integer cents) and required endorsements, plus the
//! expiry-warning window and the minimum carrier rating floor. Every struct
//! denies unknown fields — a typo is a refusal, not a silent default.
//! Shipped examples are seed data; see the README's honest-claims section.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::CoiError;

/// Carrier security-rating classes (A.M. Best-style vocabulary), ordered
/// best first — `Ord` follows declaration order. Seed vocabulary for
/// manually typed certificate data; the floor is config, never code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierRating {
    APlusPlus,
    APlus,
    A,
    AMinus,
    BPlus,
    B,
    BMinus,
    CPlus,
    C,
    CMinus,
    D,
    E,
    F,
}

impl CarrierRating {
    pub fn as_str(self) -> &'static str {
        match self {
            CarrierRating::APlusPlus => "a_plus_plus",
            CarrierRating::APlus => "a_plus",
            CarrierRating::A => "a",
            CarrierRating::AMinus => "a_minus",
            CarrierRating::BPlus => "b_plus",
            CarrierRating::B => "b",
            CarrierRating::BMinus => "b_minus",
            CarrierRating::CPlus => "c_plus",
            CarrierRating::C => "c",
            CarrierRating::CMinus => "c_minus",
            CarrierRating::D => "d",
            CarrierRating::E => "e",
            CarrierRating::F => "f",
        }
    }

    /// Short display label (e.g. `A++`) for human output only; matching and
    /// hashing always use the canonical [`CarrierRating::as_str`] form.
    pub fn label(self) -> &'static str {
        match self {
            CarrierRating::APlusPlus => "A++",
            CarrierRating::APlus => "A+",
            CarrierRating::A => "A",
            CarrierRating::AMinus => "A-",
            CarrierRating::BPlus => "B+",
            CarrierRating::B => "B",
            CarrierRating::BMinus => "B-",
            CarrierRating::CPlus => "C+",
            CarrierRating::C => "C",
            CarrierRating::CMinus => "C-",
            CarrierRating::D => "D",
            CarrierRating::E => "E",
            CarrierRating::F => "F",
        }
    }
}

/// Coverage kinds the engine understands. Closed vocabulary: a certificate
/// line or matrix entry with any other coverage string is a schema refusal
/// (fail-closed), not an ignored field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    GeneralLiability,
    Auto,
    WorkersComp,
    Umbrella,
}

impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Coverage::GeneralLiability => "general_liability",
            Coverage::Auto => "auto",
            Coverage::WorkersComp => "workers_comp",
            Coverage::Umbrella => "umbrella",
        }
    }

    /// Short display label for human output only.
    pub fn as_label(self) -> &'static str {
        match self {
            Coverage::GeneralLiability => "GL",
            Coverage::Auto => "Auto",
            Coverage::WorkersComp => "WC",
            Coverage::Umbrella => "Umbrella",
        }
    }
}

/// Endorsement kinds a requirement can demand on a policy line. Closed
/// vocabulary, same fail-closed rule as [`Coverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endorsement {
    AdditionalInsured,
    WaiverOfSubrogation,
}

impl Endorsement {
    pub fn as_str(self) -> &'static str {
        match self {
            Endorsement::AdditionalInsured => "additional_insured",
            Endorsement::WaiverOfSubrogation => "waiver_of_subrogation",
        }
    }
}

/// What a vendor category must carry for one coverage kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CoverageRequirement {
    /// Minimum per-occurrence limit, integer cents; must be positive.
    pub per_occurrence_cents: i128,
    /// Minimum aggregate limit, integer cents; must be positive.
    pub aggregate_cents: i128,
    /// Endorsements the selected policy line must carry. Empty is valid.
    #[serde(default)]
    pub endorsements: Vec<Endorsement>,
}

/// The requirement for one vendor category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CategoryRequirement {
    /// Critical categories drive the lockout recommendation: breach-severity
    /// gaps here recommend a hold on new POs (advisory only — see README).
    pub critical: bool,
    /// Required coverages keyed by kind; at least one entry.
    pub coverages: BTreeMap<Coverage, CoverageRequirement>,
}

/// The full requirements matrix plus family-level knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RequirementsConfig {
    /// Vendor category → requirement. The key must match the certificate's
    /// `vendor_category` (both sides are trimmed at validation).
    pub categories: BTreeMap<String, CategoryRequirement>,
    /// Warn when a required policy expires within this many days of the
    /// clock date (inclusive boundary).
    pub expiry_warning_days: i64,
    /// Carrier rating floor: a selected line's carrier below this breaches.
    pub min_carrier_rating: CarrierRating,
}

impl RequirementsConfig {
    /// Parse and validate a requirements matrix from JSON. Unknown fields,
    /// unknown vocabulary, and failing sanity checks are refusals.
    pub fn from_json_str(json: &str) -> Result<Self, CoiError> {
        let mut cfg: Self = serde_json::from_str(json)
            .map_err(|e| CoiError::Schema(format!("requirements config: {e}")))?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Trim free-form keys so lookups match trimmed certificate fields.
    fn normalize(&mut self) {
        self.categories = self
            .categories
            .iter()
            .map(|(key, value)| (key.trim().to_string(), value.clone()))
            .collect();
    }

    pub fn validate(&self) -> Result<(), CoiError> {
        if self.expiry_warning_days < 0 {
            return Err(CoiError::InvalidConfig(
                "expiry_warning_days must be >= 0".to_string(),
            ));
        }
        if self.categories.is_empty() {
            return Err(CoiError::InvalidConfig(
                "requirements matrix has no categories — refuse to run against an empty matrix"
                    .to_string(),
            ));
        }
        for (name, category) in &self.categories {
            if name.is_empty() {
                return Err(CoiError::InvalidConfig(
                    "category name is blank".to_string(),
                ));
            }
            if category.coverages.is_empty() {
                return Err(CoiError::InvalidConfig(format!(
                    "category '{name}' requires no coverages"
                )));
            }
            for (coverage, requirement) in &category.coverages {
                let coverage = coverage.as_str();
                if requirement.per_occurrence_cents <= 0 {
                    return Err(CoiError::InvalidConfig(format!(
                        "category '{name}' coverage {coverage}: per_occurrence_cents must be positive"
                    )));
                }
                if requirement.aggregate_cents <= 0 {
                    return Err(CoiError::InvalidConfig(format!(
                        "category '{name}' coverage {coverage}: aggregate_cents must be positive"
                    )));
                }
                for (index, endorsement) in requirement.endorsements.iter().enumerate() {
                    if requirement.endorsements[..index].contains(endorsement) {
                        return Err(CoiError::InvalidConfig(format!(
                            "category '{name}' coverage {coverage}: duplicate endorsement {}",
                            endorsement.as_str()
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_json() -> &'static str {
        r#"{
            "categories": {
                "electrical_contractor": {
                    "critical": true,
                    "coverages": {
                        "general_liability": {
                            "per_occurrence_cents": 100000000,
                            "aggregate_cents": 200000000,
                            "endorsements": ["additional_insured"]
                        },
                        "workers_comp": {
                            "per_occurrence_cents": 50000000,
                            "aggregate_cents": 50000000
                        }
                    }
                },
                "landscaper": {
                    "critical": false,
                    "coverages": {
                        "general_liability": {
                            "per_occurrence_cents": 10000000,
                            "aggregate_cents": 20000000
                        }
                    }
                }
            },
            "expiry_warning_days": 30,
            "min_carrier_rating": "a_minus"
        }"#
    }

    #[test]
    fn seed_config_parses_and_validates() {
        let cfg = RequirementsConfig::from_json_str(base_json()).expect("seed config is valid");
        assert_eq!(cfg.categories.len(), 2);
        assert_eq!(cfg.min_carrier_rating, CarrierRating::AMinus);
        assert!(cfg.categories["electrical_contractor"].critical);
        assert!(!cfg.categories["landscaper"].critical);
    }

    #[test]
    fn config_rejects_unknown_fields_bad_values_and_duplicates() {
        let unknown_field = base_json().replace(
            "\"expiry_warning_days\": 30",
            "\"expiry_warning_days\": 30, \"vendor_matching\": \"email\"",
        );
        assert!(matches!(
            RequirementsConfig::from_json_str(&unknown_field),
            Err(CoiError::Schema(_))
        ));

        let negative_window =
            base_json().replace("\"expiry_warning_days\": 30", "\"expiry_warning_days\": -1");
        assert!(matches!(
            RequirementsConfig::from_json_str(&negative_window),
            Err(CoiError::InvalidConfig(_))
        ));

        let zero_limit = base_json().replace(
            "\"per_occurrence_cents\": 100000000",
            "\"per_occurrence_cents\": 0",
        );
        assert!(matches!(
            RequirementsConfig::from_json_str(&zero_limit),
            Err(CoiError::InvalidConfig(_))
        ));

        let duplicate = base_json().replace(
            "\"endorsements\": [\"additional_insured\"]",
            "\"endorsements\": [\"additional_insured\", \"additional_insured\"]",
        );
        assert!(matches!(
            RequirementsConfig::from_json_str(&duplicate),
            Err(CoiError::InvalidConfig(_))
        ));

        let empty_matrix =
            r#"{"categories": {}, "expiry_warning_days": 30, "min_carrier_rating": "a"}"#;
        assert!(matches!(
            RequirementsConfig::from_json_str(empty_matrix),
            Err(CoiError::InvalidConfig(_))
        ));

        let unknown_coverage = base_json().replace("\"general_liability\"", "\"hull\"");
        assert!(matches!(
            RequirementsConfig::from_json_str(&unknown_coverage),
            Err(CoiError::Schema(_))
        ));

        let no_coverages = base_json().replace(
            "\"workers_comp\": { \"per_occurrence_cents\": 50000000, \"aggregate_cents\": 50000000 }",
            "",
        );
        // Removing the WC entry leaves GL, which is valid — instead verify an
        // explicitly empty coverages map is refused.
        let empty_coverages = r#"{
            "categories": { "landscaper": { "critical": false, "coverages": {} } },
            "expiry_warning_days": 30,
            "min_carrier_rating": "a"
        }"#;
        assert!(RequirementsConfig::from_json_str(&no_coverages).is_ok());
        assert!(matches!(
            RequirementsConfig::from_json_str(empty_coverages),
            Err(CoiError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_is_canonical_and_key_trimmed() {
        let parsed = RequirementsConfig::from_json_str(base_json()).unwrap();
        let compact = serde_json::to_string(&parsed).unwrap();
        let reparsed = RequirementsConfig::from_json_str(&compact).unwrap();
        assert_eq!(
            crate::pack::canonical_json(&parsed).unwrap(),
            crate::pack::canonical_json(&reparsed).unwrap()
        );

        let padded = base_json().replace("electrical_contractor", "  electrical_contractor  ");
        let trimmed = RequirementsConfig::from_json_str(&padded).unwrap();
        assert!(trimmed.categories.contains_key("electrical_contractor"));
    }
}
