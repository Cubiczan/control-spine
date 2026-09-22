//! The typed certificate input.
//!
//! COI data is manually typed (from a PDF, portal, or email) — the engine's
//! boundary is a closed-vocabulary, schema-checked document. Malformed
//! certificates are refused, never coerced: unknown fields, unknown
//! coverage/endorsement/rating vocabulary, non-positive limits, inverted
//! dates, and blank identifiers are all hard refusals (fail-closed).

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::config::{CarrierRating, Coverage, Endorsement};
use crate::error::CoiError;

/// A manually typed certificate of insurance for one vendor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Certificate {
    /// Stable vendor business key — also the finding subject every signoff
    /// receipt must name.
    pub vendor_id: String,
    /// Vendor category as used in the requirements matrix.
    pub vendor_category: String,
    /// Policy lines; a multi-policy certificate maps each line to a coverage
    /// kind. Empty is valid — every required coverage then fails missing.
    pub policies: Vec<PolicyLine>,
}

/// One policy line as typed from the certificate. Money is integer cents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct PolicyLine {
    pub policy_number: String,
    pub carrier_name: String,
    pub carrier_rating: CarrierRating,
    pub coverage: Coverage,
    /// Per-occurrence limit in integer cents; positive.
    pub per_occurrence_limit_cents: i128,
    /// Aggregate limit in integer cents; positive.
    pub aggregate_limit_cents: i128,
    /// Coverage start; the engine never reads a clock.
    pub effective_date: NaiveDate,
    /// Last day the policy is valid (inclusive).
    pub expiration_date: NaiveDate,
    #[serde(default)]
    pub endorsements: Vec<Endorsement>,
}

impl Certificate {
    /// Parse and validate a certificate from JSON. Unknown fields and
    /// unknown vocabulary are schema refusals; sanity failures are
    /// malformed-certificate refusals.
    pub fn from_json_str(json: &str) -> Result<Self, CoiError> {
        let mut cert: Self = serde_json::from_str(json)
            .map_err(|e| CoiError::Schema(format!("certificate: {e}")))?;
        cert.normalize();
        cert.validate()?;
        Ok(cert)
    }

    /// Trim free-form identifiers so lookups and signoff subjects are exact.
    fn normalize(&mut self) {
        self.vendor_id = self.vendor_id.trim().to_string();
        self.vendor_category = self.vendor_category.trim().to_string();
        for policy in &mut self.policies {
            policy.policy_number = policy.policy_number.trim().to_string();
            policy.carrier_name = policy.carrier_name.trim().to_string();
        }
    }

    pub fn validate(&self) -> Result<(), CoiError> {
        if self.vendor_id.is_empty() {
            return Err(CoiError::MalformedCertificate(
                "vendor_id is blank".to_string(),
            ));
        }
        if self.vendor_category.is_empty() {
            return Err(CoiError::MalformedCertificate(
                "vendor_category is blank".to_string(),
            ));
        }
        for (index, policy) in self.policies.iter().enumerate() {
            let at = format!("policy[{index}]");
            if policy.policy_number.is_empty() {
                return Err(CoiError::MalformedCertificate(format!(
                    "{at}: policy_number is blank"
                )));
            }
            if policy.carrier_name.is_empty() {
                return Err(CoiError::MalformedCertificate(format!(
                    "{at}: carrier_name is blank"
                )));
            }
            if policy.per_occurrence_limit_cents <= 0 {
                return Err(CoiError::MalformedCertificate(format!(
                    "{at}: per_occurrence_limit_cents must be positive"
                )));
            }
            if policy.aggregate_limit_cents <= 0 {
                return Err(CoiError::MalformedCertificate(format!(
                    "{at}: aggregate_limit_cents must be positive"
                )));
            }
            if policy.effective_date > policy.expiration_date {
                return Err(CoiError::MalformedCertificate(format!(
                    "{at}: effective_date {} is after expiration_date {}",
                    policy.effective_date, policy.expiration_date
                )));
            }
            for (index, endorsement) in policy.endorsements.iter().enumerate() {
                if policy.endorsements[..index].contains(endorsement) {
                    return Err(CoiError::MalformedCertificate(format!(
                        "{at}: duplicate endorsement {}",
                        endorsement.as_str()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_json() -> &'static str {
        r#"{
            "vendor_id": "V-1001",
            "vendor_category": "electrical_contractor",
            "policies": [
                {
                    "policy_number": "GL-2026-001",
                    "carrier_name": "Seed Mutual",
                    "carrier_rating": "a",
                    "coverage": "general_liability",
                    "per_occurrence_limit_cents": 100000000,
                    "aggregate_limit_cents": 200000000,
                    "effective_date": "2026-01-01",
                    "expiration_date": "2027-12-31",
                    "endorsements": ["additional_insured", "waiver_of_subrogation"]
                }
            ]
        }"#
    }

    #[test]
    fn typed_certificate_parses() {
        let cert = Certificate::from_json_str(cert_json()).expect("seed certificate is valid");
        assert_eq!(cert.vendor_id, "V-1001");
        assert_eq!(cert.policies[0].carrier_rating, CarrierRating::A);
        assert_eq!(cert.policies[0].coverage, Coverage::GeneralLiability);
        assert_eq!(cert.policies[0].endorsements.len(), 2);
    }

    #[test]
    fn cert_rejects_unknown_vocabulary_and_fields() {
        let unknown_coverage = cert_json().replace("general_liability", "hull");
        assert!(matches!(
            Certificate::from_json_str(&unknown_coverage),
            Err(CoiError::Schema(_))
        ));

        let unknown_endorsement = cert_json().replace("additional_insured", "sole_proprietor");
        assert!(matches!(
            Certificate::from_json_str(&unknown_endorsement),
            Err(CoiError::Schema(_))
        ));

        let unknown_rating =
            cert_json().replace("\"carrier_rating\": \"a\"", "\"carrier_rating\": \"z\"");
        assert!(matches!(
            Certificate::from_json_str(&unknown_rating),
            Err(CoiError::Schema(_))
        ));

        let unknown_field = cert_json().replace(
            "\"vendor_id\": \"V-1001\"",
            "\"vendor_id\": \"V-1001\", \"vendor_notes\": \"x\"",
        );
        assert!(matches!(
            Certificate::from_json_str(&unknown_field),
            Err(CoiError::Schema(_))
        ));

        let duplicate = cert_json().replace(
            "\"endorsements\": [\"additional_insured\", \"waiver_of_subrogation\"]",
            "\"endorsements\": [\"additional_insured\", \"additional_insured\"]",
        );
        assert!(matches!(
            Certificate::from_json_str(&duplicate),
            Err(CoiError::MalformedCertificate(_))
        ));
    }

    #[test]
    fn cert_rejects_bad_shapes() {
        let zero_limit = cert_json().replace("100000000", "0");
        assert!(matches!(
            Certificate::from_json_str(&zero_limit),
            Err(CoiError::MalformedCertificate(_))
        ));

        let inverted = cert_json().replace(
            "\"effective_date\": \"2026-01-01\"",
            "\"effective_date\": \"2028-01-01\"",
        );
        assert!(matches!(
            Certificate::from_json_str(&inverted),
            Err(CoiError::MalformedCertificate(_))
        ));

        let blank_vendor = cert_json().replace("V-1001", "   ");
        assert!(matches!(
            Certificate::from_json_str(&blank_vendor),
            Err(CoiError::MalformedCertificate(_))
        ));

        let bad_date = cert_json().replace("2026-01-01", "01/01/2026");
        assert!(matches!(
            Certificate::from_json_str(&bad_date),
            Err(CoiError::Schema(_))
        ));
    }

    #[test]
    fn cert_identifiers_are_trimmed() {
        let padded = cert_json().replace("V-1001", "  V-1001  ");
        let cert = Certificate::from_json_str(&padded).expect("padding is tolerated");
        assert_eq!(cert.vendor_id, "V-1001");
    }
}
