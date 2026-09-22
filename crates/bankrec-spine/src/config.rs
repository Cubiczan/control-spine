//! Schema-checked config table (rule table) for bankrec-spine.
//!
//! The config is a JSON document parsed with `deny_unknown_fields` and
//! range-validated — a typo or an out-of-spec value refuses the run instead
//! of silently widening a tolerance. Shipped defaults are **seed values**
//! for development and CI, not a compliance baseline; production treasury
//! policy supplies its own table.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Spec ceiling on many-to-one group size: N ≤ 5 ledger lines may sum to
/// one statement line. The config may only tighten it.
pub const MAX_GROUP_SIZE_LIMIT: u8 = 5;

fn default_max_group_size() -> u8 {
    5
}

fn default_stale_days() -> i64 {
    14
}

fn default_candidate_cap() -> u32 {
    100
}

fn default_date_window_days() -> Option<i64> {
    None
}

/// Rule table for a reconciliation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BankrecConfig {
    /// Allowed amount difference, in cents, for the tolerance tier and for
    /// many-to-one group sums (± window around the statement amount).
    /// Zero collapses the tolerance tier onto exact matching.
    pub tolerance_cents: i64,
    /// Largest many-to-one group (ledger lines per statement line), 2–5.
    #[serde(default = "default_max_group_size")]
    pub max_group_size: u8,
    /// Unmatched items older than this many days escalate from warn to
    /// breach severity (the stale-item rule).
    #[serde(default = "default_stale_days")]
    pub stale_days: i64,
    /// Determinism bound on the many-to-one search: at most this many
    /// candidate ledger entries, in canonical (date, reference, input
    /// order) order, are considered per statement line. Items beyond the
    /// bound stay unmatched and surface as findings — never silently
    /// dropped.
    #[serde(default = "default_candidate_cap")]
    pub many_to_one_candidate_cap: u32,
    /// Optional date-proximity window for many-to-one groups, in days: when
    /// set, every ledger entry in a group must lie within this many days of
    /// the statement line's date (in either direction). `None` (the seed
    /// default) imposes no date constraint — matching is amount- and
    /// order-driven only.
    #[serde(default = "default_date_window_days")]
    pub many_to_one_date_window_days: Option<i64>,
}

impl BankrecConfig {
    /// Range validation on top of the schema check.
    pub fn validate(&self) -> Result<(), String> {
        if self.tolerance_cents < 0 {
            return Err("tolerance_cents must be >= 0".to_string());
        }
        if self.max_group_size < 2 || self.max_group_size > MAX_GROUP_SIZE_LIMIT {
            return Err(format!(
                "max_group_size must be between 2 and {MAX_GROUP_SIZE_LIMIT} (spec pins N ≤ 5)"
            ));
        }
        if self.stale_days < 0 {
            return Err("stale_days must be >= 0".to_string());
        }
        if self.many_to_one_candidate_cap == 0 || self.many_to_one_candidate_cap > 1000 {
            return Err("many_to_one_candidate_cap must be between 1 and 1000".to_string());
        }
        if self.many_to_one_date_window_days.is_some_and(|w| w < 0) {
            return Err("many_to_one_date_window_days must be >= 0 when set".to_string());
        }
        Ok(())
    }
}

/// Parse and validate the config from its canonical JSON bytes.
pub fn parse_config(bytes: &[u8]) -> crate::Result<BankrecConfig> {
    let config: BankrecConfig = serde_json::from_slice(bytes)
        .map_err(|e| Error::Config(format!("malformed config JSON: {e}")))?;
    config.validate().map_err(|e| {
        Error::Config(format!(
            "{e} (full value: {})",
            String::from_utf8_lossy(bytes)
        ))
    })?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config_bytes(tweaks: serde_json::Value) -> Vec<u8> {
        let mut v = json!({
            "tolerance_cents": 500,
            "max_group_size": 5,
            "stale_days": 14,
            "many_to_one_candidate_cap": 100
        });
        if let (serde_json::Value::Object(base), serde_json::Value::Object(patch)) =
            (&mut v, tweaks)
        {
            for (k, val) in patch {
                base.insert(k.clone(), val);
            }
        }
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn config_parses_full_table() {
        let cfg = parse_config(&config_bytes(json!({}))).unwrap();
        assert_eq!(cfg.tolerance_cents, 500);
        assert_eq!(cfg.max_group_size, 5);
        assert_eq!(cfg.stale_days, 14);
        assert_eq!(cfg.many_to_one_candidate_cap, 100);
    }

    #[test]
    fn config_defaults_apply_for_optional_fields() {
        let bytes = serde_json::to_vec(&json!({ "tolerance_cents": 0 })).unwrap();
        let cfg = parse_config(&bytes).unwrap();
        assert_eq!(cfg.max_group_size, 5);
        assert_eq!(cfg.stale_days, 14);
        assert_eq!(cfg.many_to_one_candidate_cap, 100);
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let bytes =
            serde_json::to_vec(&json!({ "tolerance_cents": 0, "toleranace_cents": 1 })).unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_rejects_negative_tolerance() {
        let bytes = serde_json::to_vec(&json!({ "tolerance_cents": -1 })).unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_rejects_max_group_size_above_spec_limit() {
        let bytes =
            serde_json::to_vec(&json!({ "tolerance_cents": 0, "max_group_size": 6 })).unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_rejects_max_group_size_below_two() {
        let bytes =
            serde_json::to_vec(&json!({ "tolerance_cents": 0, "max_group_size": 1 })).unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_rejects_negative_stale_days() {
        let bytes = serde_json::to_vec(&json!({ "tolerance_cents": 0, "stale_days": -1 })).unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_rejects_zero_candidate_cap() {
        let bytes =
            serde_json::to_vec(&json!({ "tolerance_cents": 0, "many_to_one_candidate_cap": 0 }))
                .unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }

    #[test]
    fn config_defaults_to_no_date_window() {
        let bytes = serde_json::to_vec(&json!({ "tolerance_cents": 0 })).unwrap();
        let config = parse_config(&bytes).unwrap();
        assert_eq!(config.many_to_one_date_window_days, None);
    }

    #[test]
    fn config_rejects_negative_date_window() {
        let bytes = serde_json::to_vec(&json!({
            "tolerance_cents": 0,
            "many_to_one_date_window_days": -1
        }))
        .unwrap();
        assert!(matches!(parse_config(&bytes), Err(Error::Config(_))));
    }
}
