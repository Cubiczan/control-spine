//! Schema-checked configuration tables for capa-spine.
//!
//! [`CapaConfig::parse`] is the only sanctioned entry point: it enforces the
//! JSON schema (unknown fields refused), matrix completeness over every
//! category × detectability cell, and sanity bounds on the windows. A config
//! that cannot be validated fails closed before the engine runs.

use serde::{Deserialize, Serialize};
use spine::Severity;

use crate::model::{Category, Detectability};

/// One severity-matrix cell: category × detectability → severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityCell {
    pub category: Category,
    pub detectability: Detectability,
    pub severity: Severity,
}

/// Hours allowed for containment, per classified severity. `None` means
/// containment is not required at that severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentHours {
    #[serde(default)]
    pub breach: Option<u64>,
    #[serde(default)]
    pub warn: Option<u64>,
    #[serde(default)]
    pub info: Option<u64>,
}

/// Aging thresholds for CAPAs that remain open — including closures the
/// engine refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgingRules {
    pub warn_after_days: u64,
    pub breach_after_days: u64,
}

/// The full configuration table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapaConfig {
    pub severity_matrix: Vec<SeverityCell>,
    pub containment_hours: ContainmentHours,
    pub aging: AgingRules,
    pub effectiveness_window_days: u64,
}

/// Refusal reasons raised fail-closed before any finding is evaluated:
/// configuration validation and population invariants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config is not valid JSON: {0}")]
    Json(String),
    #[error("config schema violation: {0}")]
    Schema(String),
    #[error("severity matrix incomplete: no cell for {0} × {1}")]
    MissingMatrixCell(String, String),
    #[error("severity matrix ambiguous: duplicate cell for {0} × {1}")]
    DuplicateMatrixCell(String, String),
    #[error(
        "population ambiguous: duplicate CAPA id {0} — ids are subject keys for findings and signoff receipts and must be unique"
    )]
    DuplicateCapaId(String),
    #[error(
        "aging thresholds invalid: warn_after_days ({warn_after_days}) must be positive and strictly less than breach_after_days ({breach_after_days})"
    )]
    AgingThresholds {
        warn_after_days: u64,
        breach_after_days: u64,
    },
    #[error("effectiveness_window_days ({0}) must be positive")]
    EffectivenessWindow(u64),
    #[error("containment window for {0}-severity CAPAs must be at least one hour when set")]
    ContainmentWindow(String),
}

impl CapaConfig {
    /// Parse and validate config bytes. Fail-closed: any doubt refuses.
    pub fn parse(bytes: &[u8]) -> Result<CapaConfig, ConfigError> {
        let config: CapaConfig = serde_json::from_slice(bytes).map_err(|e| {
            if e.is_syntax() || e.is_eof() {
                ConfigError::Json(e.to_string())
            } else {
                ConfigError::Schema(e.to_string())
            }
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Matrix: every cell present exactly once.
        for category in Category::ALL {
            for detectability in Detectability::ALL {
                let cell_count = self
                    .severity_matrix
                    .iter()
                    .filter(|c| c.category == category && c.detectability == detectability)
                    .count();
                match cell_count {
                    0 => {
                        return Err(ConfigError::MissingMatrixCell(
                            category.to_string(),
                            detectability.to_string(),
                        ))
                    }
                    1 => {}
                    _ => {
                        return Err(ConfigError::DuplicateMatrixCell(
                            category.to_string(),
                            detectability.to_string(),
                        ))
                    }
                }
            }
        }

        // Containment windows are positive when set.
        for (label, hours) in [
            ("breach", self.containment_hours.breach),
            ("warn", self.containment_hours.warn),
            ("info", self.containment_hours.info),
        ] {
            if hours.is_some_and(|h| h == 0) {
                return Err(ConfigError::ContainmentWindow(label.to_string()));
            }
        }

        // Aging: warn strictly inside breach, and positive.
        if self.aging.warn_after_days == 0
            || self.aging.warn_after_days >= self.aging.breach_after_days
        {
            return Err(ConfigError::AgingThresholds {
                warn_after_days: self.aging.warn_after_days,
                breach_after_days: self.aging.breach_after_days,
            });
        }

        if self.effectiveness_window_days == 0 {
            return Err(ConfigError::EffectivenessWindow(0));
        }

        Ok(())
    }

    /// Matrix severity for a (category, detectability) cell. `None` only for
    /// configs built without `parse` — the engine treats that as an error.
    pub fn severity_for(
        &self,
        category: Category,
        detectability: Detectability,
    ) -> Option<Severity> {
        self.severity_matrix
            .iter()
            .find(|c| c.category == category && c.detectability == detectability)
            .map(|c| c.severity)
    }

    /// Containment window in hours for a classified severity, if required.
    pub fn containment_hours_for(&self, severity: Severity) -> Option<u64> {
        match severity {
            Severity::Breach => self.containment_hours.breach,
            Severity::Warn => self.containment_hours.warn,
            Severity::Info => self.containment_hours.info,
        }
    }
}
