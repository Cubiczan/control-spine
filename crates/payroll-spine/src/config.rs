//! Schema-checked JSON config tables for the payroll engine.
//!
//! Every struct refuses unknown fields (`deny_unknown_fields`) and is
//! validated beyond shape by [`PayrollConfig::validate`] — rates within
//! 0..=100%, positive wage bases, ascending bracket tables, FUTA credit not
//! above the federal rate. Malformed config is a refusal, never a
//! best-effort guess. Shipped values are seed data (see README).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine::{PayrollError, RATE_CAP};

/// Withholding bracket tables by filing status. The lower-bounds-only
/// encoding makes brackets contiguous by construction: each bracket spans
/// from its `lower_cents` up to the next bracket's lower bound (the last is
/// open-ended).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayrollConfig {
    pub fica: FicaConfig,
    pub employer: EmployerConfig,
    pub brackets: BracketTables,
    /// Whether employee 401(k) deferrals are pre-tax for federal income-tax
    /// withholding (plan-level election). Deferrals never reduce
    /// FICA/Medicare wages either way — that is statutory, not a flag.
    pub retirement_401k_pre_tax: bool,
    /// Register tolerance in cents: variances strictly greater than this are
    /// flagged. Zero flags any difference, including one cent.
    pub register_tolerance_cents: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FicaConfig {
    /// Social Security employee rate, micro-percent (6_200_000 = 6.2%).
    pub ss_rate_micro: i128,
    /// Social Security wage base in cents for the year.
    pub ss_wage_base_cents: i128,
    pub medicare_rate_micro: i128,
    pub additional_medicare_rate_micro: i128,
    /// YTD threshold above which the additional Medicare rate applies, cents.
    pub additional_medicare_threshold_cents: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmployerConfig {
    pub futa_rate_micro: i128,
    /// FUTA credit reduction applied against the federal rate
    /// (5_400_000 = 5.4%).
    pub futa_credit_rate_micro: i128,
    pub futa_wage_base_cents: i128,
    /// Per-state SUTA schedules keyed by state code.
    pub suta: BTreeMap<String, SutaConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SutaConfig {
    pub rate_micro: i128,
    pub wage_base_cents: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BracketTables {
    pub single: Vec<Bracket>,
    pub married: Vec<Bracket>,
}

/// One marginal bracket: from `lower_cents` (inclusive) to the next
/// bracket's lower bound (exclusive), taxed at `rate_micro`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bracket {
    /// Lower bound of the bracket in annual cents (inclusive).
    pub lower_cents: i128,
    /// Marginal rate over the bracket, micro-percent.
    pub rate_micro: i128,
}

/// Filing status selecting the bracket table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilingStatus {
    Single,
    Married,
}

impl BracketTables {
    pub fn table(&self, status: FilingStatus) -> &[Bracket] {
        match status {
            FilingStatus::Single => &self.single,
            FilingStatus::Married => &self.married,
        }
    }
}

fn check_rate(name: &str, rate_micro: i128) -> Result<(), PayrollError> {
    if !(0..=RATE_CAP).contains(&rate_micro) {
        return Err(PayrollError::InvalidConfig(format!(
            "{name}: rate must be within 0..=100% (0..={RATE_CAP} micro-percent), got {rate_micro}"
        )));
    }
    Ok(())
}

fn check_positive(name: &str, cents: i128) -> Result<(), PayrollError> {
    if cents <= 0 {
        return Err(PayrollError::InvalidConfig(format!(
            "{name}: must be positive, got {cents}"
        )));
    }
    Ok(())
}

fn check_bracket_table(name: &str, brackets: &[Bracket]) -> Result<(), PayrollError> {
    if brackets.is_empty() {
        return Err(PayrollError::InvalidConfig(format!(
            "brackets.{name}: at least one bracket is required"
        )));
    }
    if brackets[0].lower_cents != 0 {
        return Err(PayrollError::InvalidConfig(format!(
            "brackets.{name}: the first bracket must start at 0 cents"
        )));
    }
    for pair in brackets.windows(2) {
        if pair[1].lower_cents <= pair[0].lower_cents {
            return Err(PayrollError::InvalidConfig(format!(
                "brackets.{name}: bracket lower bounds must be strictly ascending"
            )));
        }
    }
    for (i, bracket) in brackets.iter().enumerate() {
        check_rate(
            &format!("brackets.{name}[{i}].rate_micro"),
            bracket.rate_micro,
        )?;
    }
    Ok(())
}

impl PayrollConfig {
    /// Fail-closed config validation beyond the serde schema.
    pub fn validate(&self) -> Result<(), PayrollError> {
        check_rate("fica.ss_rate_micro", self.fica.ss_rate_micro)?;
        check_rate("fica.medicare_rate_micro", self.fica.medicare_rate_micro)?;
        check_rate(
            "fica.additional_medicare_rate_micro",
            self.fica.additional_medicare_rate_micro,
        )?;
        check_positive("fica.ss_wage_base_cents", self.fica.ss_wage_base_cents)?;
        check_positive(
            "fica.additional_medicare_threshold_cents",
            self.fica.additional_medicare_threshold_cents,
        )?;

        check_rate("employer.futa_rate_micro", self.employer.futa_rate_micro)?;
        check_rate(
            "employer.futa_credit_rate_micro",
            self.employer.futa_credit_rate_micro,
        )?;
        if self.employer.futa_credit_rate_micro > self.employer.futa_rate_micro {
            return Err(PayrollError::InvalidConfig(
                "employer.futa_credit_rate_micro: credit cannot exceed the federal FUTA rate"
                    .to_string(),
            ));
        }
        check_positive(
            "employer.futa_wage_base_cents",
            self.employer.futa_wage_base_cents,
        )?;
        for (state, schedule) in &self.employer.suta {
            check_rate(
                &format!("employer.suta.{state}.rate_micro"),
                schedule.rate_micro,
            )?;
            check_positive(
                &format!("employer.suta.{state}.wage_base_cents"),
                schedule.wage_base_cents,
            )?;
        }

        check_bracket_table("single", &self.brackets.single)?;
        check_bracket_table("married", &self.brackets.married)?;

        if self.register_tolerance_cents < 0 {
            return Err(PayrollError::InvalidConfig(
                "register_tolerance_cents: must not be negative".to_string(),
            ));
        }
        Ok(())
    }
}
