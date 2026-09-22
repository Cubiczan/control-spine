//! Normalized financials input — the caller-attested clock and periods.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::units::Cents;

/// Normalized financials. `measurement_date` is caller-supplied — the clock
/// is an input, never read. Period rows are the entity's fiscal quarters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Financials {
    pub entity: String,
    pub measurement_date: NaiveDate,
    pub periods: Vec<PeriodFinancials>,
}

/// One fiscal quarter. Flow items (EBITDA, interest, rent, current
/// maturities) are the quarter's amounts; stock items (total debt, current
/// assets, current liabilities) are the quarter-end balances. LTM windows
/// sum the flow items of the trailing four rows and take stock items from
/// the last row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeriodFinancials {
    pub period_id: String,
    pub period_end: NaiveDate,
    pub total_debt_cents: Cents,
    pub ebitda_cents: Cents,
    pub interest_expense_cents: Cents,
    pub current_assets_cents: Cents,
    pub current_liabilities_cents: Cents,
    pub rent_expense_cents: Cents,
    pub current_maturities_cents: Cents,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn financials_reject_unknown_fields() {
        let json = r#"{"entity":"E","measurement_date":"2026-06-30","periods":[],"extra":1}"#;
        assert!(serde_json::from_str::<Financials>(json).is_err());
    }

    #[test]
    fn period_rejects_unknown_fields() {
        let json = r#"{"period_id":"Q1","period_end":"2026-03-31","total_debt_cents":"0","ebitda_cents":"0","interest_expense_cents":"0","current_assets_cents":"0","current_liabilities_cents":"0","rent_expense_cents":"0","current_maturities_cents":"0","nope":1}"#;
        assert!(serde_json::from_str::<PeriodFinancials>(json).is_err());
    }

    #[test]
    fn money_fields_are_string_cents() {
        let json = r#"{"period_id":"Q1","period_end":"2026-03-31","total_debt_cents":"3500000000","ebitda_cents":"-100","interest_expense_cents":"0","current_assets_cents":"0","current_liabilities_cents":"0","rent_expense_cents":"0","current_maturities_cents":"0"}"#;
        let p: PeriodFinancials = serde_json::from_str(json).unwrap();
        assert_eq!(p.ebitda_cents.get(), -100);
        assert_eq!(p.total_debt_cents.get(), 3_500_000_000);
    }
}
