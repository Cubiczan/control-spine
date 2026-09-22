//! Input contract and boundary normalization for bankrec-spine.
//!
//! Sign conventions are normalized here, at the boundary — the matching
//! engine only ever sees canonical signed cents (positive = money into the
//! account):
//!
//! * **Statement lines** carry `amount_cents` already signed in flow
//!   terms: positive = money into the account (a deposit / bank credit),
//!   negative = money out of the account (a withdrawal / bank debit).
//! * **Ledger entries** carry a positive magnitude plus the cash-account
//!   `side`: a debit to cash is money into the account (+), a credit to
//!   cash is money out (−). This is the books' convention, which points
//!   opposite to the bank's labels for the same movement — a bank debit
//!   (money out) is a credit entry in the cash account.
//!
//! Parsing fails closed: malformed JSON, unparsable dates, zero-amount
//! statement lines, non-positive ledger magnitudes, and ambiguous ids are
//! all refused rather than coerced.

use chrono::NaiveDate;
use serde::Deserialize;

use crate::Error;

/// Cash-account side of a ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerSide {
    /// Debit to cash: money into the account.
    Debit,
    /// Credit to cash: money out of the account.
    Credit,
}

/// Wire shape of a bank statement line. `amount_cents` is signed: positive
/// = money into the account, negative = money out. Must be non-zero — a
/// zero-amount line has no flow direction and is refused.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementLine {
    pub id: String,
    /// ISO `YYYY-MM-DD`. The caller supplies all dates; the engine never
    /// reads a clock.
    pub date: String,
    /// Statement reference, compared exactly (system key, no normalization).
    pub reference: String,
    pub amount_cents: i128,
}

/// Wire shape of a cash-account ledger entry. `amount_cents` is a positive
/// magnitude; direction comes from `side`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub id: String,
    /// ISO `YYYY-MM-DD`.
    pub date: String,
    /// Ledger reference, compared exactly.
    pub reference: String,
    pub side: LedgerSide,
    pub amount_cents: i128,
}

/// Wire shape of the inputs document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationInputs {
    pub statement_lines: Vec<StatementLine>,
    pub ledger_entries: Vec<LedgerEntry>,
}

/// Validated statement line in canonical form: parsed date and signed
/// canonical amount (positive = money into the account).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStatement {
    pub id: String,
    pub date: NaiveDate,
    pub reference: String,
    pub amount: i128,
}

/// Validated ledger entry in canonical form: parsed date and signed
/// canonical amount (debit = +magnitude, credit = −magnitude).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLedger {
    pub id: String,
    pub date: NaiveDate,
    pub reference: String,
    pub amount: i128,
}

/// Fully validated, boundary-normalized inputs. The only shape
/// [`crate::engine::compute`] accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInputs {
    pub statements: Vec<CanonicalStatement>,
    pub ledgers: Vec<CanonicalLedger>,
}

/// Parse and validate the inputs document from its canonical JSON bytes.
pub fn parse_inputs(bytes: &[u8]) -> crate::Result<ValidatedInputs> {
    let raw: ReconciliationInputs = serde_json::from_slice(bytes)
        .map_err(|e| Error::Inputs(format!("malformed inputs JSON: {e}")))?;

    // Ids are the finding subjects in evidence packs; they must be unique
    // across both collections so a signoff receipt names exactly one item.
    let mut seen_ids = std::collections::HashSet::new();

    let mut statements = Vec::with_capacity(raw.statement_lines.len());
    for line in &raw.statement_lines {
        if line.id.is_empty() {
            return Err(Error::Inputs(
                "statement line id must be non-empty".to_string(),
            ));
        }
        if !seen_ids.insert(line.id.clone()) {
            return Err(Error::Inputs(format!("duplicate item id: {}", line.id)));
        }
        let date = parse_date(&line.date)
            .map_err(|e| Error::Inputs(format!("statement line {}: {e}", line.id)))?;
        if line.amount_cents == 0 {
            return Err(Error::Inputs(format!(
                "statement line {}: amount_cents must be non-zero (positive = money into the account)",
                line.id
            )));
        }
        statements.push(CanonicalStatement {
            id: line.id.clone(),
            date,
            reference: line.reference.clone(),
            amount: line.amount_cents,
        });
    }

    let mut ledgers = Vec::with_capacity(raw.ledger_entries.len());
    for entry in &raw.ledger_entries {
        if entry.id.is_empty() {
            return Err(Error::Inputs(
                "ledger entry id must be non-empty".to_string(),
            ));
        }
        if !seen_ids.insert(entry.id.clone()) {
            return Err(Error::Inputs(format!("duplicate item id: {}", entry.id)));
        }
        let date = parse_date(&entry.date)
            .map_err(|e| Error::Inputs(format!("ledger entry {}: {e}", entry.id)))?;
        if entry.amount_cents <= 0 {
            return Err(Error::Inputs(format!(
                "ledger entry {}: amount_cents must be a positive magnitude; direction comes from side",
                entry.id
            )));
        }
        let amount = match entry.side {
            LedgerSide::Debit => entry.amount_cents,
            LedgerSide::Credit => -entry.amount_cents,
        };
        ledgers.push(CanonicalLedger {
            id: entry.id.clone(),
            date,
            reference: entry.reference.clone(),
            amount,
        });
    }

    Ok(ValidatedInputs {
        statements,
        ledgers,
    })
}

fn parse_date(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| format!("date {s:?} is not ISO YYYY-MM-DD"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inputs_json() -> serde_json::Value {
        json!({
            "statement_lines": [
                {"id": "S1", "date": "2026-09-01", "reference": "R1", "amount_cents": 10000}
            ],
            "ledger_entries": [
                {"id": "L1", "date": "2026-09-01", "reference": "R1", "side": "debit", "amount_cents": 10000}
            ]
        })
    }

    #[test]
    fn parse_inputs_accepts_well_formed_document() {
        let bytes = serde_json::to_vec(&inputs_json()).unwrap();
        let v = parse_inputs(&bytes).unwrap();
        assert_eq!(v.statements.len(), 1);
        assert_eq!(v.ledgers.len(), 1);
        assert_eq!(v.statements[0].amount, 10_000);
        // Debit to cash is canonical positive.
        assert_eq!(v.ledgers[0].amount, 10_000);
    }

    #[test]
    fn ledger_credit_normalizes_to_negative() {
        let bytes = serde_json::to_vec(&json!({
            "statement_lines": [],
            "ledger_entries": [
                {"id": "L1", "date": "2026-09-01", "reference": "R1", "side": "credit", "amount_cents": 7000}
            ]
        }))
        .unwrap();
        let v = parse_inputs(&bytes).unwrap();
        assert_eq!(v.ledgers[0].amount, -7_000);
    }

    #[test]
    fn inputs_reject_unknown_fields() {
        let mut v = inputs_json();
        v["surprise"] = json!(1);
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(parse_inputs(&bytes), Err(Error::Inputs(_))));
    }

    #[test]
    fn inputs_reject_zero_amount_statement_line() {
        let mut v = inputs_json();
        v["statement_lines"][0]["amount_cents"] = json!(0);
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(parse_inputs(&bytes), Err(Error::Inputs(_))));
    }

    #[test]
    fn inputs_reject_nonpositive_ledger_magnitude() {
        let mut v = inputs_json();
        v["ledger_entries"][0]["amount_cents"] = json!(-5);
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(parse_inputs(&bytes), Err(Error::Inputs(_))));
    }

    #[test]
    fn inputs_reject_duplicate_ids_across_collections() {
        let mut v = inputs_json();
        v["ledger_entries"][0]["id"] = json!("S1");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(parse_inputs(&bytes), Err(Error::Inputs(_))));
    }

    #[test]
    fn inputs_reject_bad_date() {
        let mut v = inputs_json();
        v["statement_lines"][0]["date"] = json!("09/01/2026");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(parse_inputs(&bytes), Err(Error::Inputs(_))));
    }
}
