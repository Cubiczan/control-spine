//! Transaction input for the commission engine: typed sales and returns,
//! schema-checked JSON. Validation is fail-closed — a malformed input file
//! refuses to load rather than computing on guesswork.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// Transaction kind. A return reverses credits of the sale it references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnKind {
    Sale,
    Return,
}

/// One credited role on a sale. Collisions — two credits of the same role
/// competing for one transaction — are resolved by explicit `priority`
/// (lower wins), never by input order; an exact tie drops the role's credit
/// and raises a breach finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credit {
    pub rep_id: String,
    pub role: String,
    /// Lower number = higher priority.
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// Unique within the file.
    pub transaction_id: String,
    /// Transaction date — drives plan-version assignment (caller-supplied
    /// data; the engine never reads a clock).
    pub date: NaiveDate,
    /// Positive integer cents. Returns also carry a positive amount; the
    /// kind determines the sign of the resulting credit lines.
    pub amount_cents: i128,
    pub kind: TxnKind,
    /// Sales must not set this; returns must reference a sale in this file.
    #[serde(default)]
    pub original_transaction_id: Option<String>,
    /// Sales: one or more credits. Returns: must be empty — a return mirrors
    /// the original's winning credits, which is what ties the clawback to
    /// the original.
    #[serde(default)]
    pub credits: Vec<Credit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionsFile {
    pub transactions: Vec<Transaction>,
}

/// Transaction input refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputError {
    #[error("transactions file must not be empty")]
    Empty,
    #[error("transaction {id:?}: transaction_id must be non-empty")]
    EmptyTransactionId { id: String },
    #[error("duplicate transaction_id {id:?}")]
    DuplicateTransactionId { id: String },
    #[error("transaction {id:?}: amount_cents must be positive")]
    NonPositiveAmount { id: String },
    #[error("transaction {id:?}: sale must carry at least one credit")]
    SaleWithoutCredits { id: String },
    #[error("transaction {id:?}: sale must not set original_transaction_id")]
    SaleWithOriginal { id: String },
    #[error("transaction {id:?}: return must set original_transaction_id")]
    ReturnWithoutOriginal { id: String },
    #[error("transaction {id:?}: return must not reference itself")]
    SelfReferencingReturn { id: String },
    #[error("transaction {id:?}: return references unknown transaction {original:?}")]
    UnknownOriginal { id: String, original: String },
    #[error("transaction {id:?}: return references {original:?} which is not a sale")]
    OriginalNotSale { id: String, original: String },
    #[error(
        "transaction {id:?}: return must not carry credits; it mirrors the original's credits"
    )]
    ReturnWithCredits { id: String },
    #[error("transaction {id:?}: credit rep_id and role must be non-empty")]
    EmptyCreditIdentity { id: String },
}

impl TransactionsFile {
    /// Fail-closed input validation, including cross-references (a return
    /// must point at a sale that exists in the same file).
    pub fn validate(&self) -> Result<(), InputError> {
        if self.transactions.is_empty() {
            return Err(InputError::Empty);
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.transactions {
            if t.transaction_id.trim().is_empty() {
                return Err(InputError::EmptyTransactionId {
                    id: t.transaction_id.clone(),
                });
            }
            if !seen.insert(t.transaction_id.clone()) {
                return Err(InputError::DuplicateTransactionId {
                    id: t.transaction_id.clone(),
                });
            }
            if t.amount_cents <= 0 {
                return Err(InputError::NonPositiveAmount {
                    id: t.transaction_id.clone(),
                });
            }
            match t.kind {
                TxnKind::Sale => {
                    if t.credits.is_empty() {
                        return Err(InputError::SaleWithoutCredits {
                            id: t.transaction_id.clone(),
                        });
                    }
                    if t.original_transaction_id.is_some() {
                        return Err(InputError::SaleWithOriginal {
                            id: t.transaction_id.clone(),
                        });
                    }
                }
                TxnKind::Return => {
                    let original = t.original_transaction_id.as_deref().ok_or_else(|| {
                        InputError::ReturnWithoutOriginal {
                            id: t.transaction_id.clone(),
                        }
                    })?;
                    if original.trim().is_empty() {
                        return Err(InputError::ReturnWithoutOriginal {
                            id: t.transaction_id.clone(),
                        });
                    }
                    if original == t.transaction_id {
                        return Err(InputError::SelfReferencingReturn {
                            id: t.transaction_id.clone(),
                        });
                    }
                    if !t.credits.is_empty() {
                        return Err(InputError::ReturnWithCredits {
                            id: t.transaction_id.clone(),
                        });
                    }
                }
            }
            for c in &t.credits {
                if c.rep_id.trim().is_empty() || c.role.trim().is_empty() {
                    return Err(InputError::EmptyCreditIdentity {
                        id: t.transaction_id.clone(),
                    });
                }
            }
        }
        // Cross-references second, after ids are known to be unique.
        for t in &self.transactions {
            if t.kind == TxnKind::Return {
                let original = t
                    .original_transaction_id
                    .as_deref()
                    .expect("validated above");
                let target = self
                    .transactions
                    .iter()
                    .find(|c| c.transaction_id == original);
                match target {
                    None => {
                        return Err(InputError::UnknownOriginal {
                            id: t.transaction_id.clone(),
                            original: original.to_string(),
                        })
                    }
                    Some(target) if target.kind != TxnKind::Sale => {
                        return Err(InputError::OriginalNotSale {
                            id: t.transaction_id.clone(),
                            original: original.to_string(),
                        })
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sale(id: &str, date: &str, amount: i128, credits: Vec<Credit>) -> Transaction {
        Transaction {
            transaction_id: id.to_string(),
            date: NaiveDate::parse_from_str(date, "%Y-%m-%d").expect("valid date"),
            amount_cents: amount,
            kind: TxnKind::Sale,
            original_transaction_id: None,
            credits,
        }
    }

    fn credit(rep: &str, role: &str, priority: u32) -> Credit {
        Credit {
            rep_id: rep.to_string(),
            role: role.to_string(),
            priority,
        }
    }

    fn ret(id: &str, date: &str, amount: i128, original: &str) -> Transaction {
        Transaction {
            transaction_id: id.to_string(),
            date: NaiveDate::parse_from_str(date, "%Y-%m-%d").expect("valid date"),
            amount_cents: amount,
            kind: TxnKind::Return,
            original_transaction_id: Some(original.to_string()),
            credits: Vec::new(),
        }
    }

    #[test]
    fn valid_sales_and_returns_pass_validation() {
        let file = TransactionsFile {
            transactions: vec![
                sale("T1", "2026-02-01", 1_000, vec![credit("rep-1", "ae", 1)]),
                ret("T2", "2026-03-01", 100, "T1"),
            ],
        };
        assert_eq!(file.validate(), Ok(()));
    }

    #[test]
    fn dangling_return_original_is_rejected() {
        let file = TransactionsFile {
            transactions: vec![ret("T2", "2026-03-01", 100, "MISSING")],
        };
        assert_eq!(
            file.validate(),
            Err(InputError::UnknownOriginal {
                id: "T2".to_string(),
                original: "MISSING".to_string()
            })
        );
    }

    #[test]
    fn return_referencing_a_return_is_rejected() {
        let file = TransactionsFile {
            transactions: vec![
                sale("T1", "2026-02-01", 1_000, vec![credit("rep-1", "ae", 1)]),
                ret("T2", "2026-03-01", 100, "T1"),
                ret("T3", "2026-04-01", 100, "T2"),
            ],
        };
        assert_eq!(
            file.validate(),
            Err(InputError::OriginalNotSale {
                id: "T3".to_string(),
                original: "T2".to_string()
            })
        );
    }

    #[test]
    fn return_may_not_carry_its_own_credits() {
        let mut t = ret("T2", "2026-03-01", 100, "T1");
        t.credits = vec![credit("rep-9", "ae", 1)];
        let file = TransactionsFile {
            transactions: vec![
                sale("T1", "2026-02-01", 1_000, vec![credit("rep-1", "ae", 1)]),
                t,
            ],
        };
        assert_eq!(
            file.validate(),
            Err(InputError::ReturnWithCredits {
                id: "T2".to_string()
            })
        );
    }

    #[test]
    fn sale_must_not_reference_an_original() {
        let mut t = sale("T1", "2026-02-01", 1_000, vec![credit("rep-1", "ae", 1)]);
        t.original_transaction_id = Some("T0".to_string());
        let file = TransactionsFile {
            transactions: vec![t],
        };
        assert_eq!(
            file.validate(),
            Err(InputError::SaleWithOriginal {
                id: "T1".to_string()
            })
        );
    }

    #[test]
    fn duplicate_transaction_ids_are_rejected() {
        let file = TransactionsFile {
            transactions: vec![
                sale("T1", "2026-02-01", 1_000, vec![credit("rep-1", "ae", 1)]),
                sale("T1", "2026-02-02", 1_000, vec![credit("rep-1", "ae", 1)]),
            ],
        };
        assert_eq!(
            file.validate(),
            Err(InputError::DuplicateTransactionId {
                id: "T1".to_string()
            })
        );
    }
}
