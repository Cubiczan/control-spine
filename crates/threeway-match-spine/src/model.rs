//! Typed inputs and config for the procurement engine. All JSON is
//! schema-checked at the serde boundary: business ids must be non-empty and
//! free of the `:` subject separator, dates must be canonical `YYYY-MM-DD`,
//! quantities must be positive, and the config rejects unknown fields.

use crate::error::EngineError;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Canonical date format for every date field. Canonical-formatted ISO dates
/// order lexicographically, so version resolution needs no date arithmetic.
pub const DATE_FORMAT: &str = "%Y-%m-%d";

/// How a PO line matches: goods lines require goods receipts (three-way);
/// service lines match PO ↔ invoice only (two-way).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineKind {
    Goods,
    Service,
}

/// A purchase order: the commitment side of the match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseOrder {
    pub po_id: String,
    pub lines: Vec<PoLine>,
}

/// A versioned PO line. Mid-PO price changes append a new version; matching
/// resolves the version in force at the receipt date (goods) or invoice date
/// (services).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoLine {
    pub po_line_id: String,
    pub line_kind: LineKind,
    pub versions: Vec<PoLineVersion>,
}

/// One version of a PO line: the ordered quantity and unit price in force
/// from `effective_from` (inclusive) until the next version's date.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoLineVersion {
    pub version: u32,
    pub effective_from: String,
    pub qty_ordered: i128,
    pub unit_price_cents: i128,
}

/// One line of a goods receipt document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoodsReceiptLine {
    pub gr_id: String,
    pub po_id: String,
    pub po_line_id: String,
    pub qty_received: i128,
    pub received_date: String,
}

/// A vendor invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub invoice_id: String,
    pub vendor_id: String,
    pub invoice_number: String,
    pub invoice_date: String,
    pub lines: Vec<InvoiceLine>,
}

/// One line of an invoice. `tax_cents`/`freight_cents` are line-level
/// allocations; they enter tolerance math only when
/// [`MatchConfig::exclude_tax_freight`] is false. `no_gr_override` marks the
/// line as an intentional no-receipt payment; the flag alone blocks nothing
/// and resolves nothing — resolution needs a four-eyes signoff on the
/// finding subject (see [`crate::verify`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLine {
    pub line_id: String,
    pub po_id: String,
    pub po_line_id: String,
    pub qty_invoiced: i128,
    pub unit_price_cents: i128,
    #[serde(default)]
    pub tax_cents: i128,
    #[serde(default)]
    pub freight_cents: i128,
    #[serde(default)]
    pub no_gr_override: bool,
}

/// All engine inputs. The canonical bytes of this struct are what the
/// `inputs_hash` provenance hash covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInputs {
    pub purchase_orders: Vec<PurchaseOrder>,
    pub goods_receipts: Vec<GoodsReceiptLine>,
    pub invoices: Vec<Invoice>,
}

/// Deterministic match tolerances. The shipped defaults are seed data —
/// policy placeholders, not authoritative thresholds (see README).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchConfig {
    /// Price tolerance in basis points of the matched PO version's unit
    /// price (0..=10000). 200 bp = 2.00%.
    pub price_tolerance_bp: i64,
    /// Absolute quantity tolerance (units) for under-billing on a matched
    /// PO line. Over-billing has no tolerance — any excess is a finding.
    #[serde(default)]
    pub qty_tolerance_units: i128,
    /// Exclude line tax and freight from tolerance math (default true).
    #[serde(default = "default_true")]
    pub exclude_tax_freight: bool,
}

fn default_true() -> bool {
    true
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            price_tolerance_bp: 200,
            qty_tolerance_units: 0,
            exclude_tax_freight: true,
        }
    }
}

impl MatchConfig {
    pub fn validate(&self) -> Result<(), EngineError> {
        if !(0..=10_000).contains(&self.price_tolerance_bp) {
            return Err(EngineError::InvalidConfig(format!(
                "price_tolerance_bp must be within 0..=10000, got {}",
                self.price_tolerance_bp
            )));
        }
        if self.qty_tolerance_units < 0 {
            return Err(EngineError::InvalidConfig(format!(
                "qty_tolerance_units must be non-negative, got {}",
                self.qty_tolerance_units
            )));
        }
        Ok(())
    }
}

impl MatchInputs {
    /// Fail-closed boundary validation: every ambiguity that could make a
    /// finding or subject unstable is refused before matching runs.
    pub fn validate(&self) -> Result<(), EngineError> {
        let mut po_ids: BTreeSet<&str> = BTreeSet::new();
        for po in &self.purchase_orders {
            check_id("po_id", &po.po_id)?;
            if !po_ids.insert(po.po_id.as_str()) {
                return Err(EngineError::InvalidInput(format!(
                    "duplicate po_id {} across purchase orders",
                    po.po_id
                )));
            }
            let mut line_ids: BTreeSet<&str> = BTreeSet::new();
            for line in &po.lines {
                check_id("po_line_id", &line.po_line_id)?;
                if !line_ids.insert(line.po_line_id.as_str()) {
                    return Err(EngineError::InvalidInput(format!(
                        "duplicate po_line_id {} in PO {}",
                        line.po_line_id, po.po_id
                    )));
                }
                validate_po_line(line)?;
            }
        }
        for gr in &self.goods_receipts {
            check_id("gr_id", &gr.gr_id)?;
            check_id("po_id", &gr.po_id)?;
            check_id("po_line_id", &gr.po_line_id)?;
            if gr.qty_received <= 0 {
                return Err(EngineError::InvalidInput(format!(
                    "qty_received must be positive on receipt {} (got {})",
                    gr.gr_id, gr.qty_received
                )));
            }
            validate_date("received_date", &gr.received_date)?;
        }
        let mut invoice_ids: BTreeSet<&str> = BTreeSet::new();
        for inv in &self.invoices {
            check_id("invoice_id", &inv.invoice_id)?;
            check_id("vendor_id", &inv.vendor_id)?;
            check_id("invoice_number", &inv.invoice_number)?;
            validate_date("invoice_date", &inv.invoice_date)?;
            if !invoice_ids.insert(inv.invoice_id.as_str()) {
                return Err(EngineError::InvalidInput(format!(
                    "duplicate invoice_id {} across invoices",
                    inv.invoice_id
                )));
            }
            if inv.lines.is_empty() {
                return Err(EngineError::InvalidInput(format!(
                    "invoice {} must carry at least one line",
                    inv.invoice_id
                )));
            }
            let mut line_ids: BTreeSet<&str> = BTreeSet::new();
            for line in &inv.lines {
                check_id("line_id", &line.line_id)?;
                check_id("po_id", &line.po_id)?;
                check_id("po_line_id", &line.po_line_id)?;
                if !line_ids.insert(line.line_id.as_str()) {
                    return Err(EngineError::InvalidInput(format!(
                        "duplicate line_id {} in invoice {}",
                        line.line_id, inv.invoice_id
                    )));
                }
                if line.qty_invoiced <= 0 {
                    return Err(EngineError::InvalidInput(format!(
                        "qty_invoiced must be positive on invoice {} line {} (got {})",
                        inv.invoice_id, line.line_id, line.qty_invoiced
                    )));
                }
                if line.unit_price_cents < 0 {
                    return Err(EngineError::InvalidInput(format!(
                        "unit_price_cents must be non-negative on invoice {} line {}",
                        inv.invoice_id, line.line_id
                    )));
                }
                if line.tax_cents < 0 || line.freight_cents < 0 {
                    return Err(EngineError::InvalidInput(format!(
                        "tax_cents and freight_cents must be non-negative on invoice {} line {}",
                        inv.invoice_id, line.line_id
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_po_line(line: &crate::model::PoLine) -> Result<(), EngineError> {
    if line.versions.is_empty() {
        return Err(EngineError::InvalidInput(format!(
            "PO line {} has no versions",
            line.po_line_id
        )));
    }
    let mut version_numbers: BTreeSet<u32> = BTreeSet::new();
    let mut effective_dates: BTreeSet<&str> = BTreeSet::new();
    for v in &line.versions {
        if !version_numbers.insert(v.version) {
            return Err(EngineError::InvalidInput(format!(
                "duplicate version {} on PO line {}",
                v.version, line.po_line_id
            )));
        }
        validate_date("effective_from", &v.effective_from)?;
        if !effective_dates.insert(v.effective_from.as_str()) {
            return Err(EngineError::InvalidInput(format!(
                "two versions of PO line {} share effective_from {} — version resolution would be ambiguous",
                line.po_line_id, v.effective_from
            )));
        }
        if v.qty_ordered <= 0 {
            return Err(EngineError::InvalidInput(format!(
                "qty_ordered must be positive on PO line {} version {}",
                line.po_line_id, v.version
            )));
        }
        if v.unit_price_cents < 0 {
            return Err(EngineError::InvalidInput(format!(
                "unit_price_cents must be non-negative on PO line {} version {}",
                line.po_line_id, v.version
            )));
        }
    }
    Ok(())
}

/// Business ids name finding subjects; they must be non-empty and free of
/// the `:` subject separator.
fn check_id(field: &str, id: &str) -> Result<(), EngineError> {
    if id.trim().is_empty() {
        return Err(EngineError::InvalidInput(format!(
            "{field} must be non-empty"
        )));
    }
    if id.contains(':') {
        return Err(EngineError::InvalidInput(format!(
            "{field} must not contain ':' (the subject separator): {id}"
        )));
    }
    Ok(())
}

/// Dates must parse and reformat to exactly the input string — canonical
/// `YYYY-MM-DD` only, so lexicographic order equals calendar order.
fn validate_date(field: &str, raw: &str) -> Result<NaiveDate, EngineError> {
    let parsed = NaiveDate::parse_from_str(raw, DATE_FORMAT).map_err(|_| {
        EngineError::InvalidInput(format!("{field} must be a valid YYYY-MM-DD date: {raw}"))
    })?;
    if parsed.format(DATE_FORMAT).to_string() != raw {
        return Err(EngineError::InvalidInput(format!(
            "{field} must be canonically formatted YYYY-MM-DD (zero-padded): {raw}"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_canonical_dates_are_refused() {
        assert!(validate_date("d", "2026-3-5").is_err());
        assert!(validate_date("d", "2026-03-05T00:00:00").is_err());
        assert!(validate_date("d", "not-a-date").is_err());
        assert!(validate_date("d", "2026-03-05").is_ok());
    }

    #[test]
    fn subject_separator_is_forbidden_in_ids() {
        assert!(check_id("id", "PO:1").is_err());
        assert!(check_id("id", "PO-1").is_ok());
        assert!(check_id("id", " ").is_err());
    }

    #[test]
    fn config_range_is_enforced() {
        let cfg = MatchConfig {
            price_tolerance_bp: 20_001,
            ..MatchConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = MatchConfig {
            qty_tolerance_units: -1,
            ..MatchConfig::default()
        };
        assert!(cfg.validate().is_err());
        assert!(MatchConfig::default().validate().is_ok());
    }
}
