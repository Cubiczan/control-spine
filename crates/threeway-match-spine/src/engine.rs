//! The pure procurement matching engine: three-way (PO ↔ goods receipt ↔
//! invoice) for goods lines, two-way (PO ↔ invoice) for service lines.
//!
//! No clock, filesystem, network, or randomness: every quantity, price, and
//! date is caller input, all money is integer cents (i128), and all
//! governance types (findings, signoffs, evidence packs, the seal) come from
//! the canonical `spine` crate. Finding order follows input order — the same
//! inputs always produce byte-identical packs.

use crate::error::EngineError;
use crate::model::{
    GoodsReceiptLine, Invoice, InvoiceLine, LineKind, MatchConfig, MatchInputs, PoLineVersion,
};
use spine::{sha256_hex, EvidencePack, Finding, Severity, Signoff};
use std::collections::{BTreeMap, BTreeSet};

/// Invoice unit price differs from the matched PO version's unit price by
/// more than the configured tolerance.
pub const RULE_PRICE_VARIANCE: &str = "PRICE_VARIANCE";
/// Invoiced quantity exceeds received quantity (goods) or ordered quantity
/// (services). No tolerance — any excess breaches.
pub const RULE_OVER_BILLING: &str = "OVER_BILLING";
/// Invoiced quantity falls short of received/ordered quantity beyond the
/// configured quantity tolerance (warn — not a payment risk by itself).
pub const RULE_QTY_VARIANCE: &str = "QTY_VARIANCE";
/// Invoice against a goods PO line with no goods receipt: payment blocked
/// unless the invoice line carries `no_gr_override` AND four-eyes signoffs.
pub const RULE_NO_GR_NO_PAY: &str = "NO_GR_NO_PAY";
/// Same normalized (vendor, invoice number, amount) as an earlier invoice in
/// the same batch.
pub const RULE_DUPLICATE_INVOICE: &str = "DUPLICATE_INVOICE";
/// Invoice line references a PO line that does not exist.
pub const RULE_PO_LINE_NOT_FOUND: &str = "PO_LINE_NOT_FOUND";
/// Receipt (or service invoice) dated before every version of its PO line —
/// no version is in force to match against.
pub const RULE_VERSION_NOT_IN_FORCE: &str = "VERSION_NOT_IN_FORCE";
/// Goods receipt references a PO line that does not exist.
pub const RULE_UNMATCHED_RECEIPT: &str = "UNMATCHED_RECEIPT";

/// Canonical input bytes — what the pack's `inputs_hash` covers.
pub fn canonical_inputs_bytes(inputs: &MatchInputs) -> Vec<u8> {
    serde_json::to_vec(inputs)
        .expect("MatchInputs is a fixed-shape struct; serialization cannot fail")
}

/// Canonical config bytes — what the pack's `params_hash` covers.
pub fn canonical_params_bytes(config: &MatchConfig) -> Vec<u8> {
    serde_json::to_vec(config)
        .expect("MatchConfig is a fixed-shape struct; serialization cannot fail")
}

/// Per-unit tolerance in cents: half-up rounding of `po_unit × bp / 10000`.
/// Both operands are validated non-negative, so integer division plus half
/// the divisor is exactly round-half-up.
fn per_unit_tolerance(po_unit: i128, bp: i64) -> i128 {
    (po_unit * i128::from(bp) + 5000) / 10000
}

fn div_half_up(n: i128, d: i128) -> i128 {
    (n + d / 2) / d
}

fn units(n: i128) -> &'static str {
    if n == 1 {
        "unit"
    } else {
        "units"
    }
}

/// Invoice unit price for tolerance math. With tax/freight excluded (the
/// default) this is the pre-tax unit price. When included, tax and freight
/// load the line's unit price; the loaded price is quantized to whole cents
/// half-up (documented in the README).
fn effective_unit_price(line: &InvoiceLine, exclude_tax_freight: bool) -> i128 {
    if exclude_tax_freight {
        line.unit_price_cents
    } else {
        let gross = line.qty_invoiced * line.unit_price_cents + line.tax_cents + line.freight_cents;
        div_half_up(gross, line.qty_invoiced)
    }
}

/// Stable business key for an invoice-line finding.
fn line_subject(invoice: &Invoice, line: &InvoiceLine) -> String {
    format!(
        "{}:{}:{}",
        invoice.vendor_id, invoice.invoice_number, line.line_id
    )
}

/// Stable business key for an invoice-level finding.
fn invoice_subject(invoice: &Invoice) -> String {
    format!("{}:{}", invoice.vendor_id, invoice.invoice_number)
}

/// Stable business key for a receipt-side finding.
fn receipt_subject(gr: &GoodsReceiptLine) -> String {
    format!("{}:{}:{}", gr.gr_id, gr.po_id, gr.po_line_id)
}

/// Duplicate-detection key: SHA-256 over the normalized (vendor, invoice
/// number, total payable cents) triple. Vendor and number are trimmed and
/// lowercased; the amount is the invoice's total payable cents.
fn duplicate_hash(invoice: &Invoice) -> String {
    let total_payable: i128 = invoice
        .lines
        .iter()
        .map(|l| l.qty_invoiced * l.unit_price_cents + l.tax_cents + l.freight_cents)
        .sum();
    let key = format!(
        "{}:{}:{}",
        invoice.vendor_id.trim().to_lowercase(),
        invoice.invoice_number.trim().to_lowercase(),
        total_payable
    );
    sha256_hex(key.as_bytes())
}

/// The version in force at `date`: the last `effective_from` ≤ date.
/// Versions are pre-sorted ascending and dates are canonical ISO, so a
/// lexicographic comparison is a calendar comparison.
fn version_in_force<'a>(versions: &'a [PoLineVersion], date: &str) -> Option<&'a PoLineVersion> {
    versions
        .iter()
        .rev()
        .find(|v| v.effective_from.as_str() <= date)
}

/// Compute the evidence pack for `inputs` under `config`.
///
/// `signoffs` are receipts the caller already holds (typically resolution
/// approvals for this batch); they are embedded in the pack verbatim and are
/// judged at verify time. Findings depend only on inputs and config.
pub fn compute(
    inputs: &MatchInputs,
    config: &MatchConfig,
    engine_id: &str,
    tool_version: &str,
    signoffs: Vec<Signoff>,
) -> Result<EvidencePack, EngineError> {
    if engine_id.trim().is_empty() {
        return Err(EngineError::InvalidConfig(
            "engine_id must be non-empty".to_string(),
        ));
    }
    if tool_version.trim().is_empty() {
        return Err(EngineError::InvalidConfig(
            "tool_version must be non-empty".to_string(),
        ));
    }
    config.validate()?;
    inputs.validate()?;

    // PO line index: (po_id, line) -> line kind plus versions sorted by
    // effective date. The match kind belongs to the PO line, not the invoice.
    let mut po_lines: BTreeMap<(String, String), (LineKind, Vec<PoLineVersion>)> = BTreeMap::new();
    for po in &inputs.purchase_orders {
        for line in &po.lines {
            let mut versions = line.versions.clone();
            versions.sort_by(|a, b| a.effective_from.cmp(&b.effective_from));
            po_lines.insert(
                (po.po_id.clone(), line.po_line_id.clone()),
                (line.line_kind, versions),
            );
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    // Phase 1 — receipt-side integrity. Every receipt line either lands on a
    // known PO line with a version in force at its receipt date, or it
    // breaches: nothing is silently dropped.
    for gr in &inputs.goods_receipts {
        let key = (gr.po_id.clone(), gr.po_line_id.clone());
        match po_lines.get(&key) {
            None => findings.push(Finding::breach(
                RULE_UNMATCHED_RECEIPT,
                receipt_subject(gr),
                format!(
                    "receipt references unknown PO line {}:{}",
                    gr.po_id, gr.po_line_id
                ),
            )),
            Some((_, versions)) => {
                if version_in_force(versions, &gr.received_date).is_none() {
                    findings.push(Finding::breach(
                        RULE_VERSION_NOT_IN_FORCE,
                        receipt_subject(gr),
                        format!(
                            "receipt date {} predates every version of PO line {}:{}",
                            gr.received_date, gr.po_id, gr.po_line_id
                        ),
                    ));
                }
            }
        }
    }

    // Phase 2 — aggregate valid receipts per (PO line, version in force at
    // receipt date). Partial receipts across multiple GR lines aggregate to
    // the PO line; per version, because a mid-PO price change can split the
    // receipts across two prices.
    let mut received: BTreeMap<(String, String), BTreeMap<u32, i128>> = BTreeMap::new();
    let mut receipt_refs: BTreeSet<(String, String)> = BTreeSet::new();
    for gr in &inputs.goods_receipts {
        let key = (gr.po_id.clone(), gr.po_line_id.clone());
        receipt_refs.insert(key.clone());
        if let Some((_, versions)) = po_lines.get(&key) {
            if let Some(v) = version_in_force(versions, &gr.received_date) {
                *received
                    .entry(key)
                    .or_default()
                    .entry(v.version)
                    .or_insert(0) += gr.qty_received;
            }
        }
    }

    // Phase 3 — invoice matching in input order, then duplicate detection.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for invoice in &inputs.invoices {
        for line in &invoice.lines {
            let key = (line.po_id.clone(), line.po_line_id.clone());
            match po_lines.get(&key) {
                None => findings.push(Finding::breach(
                    RULE_PO_LINE_NOT_FOUND,
                    line_subject(invoice, line),
                    format!(
                        "invoice line references unknown PO line {}:{}",
                        line.po_id, line.po_line_id
                    ),
                )),
                Some((line_kind, versions)) => match line_kind {
                    LineKind::Service => {
                        match_service_line(invoice, line, versions, config, &mut findings)
                    }
                    LineKind::Goods => match_goods_line(
                        invoice,
                        line,
                        versions,
                        received.get(&key),
                        receipt_refs.contains(&key),
                        config,
                        &mut findings,
                    ),
                },
            }
        }
        let hash = duplicate_hash(invoice);
        match seen.get(&hash) {
            Some(original) => findings.push(Finding::breach(
                RULE_DUPLICATE_INVOICE,
                invoice_subject(invoice),
                format!(
                    "duplicate invoice: same normalized vendor, invoice number, and amount as invoice {original} (hash {})",
                    &hash[..12]
                ),
            )),
            None => {
                seen.insert(hash, invoice.invoice_id.clone());
            }
        }
    }

    Ok(EvidencePack {
        engine_id: engine_id.to_string(),
        tool_version: tool_version.to_string(),
        spine_version: spine::SPINE_VERSION.to_string(),
        inputs_hash: sha256_hex(&canonical_inputs_bytes(inputs)),
        params_hash: sha256_hex(&canonical_params_bytes(config)),
        findings,
        signoffs,
        body_hash: String::new(),
    }
    .sealed())
}

/// Three-way match for a goods line: price per received version group
/// (FIFO by version), over-billing and under-billing against total received.
fn match_goods_line(
    invoice: &Invoice,
    line: &InvoiceLine,
    versions: &[PoLineVersion],
    received: Option<&BTreeMap<u32, i128>>,
    has_any_receipt: bool,
    config: &MatchConfig,
    findings: &mut Vec<Finding>,
) {
    let subject = line_subject(invoice, line);
    let recv_total: i128 = received.map_or(0, |m| m.values().sum());

    if recv_total == 0 {
        if !has_any_receipt {
            let note = if line.no_gr_override {
                "no_gr_override is set on the invoice line — resolution requires four-eyes signoff on this subject"
            } else {
                "the invoice line carries no no_gr_override — payment stays blocked without it"
            };
            findings.push(Finding::breach(
                RULE_NO_GR_NO_PAY,
                subject,
                format!(
                    "no goods receipt matches PO line {}:{}; payment blocked (no-GR-no-pay); {note}",
                    line.po_id, line.po_line_id
                ),
            ));
        }
        // Receipts exist but none resolved to a version in force: the
        // receipt-side VERSION_NOT_IN_FORCE breaches already block payment.
        return;
    }

    let inv_unit = effective_unit_price(line, config.exclude_tax_freight);
    let mut remaining = line.qty_invoiced;
    for v in versions {
        let qty_recv = received
            .and_then(|m| m.get(&v.version))
            .copied()
            .unwrap_or(0);
        let take = remaining.min(qty_recv);
        if take > 0 {
            let tol = per_unit_tolerance(v.unit_price_cents, config.price_tolerance_bp);
            if inv_unit.abs_diff(v.unit_price_cents) > tol.unsigned_abs() {
                findings.push(Finding::breach(
                    RULE_PRICE_VARIANCE,
                    subject.clone(),
                    format!(
                        "invoiced unit price {inv_unit} cents vs PO version {} unit price {} cents \
                         exceeds per-unit tolerance {tol} cents ({} bp); units matched: {take}{}",
                        v.version,
                        v.unit_price_cents,
                        config.price_tolerance_bp,
                        if config.exclude_tax_freight {
                            ""
                        } else {
                            "; price is tax/freight-loaded"
                        }
                    ),
                ));
            }
            remaining -= take;
        }
    }

    if line.qty_invoiced > recv_total {
        findings.push(Finding::breach(
            RULE_OVER_BILLING,
            subject,
            format!(
                "invoiced quantity {} exceeds received quantity {} by {} {}",
                line.qty_invoiced,
                recv_total,
                line.qty_invoiced - recv_total,
                units(line.qty_invoiced - recv_total)
            ),
        ));
    } else if line.qty_invoiced < recv_total - config.qty_tolerance_units {
        findings.push(Finding {
            rule_id: RULE_QTY_VARIANCE.to_string(),
            severity: Severity::Warn,
            subject,
            message: format!(
                "invoiced quantity {} is below received quantity {} beyond the {} unit tolerance \
                 (short {} {})",
                line.qty_invoiced,
                recv_total,
                config.qty_tolerance_units,
                recv_total - line.qty_invoiced,
                units(recv_total - line.qty_invoiced)
            ),
            requires_signoff: false,
        });
    }
}

/// Two-way match for a service line: PO ↔ invoice at the version in force at
/// the invoice date; receipts play no role.
fn match_service_line(
    invoice: &Invoice,
    line: &InvoiceLine,
    versions: &[PoLineVersion],
    config: &MatchConfig,
    findings: &mut Vec<Finding>,
) {
    let subject = line_subject(invoice, line);
    let Some(v) = version_in_force(versions, &invoice.invoice_date) else {
        findings.push(Finding::breach(
            RULE_VERSION_NOT_IN_FORCE,
            subject,
            format!(
                "no PO line version in force at invoice date {} for PO line {}:{}",
                invoice.invoice_date, line.po_id, line.po_line_id
            ),
        ));
        return;
    };

    let inv_unit = effective_unit_price(line, config.exclude_tax_freight);
    let tol = per_unit_tolerance(v.unit_price_cents, config.price_tolerance_bp);
    if inv_unit.abs_diff(v.unit_price_cents) > tol.unsigned_abs() {
        findings.push(Finding::breach(
            RULE_PRICE_VARIANCE,
            subject.clone(),
            format!(
                "invoiced unit price {inv_unit} cents vs PO version {} unit price {} cents \
                 exceeds per-unit tolerance {tol} cents ({} bp){}",
                v.version,
                v.unit_price_cents,
                config.price_tolerance_bp,
                if config.exclude_tax_freight {
                    ""
                } else {
                    "; price is tax/freight-loaded"
                }
            ),
        ));
    }
    if line.qty_invoiced > v.qty_ordered {
        findings.push(Finding::breach(
            RULE_OVER_BILLING,
            subject,
            format!(
                "invoiced quantity {} exceeds ordered quantity {} (PO version {}) by {} {}",
                line.qty_invoiced,
                v.qty_ordered,
                v.version,
                line.qty_invoiced - v.qty_ordered,
                units(line.qty_invoiced - v.qty_ordered)
            ),
        ));
    }
    // No under-billing warn for services: the ordered quantity is a ceiling,
    // and partial billing against it is normal. The goods-side QTY_VARIANCE
    // exists only where a receipt establishes what was actually owed.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PoLine, PurchaseOrder};

    #[test]
    fn per_unit_tolerance_rounds_half_up() {
        assert_eq!(per_unit_tolerance(100_000, 200), 2_000);
        assert_eq!(per_unit_tolerance(999, 100), 10);
        assert_eq!(per_unit_tolerance(0, 200), 0);
        assert_eq!(per_unit_tolerance(1_000, 0), 0);
    }

    #[test]
    fn div_half_up_is_exact_on_round_values() {
        assert_eq!(div_half_up(1_000_000, 10), 100_000);
        assert_eq!(div_half_up(1_001, 2), 501);
        assert_eq!(div_half_up(1_000, 3), 333);
    }

    #[test]
    fn version_in_force_picks_last_effective_version() {
        let versions = vec![
            PoLineVersion {
                version: 1,
                effective_from: "2026-01-01".to_string(),
                qty_ordered: 100,
                unit_price_cents: 1_000,
            },
            PoLineVersion {
                version: 2,
                effective_from: "2026-02-01".to_string(),
                qty_ordered: 100,
                unit_price_cents: 1_100,
            },
        ];
        assert_eq!(
            version_in_force(&versions, "2026-01-20").unwrap().version,
            1
        );
        assert_eq!(
            version_in_force(&versions, "2026-02-01").unwrap().version,
            2
        );
        assert_eq!(
            version_in_force(&versions, "2026-05-09").unwrap().version,
            2
        );
        assert!(version_in_force(&versions, "2025-12-31").is_none());
    }

    #[test]
    fn duplicate_hash_normalizes_vendor_and_number() {
        let invoice = Invoice {
            invoice_id: "IN-1".to_string(),
            vendor_id: "ACME".to_string(),
            invoice_number: "Inv-1".to_string(),
            invoice_date: "2026-03-01".to_string(),
            lines: vec![InvoiceLine {
                line_id: "IL-1".to_string(),
                po_id: "PO-1".to_string(),
                po_line_id: "L1".to_string(),
                qty_invoiced: 10,
                unit_price_cents: 100_000,
                tax_cents: 0,
                freight_cents: 0,
                no_gr_override: false,
            }],
        };
        let mut variant = invoice.clone();
        variant.vendor_id = " acme ".to_string();
        variant.invoice_number = " iNv-1 ".to_string();
        assert_eq!(duplicate_hash(&invoice), duplicate_hash(&variant));

        let mut other_amount = invoice.clone();
        other_amount.lines[0].unit_price_cents = 100_001;
        assert_ne!(duplicate_hash(&invoice), duplicate_hash(&other_amount));

        // Smoke: the PO index round-trips a purchase order (model wiring).
        let po = PurchaseOrder {
            po_id: "PO-1".to_string(),
            lines: vec![PoLine {
                po_line_id: "L1".to_string(),
                line_kind: LineKind::Goods,
                versions: versions_from(&invoice),
            }],
        };
        assert_eq!(po.lines[0].versions[0].unit_price_cents, 100_000);
    }

    fn versions_from(invoice: &Invoice) -> Vec<PoLineVersion> {
        vec![PoLineVersion {
            version: 1,
            effective_from: "2026-01-01".to_string(),
            qty_ordered: invoice.lines[0].qty_invoiced,
            unit_price_cents: invoice.lines[0].unit_price_cents,
        }]
    }
}
