//! Integration tests for the procurement control spine.
//!
//! Covers every rule branch of the three-way/two-way matcher, every
//! tolerance and threshold boundary, the governance paths (four-eyes,
//! subject scoping, separation of duties), and the fail-closed property —
//! a tampered evidence pack must fail verify.

use spine::{Finding, Severity, Signoff, SignoffDecision, VerifyError, SPINE_VERSION};
use threeway_match_spine::{
    canonical_inputs_bytes, canonical_params_bytes, compute, verify_pack, EngineError,
    GoodsReceiptLine, Invoice, InvoiceLine, LineKind, MatchConfig, MatchInputs, PoLine,
    PoLineVersion, ProductVerifyError, PurchaseOrder, RULE_DUPLICATE_INVOICE, RULE_NO_GR_NO_PAY,
    RULE_OVER_BILLING, RULE_PO_LINE_NOT_FOUND, RULE_PRICE_VARIANCE, RULE_QTY_VARIANCE,
    RULE_UNMATCHED_RECEIPT, RULE_VERSION_NOT_IN_FORCE,
};

const ENGINE: &str = "threeway-match-spine";
const TOOL: &str = "threeway-match-spine test";
const SUBJECT: &str = "ACME:INV-1:IL-1";

// ---------- builders ----------

fn config(
    price_tolerance_bp: i64,
    qty_tolerance_units: i128,
    exclude_tax_freight: bool,
) -> MatchConfig {
    MatchConfig {
        price_tolerance_bp,
        qty_tolerance_units,
        exclude_tax_freight,
    }
}

fn version(
    v: u32,
    effective_from: &str,
    qty_ordered: i128,
    unit_price_cents: i128,
) -> PoLineVersion {
    PoLineVersion {
        version: v,
        effective_from: effective_from.to_string(),
        qty_ordered,
        unit_price_cents,
    }
}

/// Goods PO-1 line L1 at a single version.
fn goods_po(unit_price_cents: i128, qty_ordered: i128) -> PurchaseOrder {
    PurchaseOrder {
        po_id: "PO-1".to_string(),
        lines: vec![PoLine {
            po_line_id: "L1".to_string(),
            line_kind: LineKind::Goods,
            versions: vec![version(1, "2026-01-01", qty_ordered, unit_price_cents)],
        }],
    }
}

/// Service PO-1 line L1 at a single version.
fn service_po(unit_price_cents: i128, qty_ordered: i128) -> PurchaseOrder {
    PurchaseOrder {
        po_id: "PO-1".to_string(),
        lines: vec![PoLine {
            po_line_id: "L1".to_string(),
            line_kind: LineKind::Service,
            versions: vec![version(1, "2026-01-01", qty_ordered, unit_price_cents)],
        }],
    }
}

/// Goods PO-1 line L1 with a mid-PO price change (v1 2026-01-01, v2 2026-02-01).
fn versioned_po() -> PurchaseOrder {
    PurchaseOrder {
        po_id: "PO-1".to_string(),
        lines: vec![PoLine {
            po_line_id: "L1".to_string(),
            line_kind: LineKind::Goods,
            versions: vec![
                version(1, "2026-01-01", 100, 1_000),
                version(2, "2026-02-01", 100, 1_100),
            ],
        }],
    }
}

/// Receipt against PO-1 line L1.
fn gr(gr_id: &str, qty: i128, received_date: &str) -> GoodsReceiptLine {
    gr_for(gr_id, "PO-1", "L1", qty, received_date)
}

fn gr_for(
    gr_id: &str,
    po_id: &str,
    po_line_id: &str,
    qty: i128,
    received_date: &str,
) -> GoodsReceiptLine {
    GoodsReceiptLine {
        gr_id: gr_id.to_string(),
        po_id: po_id.to_string(),
        po_line_id: po_line_id.to_string(),
        qty_received: qty,
        received_date: received_date.to_string(),
    }
}

/// Invoice line against PO-1 line L1.
fn inv_line(line_id: &str, qty: i128, unit_price_cents: i128) -> InvoiceLine {
    InvoiceLine {
        line_id: line_id.to_string(),
        po_id: "PO-1".to_string(),
        po_line_id: "L1".to_string(),
        qty_invoiced: qty,
        unit_price_cents,
        tax_cents: 0,
        freight_cents: 0,
        no_gr_override: false,
    }
}

fn invoice(id: &str, vendor: &str, number: &str, date: &str, lines: Vec<InvoiceLine>) -> Invoice {
    Invoice {
        invoice_id: id.to_string(),
        vendor_id: vendor.to_string(),
        invoice_number: number.to_string(),
        invoice_date: date.to_string(),
        lines,
    }
}

fn inputs(
    purchase_orders: Vec<PurchaseOrder>,
    goods_receipts: Vec<GoodsReceiptLine>,
    invoices: Vec<Invoice>,
) -> MatchInputs {
    MatchInputs {
        purchase_orders,
        goods_receipts,
        invoices,
    }
}

/// Clean goods baseline: PO 1000.00/unit, 10 received, 10 invoiced at par.
fn clean_inputs() -> MatchInputs {
    inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 100_000)],
        )],
    )
}

fn run(inputs: &MatchInputs, config: &MatchConfig) -> spine::EvidencePack {
    compute(inputs, config, ENGINE, TOOL, vec![]).expect("inputs valid")
}

fn run_with_signoffs(
    inputs: &MatchInputs,
    config: &MatchConfig,
    signoffs: Vec<Signoff>,
) -> spine::EvidencePack {
    compute(inputs, config, ENGINE, TOOL, signoffs).expect("inputs valid")
}

fn approve(actor: &str, subject: &str) -> Signoff {
    Signoff {
        actor: actor.to_string(),
        role: "ap-manager".to_string(),
        subject: subject.to_string(),
        decision: SignoffDecision::Approve,
        at: "2026-09-22T00:00:00Z".to_string(),
    }
}

fn rule_hits<'a>(pack: &'a spine::EvidencePack, rule: &str) -> Vec<&'a Finding> {
    pack.findings.iter().filter(|f| f.rule_id == rule).collect()
}

// ---------- rules and boundaries ----------

#[test]
fn clean_three_way_match_emits_no_findings() {
    let pack = run(&clean_inputs(), &config(200, 0, true));
    assert!(pack.findings.is_empty());
    assert_eq!(pack.spine_version, SPINE_VERSION);
    assert_eq!(pack.engine_id, ENGINE);
    assert!(!pack.body_hash.is_empty());
}

#[test]
fn multi_gr_partial_receipts_aggregate_cleanly() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 5, "2026-02-01"), gr("GR-2", 5, "2026-02-03")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 100_000)],
        )],
    );
    assert!(run(&inp, &config(200, 0, true)).findings.is_empty());
}

#[test]
fn multi_gr_aggregation_over_billing_breaches() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 5, "2026-02-01"), gr("GR-2", 5, "2026-02-03")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 11, 100_000)],
        )],
    );
    let pack = run(&inp, &config(200, 0, true));
    let over = rule_hits(&pack, RULE_OVER_BILLING);
    assert_eq!(over.len(), 1);
    assert_eq!(over[0].severity, Severity::Breach);
    assert_eq!(over[0].subject, SUBJECT);
    assert!(over[0].message.contains("by 1 unit"));
}

#[test]
fn price_tolerance_boundary_passes_exactly_and_breaches_one_cent_beyond() {
    // PO 100000 cents/unit, 200 bp -> per-unit tolerance 2000 cents.
    let inp = |price: i128| {
        inputs(
            vec![goods_po(100_000, 100)],
            vec![gr("GR-1", 10, "2026-02-01")],
            vec![invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![inv_line("IL-1", 10, price)],
            )],
        )
    };
    // Exactly at the tolerance edge passes.
    assert!(run(&inp(102_000), &config(200, 0, true))
        .findings
        .is_empty());
    // One cent beyond breaches.
    let pack = run(&inp(102_001), &config(200, 0, true));
    let hits = rule_hits(&pack, RULE_PRICE_VARIANCE);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, Severity::Breach);
    assert_eq!(hits[0].subject, SUBJECT);
}

#[test]
fn price_tolerance_rounds_half_up() {
    // PO 999 cents/unit, 100 bp -> tolerance (999*100 + 5000)/10000 = 10 cents.
    let inp = |price: i128| {
        inputs(
            vec![goods_po(999, 100)],
            vec![gr("GR-1", 10, "2026-02-01")],
            vec![invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![inv_line("IL-1", 10, price)],
            )],
        )
    };
    assert!(run(&inp(1_009), &config(100, 0, true)).findings.is_empty());
    assert_eq!(
        rule_hits(
            &run(&inp(1_010), &config(100, 0, true)),
            RULE_PRICE_VARIANCE
        )
        .len(),
        1
    );
}

#[test]
fn under_billing_quantity_tolerance_boundary() {
    // Received 10, qty tolerance 1: invoice 9 (exactly at tolerance) passes; 8 warns.
    let inp = |qty: i128| {
        inputs(
            vec![goods_po(100_000, 100)],
            vec![gr("GR-1", 10, "2026-02-01")],
            vec![invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![inv_line("IL-1", qty, 100_000)],
            )],
        )
    };
    assert!(run(&inp(9), &config(200, 1, true)).findings.is_empty());
    let pack = run(&inp(8), &config(200, 1, true));
    let hits = rule_hits(&pack, RULE_QTY_VARIANCE);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].severity, Severity::Warn);
    assert!(!hits[0].requires_signoff);
}

#[test]
fn over_billing_any_excess_breaches_even_within_qty_tolerance() {
    // Received 10 with a generous 5-unit qty tolerance: 11 invoiced still breaches.
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 11, 100_000)],
        )],
    );
    let pack = run(&inp, &config(200, 5, true));
    assert_eq!(rule_hits(&pack, RULE_OVER_BILLING).len(), 1);
    assert!(rule_hits(&pack, RULE_QTY_VARIANCE).is_empty());
}

#[test]
fn no_gr_no_pay_blocks_and_verify_refuses_unsigned_pack() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 100_000)],
        )],
    );
    let cfg = config(200, 0, true);
    let pack = run(&inp, &cfg);
    let hits = rule_hits(&pack, RULE_NO_GR_NO_PAY);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].subject, SUBJECT);
    // Fail-closed: the unsigned pack cannot verify.
    assert_eq!(
        pack.verify(&canonical_inputs_bytes(&inp), &canonical_params_bytes(&cfg)),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_NO_GR_NO_PAY.to_string()
        })
    );
}

#[test]
fn no_gr_override_needs_flag_and_four_eyes() {
    let cfg = config(200, 0, true);
    let subject = SUBJECT.to_string();
    let build = |override_flag: bool| {
        inputs(
            vec![goods_po(100_000, 100)],
            vec![],
            vec![invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![InvoiceLine {
                    no_gr_override: override_flag,
                    ..inv_line("IL-1", 10, 100_000)
                }],
            )],
        )
    };

    // Two signoffs without the override flag never resolve.
    let inp = build(false);
    let pack = run_with_signoffs(
        &inp,
        &cfg,
        vec![approve("sam", &subject), approve("quinn", &subject)],
    );
    assert_eq!(
        verify_pack(&pack, &inp, &cfg),
        Err(ProductVerifyError::NoGrOverrideMissing {
            subject: subject.clone()
        })
    );

    // Override flag with a single signer is not four-eyes.
    let inp = build(true);
    let pack = run_with_signoffs(&inp, &cfg, vec![approve("sam", &subject)]);
    assert_eq!(
        verify_pack(&pack, &inp, &cfg),
        Err(ProductVerifyError::FourEyesMissing {
            subject: subject.clone()
        })
    );

    // Override flag with two distinct signers resolves.
    let inp = build(true);
    let pack = run_with_signoffs(
        &inp,
        &cfg,
        vec![approve("sam", &subject), approve("quinn", &subject)],
    );
    assert_eq!(verify_pack(&pack, &inp, &cfg), Ok(()));
}

#[test]
fn service_line_matches_two_way_without_receipts() {
    let inp = inputs(
        vec![service_po(50_000, 50)],
        vec![],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 50_000)],
        )],
    );
    assert!(run(&inp, &config(200, 0, true)).findings.is_empty());
}

#[test]
fn service_over_billing_is_measured_against_ordered_qty() {
    let inp = inputs(
        vec![service_po(50_000, 50)],
        vec![],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 51, 50_000)],
        )],
    );
    let pack = run(&inp, &config(200, 0, true));
    assert_eq!(rule_hits(&pack, RULE_OVER_BILLING).len(), 1);
}

#[test]
fn duplicate_invoice_hash_hit_flags_only_the_later_invoice() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![
            invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![inv_line("IL-1", 10, 100_000)],
            ),
            // Different case and padding, same (vendor, number, amount): a hit.
            invoice(
                "IN-2",
                " acme ",
                " inv-1 ",
                "2026-03-05",
                vec![inv_line("IL-1", 10, 100_000)],
            ),
            // Same vendor, different number: not a hit.
            invoice(
                "IN-3",
                "ACME",
                "INV-2",
                "2026-03-06",
                vec![inv_line("IL-1", 10, 100_000)],
            ),
        ],
    );
    let pack = run(&inp, &config(200, 0, true));
    let hits = rule_hits(&pack, RULE_DUPLICATE_INVOICE);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].subject, " acme : inv-1 ");
    assert!(hits[0].message.contains("IN-1"));
}

#[test]
fn distinct_amounts_do_not_collide_in_duplicate_detection() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![
            invoice(
                "IN-1",
                "ACME",
                "INV-1",
                "2026-03-01",
                vec![inv_line("IL-1", 10, 100_000)],
            ),
            invoice(
                "IN-2",
                "ACME",
                "INV-1",
                "2026-03-05",
                vec![inv_line("IL-1", 10, 100_001)],
            ),
        ],
    );
    let pack = run(&inp, &config(200, 0, true));
    assert!(rule_hits(&pack, RULE_DUPLICATE_INVOICE).is_empty());
}

#[test]
fn mid_po_price_change_matches_version_in_force_at_receipt_date() {
    // v1 (2026-01-01): 1000 cents; v2 (2026-02-01): 1100 cents. Receipts
    // straddle the change; the invoice is priced at v2.
    let inp = inputs(
        vec![versioned_po()],
        vec![gr("GR-1", 5, "2026-01-20"), gr("GR-2", 5, "2026-02-10")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 1_100)],
        )],
    );
    let pack = run(&inp, &config(200, 0, true));
    let price = rule_hits(&pack, RULE_PRICE_VARIANCE);
    assert_eq!(price.len(), 1);
    assert!(price[0].message.contains("PO version 1"));
    assert!(price[0].message.contains("units matched: 5"));
    // The v2-priced units match cleanly and quantities balance.
    assert!(rule_hits(&pack, RULE_OVER_BILLING).is_empty());
    assert!(rule_hits(&pack, RULE_QTY_VARIANCE).is_empty());
}

#[test]
fn receipt_before_first_version_refuses_fail_closed() {
    let inp = inputs(
        vec![versioned_po()],
        vec![gr("GR-1", 5, "2025-12-31")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 5, 1_000)],
        )],
    );
    let cfg = config(200, 0, true);
    let pack = run(&inp, &cfg);
    let hits = rule_hits(&pack, RULE_VERSION_NOT_IN_FORCE);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].subject, "GR-1:PO-1:L1");
    // The invoice line itself is silent here: receipts exist but none resolve
    // to a version, so the receipt-side breach is the fail-closed block.
    assert!(rule_hits(&pack, RULE_NO_GR_NO_PAY).is_empty());
    assert_eq!(
        pack.verify(&canonical_inputs_bytes(&inp), &canonical_params_bytes(&cfg)),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_VERSION_NOT_IN_FORCE.to_string()
        })
    );
}

#[test]
fn tax_freight_is_excluded_from_tolerance_math_by_default() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![InvoiceLine {
                tax_cents: 9_999_999,
                freight_cents: 8_888_888,
                ..inv_line("IL-1", 10, 100_000)
            }],
        )],
    );
    assert!(run(&inp, &config(200, 0, true)).findings.is_empty());
}

#[test]
fn tax_freight_is_included_when_configured() {
    // Loaded unit price: (10 x 100000 + 5000000) / 10 = 600000 vs PO 100000.
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![InvoiceLine {
                tax_cents: 5_000_000,
                ..inv_line("IL-1", 10, 100_000)
            }],
        )],
    );
    let pack = run(&inp, &config(200, 0, false));
    let hits = rule_hits(&pack, RULE_PRICE_VARIANCE);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].message.contains("tax/freight-loaded"));
}

#[test]
fn unknown_references_fail_closed() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr_for("GR-9", "PO-9", "L1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![InvoiceLine {
                po_id: "PO-9".to_string(),
                ..inv_line("IL-1", 10, 100_000)
            }],
        )],
    );
    let pack = run(&inp, &config(200, 0, true));
    assert_eq!(rule_hits(&pack, RULE_UNMATCHED_RECEIPT).len(), 1);
    assert_eq!(rule_hits(&pack, RULE_PO_LINE_NOT_FOUND).len(), 1);
}

// ---------- governance and fail-closed verification ----------

#[test]
fn approvals_resolve_only_the_subject_they_name() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 11, 100_000)],
        )],
    );
    let cfg = config(200, 0, true);
    let pack = run_with_signoffs(&inp, &cfg, vec![approve("sam", "ACME:INV-1:OTHER")]);
    assert_eq!(
        pack.verify(&canonical_inputs_bytes(&inp), &canonical_params_bytes(&cfg)),
        Err(VerifyError::UnresolvedBreach {
            rule_id: RULE_OVER_BILLING.to_string()
        })
    );
}

#[test]
fn engine_cannot_countersign_its_own_pack() {
    let inp = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 11, 100_000)],
        )],
    );
    let cfg = config(200, 0, true);
    // An over-billing breach "resolved" only by the engine itself is void.
    let pack = run_with_signoffs(&inp, &cfg, vec![approve(ENGINE, SUBJECT)]);
    assert_eq!(
        verify_pack(&pack, &inp, &cfg),
        Err(ProductVerifyError::Spine(VerifyError::UnresolvedBreach {
            rule_id: RULE_OVER_BILLING.to_string()
        }))
    );
    // A distinct human signer resolves it (single signer outside the
    // no-GR override, which demands four-eyes).
    let pack = run_with_signoffs(
        &inp,
        &cfg,
        vec![approve(ENGINE, SUBJECT), approve("sam", SUBJECT)],
    );
    assert_eq!(verify_pack(&pack, &inp, &cfg), Ok(()));
}

#[test]
fn tampered_packs_fail_verify() {
    let inp = clean_inputs();
    let cfg = config(200, 0, true);
    let pack = run(&inp, &cfg);
    assert_eq!(verify_pack(&pack, &inp, &cfg), Ok(()));

    // Provenance tampering: the same pack verified against different inputs.
    assert_eq!(
        pack.verify(b"tampered", &canonical_params_bytes(&cfg)),
        Err(VerifyError::HashMismatch { field: "inputs" })
    );

    // Body tampering: a finding altered after sealing breaks the seal.
    let mut edited = pack.clone();
    edited.findings.push(Finding {
        rule_id: "FAKE".to_string(),
        severity: Severity::Info,
        subject: SUBJECT.to_string(),
        message: "injected".to_string(),
        requires_signoff: false,
    });
    assert_eq!(
        edited.verify(&canonical_inputs_bytes(&inp), &canonical_params_bytes(&cfg)),
        Err(VerifyError::BodyHashMismatch)
    );

    // Re-sealed body tampering: a pack whose findings this rule set would not
    // emit from these inputs refuses at the recompute layer.
    let resealed = edited.sealed();
    assert_eq!(
        verify_pack(&resealed, &inp, &cfg),
        Err(ProductVerifyError::FindingsDiverged)
    );
}

#[test]
fn compute_is_deterministic() {
    let inp = clean_inputs();
    let cfg = config(200, 0, true);
    let a = run(&inp, &cfg);
    let b = run(&inp, &cfg);
    assert_eq!(
        serde_json::to_string(&a).expect("serialize"),
        serde_json::to_string(&b).expect("serialize")
    );
}

#[test]
fn invalid_config_and_inputs_are_rejected() {
    let inp = clean_inputs();
    // Basis points out of range.
    assert!(matches!(
        compute(&inp, &config(20_001, 0, true), ENGINE, TOOL, vec![]),
        Err(EngineError::InvalidConfig(_))
    ));
    // Negative invoiced quantity.
    let bad_qty = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", -1, 100_000)],
        )],
    );
    assert!(matches!(
        compute(&bad_qty, &config(200, 0, true), ENGINE, TOOL, vec![]),
        Err(EngineError::InvalidInput(_))
    ));
    // Non-canonical date (February 30).
    let bad_date = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-30")],
        vec![invoice(
            "IN-1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 100_000)],
        )],
    );
    assert!(matches!(
        compute(&bad_date, &config(200, 0, true), ENGINE, TOOL, vec![]),
        Err(EngineError::InvalidInput(_))
    ));
    // Ambiguous id containing the subject separator.
    let bad_id = inputs(
        vec![goods_po(100_000, 100)],
        vec![gr("GR-1", 10, "2026-02-01")],
        vec![invoice(
            "IN:1",
            "ACME",
            "INV-1",
            "2026-03-01",
            vec![inv_line("IL-1", 10, 100_000)],
        )],
    );
    assert!(matches!(
        compute(&bad_id, &config(200, 0, true), ENGINE, TOOL, vec![]),
        Err(EngineError::InvalidInput(_))
    ));
}
