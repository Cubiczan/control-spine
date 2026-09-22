# threeway-match-spine

Procurement control spine: deterministic three-way matching (purchase order ↔
goods receipt ↔ invoice) for goods lines and two-way matching (purchase order ↔
invoice) for service lines, with typed exception findings and fail-closed
evidence packs.

This crate is a member of the `control-spine` Rust workspace and depends on the
canonical governance crate [`spine`](../../crates/spine) by path — findings,
signoff receipts, evidence packs, seals, the lock lifecycle, and fail-closed
verification all come from there. This crate adds only the procurement rule
set.

## Design intent

The canonical AP control is a matching problem: an invoice may be paid only
when what was ordered, what was received, and what was billed agree within
declared tolerances. This engine recomputes that agreement deterministically:

- **Pure engine.** No clock, filesystem, or network access; no randomness.
  Quantities, prices, and dates are caller input. Money is integer cents
  (`i128`); prices are never floats. The same inputs always produce the same
  findings and the same pack, byte for byte.
- **Versioned PO lines.** A mid-PO price change is a new version with an
  effective date. Receipts match against the version in force at the receipt
  date; service invoices match the version in force at the invoice date.
- **Partial receipts aggregate.** Multiple goods-receipt lines for the same PO
  line sum into received quantity, per version, before matching.
- **Fail closed.** Unknown references, unresolvable versions, unsigned
  breaches, and malformed input all block; nothing is silently dropped or
  assumed. `verify` recomputes findings from the presented inputs and refuses
  on any divergence, hash mismatch, broken seal, or unresolved breach.

Out of scope by design: document extraction. The engine consumes typed,
schema-checked JSON — purchase orders, receipt lines, invoices, config. Turning
PDFs or supplier emails into typed invoices is a separate problem and is not
attempted here.

## Rules

| Rule | Severity | Behavior |
|---|---|---|
| `PRICE_VARIANCE` | breach | Invoiced unit price differs from the matched PO version's unit price by more than the per-unit tolerance (basis points of the PO price, half-up rounded). |
| `OVER_BILLING` | breach | Invoiced quantity exceeds received quantity (goods) or ordered quantity (services). No tolerance — any excess breaches. |
| `QTY_VARIANCE` | warn | Goods only: invoiced quantity falls short of **received** quantity beyond the quantity tolerance — goods on hand without a matching invoice. Partial billing against a service PO's ordered ceiling is normal and never warns. |
| `NO_GR_NO_PAY` | breach | Invoice against a goods PO line with no matching receipt. Payment blocked; resolvable only when the invoice line sets `no_gr_override` AND four-eyes approvals (two distinct non-engine signers) cover the finding subject. |
| `DUPLICATE_INVOICE` | breach | Same normalized (vendor, invoice number, total payable cents) as an earlier invoice in the same batch — trimmed, lowercased, hashed with SHA-256. |
| `PO_LINE_NOT_FOUND` | breach | Invoice line references a PO line that does not exist. |
| `VERSION_NOT_IN_FORCE` | breach | A receipt (or service invoice) is dated before every version of its PO line — nothing to match against. |
| `UNMATCHED_RECEIPT` | breach | A receipt references a PO line that does not exist. |

Every breach finding requires a subject-scoped approving signoff before the
pack verifies; the producing engine cannot countersign its own pack.

## Config (schema-checked)

| Field | Type | Meaning |
|---|---|---|
| `price_tolerance_bp` | int 0–10,000 | Per-unit price tolerance in basis points of the PO unit price. |
| `qty_tolerance_units` | int ≥ 0 | Under-invoicing tolerance in units. |
| `exclude_tax_freight` | bool | `true` (default): tolerance math uses the pre-tax unit price. `false`: tax and freight load the line's unit price; the loaded price is quantized to whole cents, half-up. |

Quantities are unitless integers; matching is single-currency.

## Operator workflow notes

**No-GR overrides are set at invoice entry, not after a finding.** The
`no_gr_override` flag is a property of the submitted invoice line. When a
`NO_GR_NO_PAY` breach is produced, resolving it means re-submitting the
invoice line with the flag set and recomputing the pack, then collecting
four-eyes approval on the re-sealed pack — approvals are embedded when the
pack is produced, so any new approval routes through a recompute-and-reseal
step. A workflow that expects to attach approvals interactively to an
existing sealed pack will not work; integration should plan for recompute.

**Duplicate detection key includes the amount.** The duplicate key is
(normalized vendor, invoice number, total payable cents). A re-submission
with the same number but a changed amount is not flagged unless the new
amount also violates the price tolerance against the matched PO version.
This is an intentional trade — it prevents false positives on credit memos
and legitimate corrections — and the residual gap is accepted. A
vendor-and-number-only key mode would close it if a control owner requires.

**Single currency.** Matching is single-currency in this version per the
family spec: amounts carry no currency label, and mixing currencies in one
batch is undefined input. Multi-currency support would require tagging
every amount field and re-validating the matching semantics.

## Usage

```sh
cargo run -p threeway-match-spine -- compute \
  --pos pos.json --receipts receipts.json --invoices invoices.json \
  --config config.json --pretty

cargo run -p threeway-match-spine -- verify \
  --pack pack.json --pos pos.json --receipts receipts.json \
  --invoices invoices.json --config config.json

cargo run -p threeway-match-spine -- explain --pack pack.json
```

`compute` prints the evidence pack (inputs/params SHA-256 hashes, findings,
signoffs, body seal). `verify` refuses with a non-zero exit on any mismatch,
unresolved breach, missing override flag, or missing four-eyes approval.
`explain` prints a human-readable summary and the pack's lock-state outlook.

## Tests

`cargo test -p threeway-match-spine` covers every rule branch, the tolerance
and quantity boundaries (including half-up rounding at the edge), multi-GR
aggregation, mid-PO price-change matching, duplicate detection normalization,
signoff subject scoping, separation of duties (engine countersign refusal),
and the fail-closed paths — including a tampered evidence pack (provenance
hash, body seal, and re-sealed findings divergence each refuse).

## Honest claims

Config tables shipped with or referenced by this crate are **seed data** for
development and testing, not tuned or validated procurement policy. Nothing in
this crate is certified for SOX, ISO, SOC 2, or any other compliance regime,
and no performance or detection benchmarks are claimed. The engine consumes
typed data; it does not read documents, and it makes no claim about supplier
federation networks or AP-automation completeness.
