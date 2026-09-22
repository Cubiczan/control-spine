# ghg-ledger-spine

ESG/Sustainability department control spine — deterministic Scope 1/2/3
greenhouse-gas inventory with factor lineage, a dual-method Scope 2, Scope 3
category tagging, and a restatement-safe append-only ledger, emitting sealed
evidence packs under the canonical [`crates/spine`](../spine) governance
contract.

One member of the control-spine family: same governance contract, same
evidence-pack shape, same human-lock lifecycle, same fail-closed rules.

## Design intent

The control computation for a GHG inventory is deterministic arithmetic —
activity × emission factor — with an expensive failure mode: an assurance
finding. The product therefore optimizes for the evidence trail, not
convenience. Concretely:

- **Pure engine.** No clock, no filesystem, no network, no RNG. Time and
  period are caller inputs. Same inputs, same pack, byte for byte.
- **Fixed-point integers only.** Quantities, conversion factors, and emission
  factors are `{value, scale}` pairs parsed as integers; floats are never
  parsed or computed. Emissions are integer grams of CO₂e. Multiplication
  rounds half-up to the gram, per line.
- **Unit conversion at the boundary only.** Records carry source units
  (e.g. MWh); a config-driven conversion table maps them to the factor's
  canonical unit (e.g. kWh) exactly once, before the factor lookup — never
  inside the engine loop.
- **Factor lineage on every line.** Each emission line records the exact
  factor row used — version id, factor value, activity/unit/region/year — so
  a restatement can show which factor version moved a number.
- **Fail-closed gaps.** A missing factor is a `GHG-FACTOR-MISSING` **breach**
  finding and the line is not computed — it is never silently zeroed. A
  scope-3 activity with no configured category mapping is a
  `GHG-SCOPE3-UNMAPPED` gap. Malformed records (negative/zero quantity,
  duplicate ids, out-of-range data-quality scores) are
  `GHG-INPUT-INVALID` breaches, never coerced.
- **Scope 2 dual method.** Location-based and market-based emissions are both
  computed and reported as separate lines (`scope2:location`,
  `scope2:market`). Market-based coverage (e.g. RECs) only offsets the
  covered quantity. Every market-based Scope 2 line carries an explicit
  `disclosure` label in the pack stating the figure covers contractual
  instruments only and excludes residual-mix factors. When both methods
  compute and diverge beyond a configured basis-point threshold, a
  `GHG-SCOPE2-DIVERGENCE` warn finding is
  emitted. A missing market factor blocks market-based reporting only —
  location-based still computes, the gap is explicit.
- **Restatement-safe ledger.** Corrections are new packs that reference the
  predecessor pack's body hash and inputs hash with a mandatory reason and
  per-ledger-key deltas. Prior packs are never modified.
- **Governance.** Findings, human signoffs, provenance hashes (SHA-256 over
  canonical input/config bytes), the body seal, the `draft → awaiting_signoff
  → signed` lock, and fail-closed verification all come from `crates/spine`.
  Breach findings cannot resolve without a subject-scoped human signoff; an
  approval cannot come from the engine itself (separation of duties).

## Usage

```console
# Compute an inventory and emit a sealed evidence pack on stdout
ghg-ledger-spine compute --inputs records.json --config config.json

# Restate: a new ledger version correcting a prior pack (reason required)
ghg-ledger-spine compute --inputs records.json --config config.json \
    --prior-pack prior.json --reason "meter correction: rec-1 under-reported"

# Verify a pack against its inputs — refuses on any doubt (exit 1)
ghg-ledger-spine verify --pack pack.json --inputs records.json --config config.json

# Human-readable summary (no verification)
ghg-ledger-spine explain --pack pack.json
```

Exit codes: `0` success, `1` refusal (verification or engine), `2` usage/IO.

**The CLI is not a standalone compliance path to the signed lock.** The
`compute`, `verify`, and `explain` commands only move and check bytes — they
never advance the `draft → awaiting_signoff → signed` lock. Signoff and lock
advancement happen at the library level, through the `spine` governance
APIs; a pack that verifies is still an unsigned pack.

## Configuration (JSON, schema-checked)

| Field                        | Shape                                                                                        | Notes                                      |
| ---------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `period`                     | string                                                                                       | Caller-supplied reporting period           |
| `conversions`                | `[{from_unit, to_unit, factor{value, scale}}]`                                               | Applied once, at the boundary              |
| `factors`                    | `[{activity, unit, region, year, method, factor{value, scale}, factor_version, source}]`     | Versioned lookup table                     |
| `scope3_categories`          | `[{category 1–15, activities[]}]`                                                            | Each activity maps to at most one category |
| `dq_tiers`                   | `[{min_score, label}]`                                                                       | Strictly descending, must cover 0          |
| `scope2_divergence_warn_bps` | integer                                                                                      | Divergence warn threshold, basis points    |

Canonical units inside the engine are whatever the factor table says
(typically kWh, kg, passenger_km). A `dq_score` on a record (0–100) flows
through to the line's `confidence` label; records without one are
`not_reported`.

## Test anchors

`tests/engine.rs` covers every anchor from the product spec: factor-version
lineage in output, the missing-factor gap, Scope 2 dual-method divergence,
restatement delta correctness — plus conversion-once-at-the-boundary,
divergence threshold boundaries, DQ-tier boundaries, half-up rounding,
duplicate/negative/zero input breaches, scope-3 category config boundaries,
determinism under input reordering, and the fail-closed paths (tampered
lines, tampered findings, wrong inputs, tampered predecessor). `tests/cli.rs`
drives the binary end to end.

## Honest claims

- The shipped factor table and conversion table are **seed data** —
  illustrative EPA-style values for development and testing. They are not
  authoritative regulatory emission factors; replace them with your
  assurance-reviewed tables before any real reporting use.
- This crate makes **no compliance claims** — no GHG-protocol certification,
  no assurance standard conformance, no audited numbers, and no performance
  benchmarks. The engine is deterministic and testable; that is the whole
  claim.
- Document extraction is out of scope: the engine consumes typed activity
  records and typed factor tables, not utility bills or invoices.
- The market-based method models only quantity-level coverage (e.g.
  contractual instruments). It does not model residual-mix factors, guarantee
  of origin registries, or market-boundary rules. The `disclosure` label on
  market-based Scope 2 lines restates this limitation in-pack.
