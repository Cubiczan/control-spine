# coi-spine

Risk/Insurance member of the control-spine family: deterministic vendor
certificate-of-insurance (COI) coverage-gap detection with evidence packs,
subject-scoped human signoff, and fail-closed verification.

The engine evaluates **typed certificate data** against a configuration-driven
requirements matrix and emits a `spine::EvidencePack` carrying SHA-256
provenance hashes, typed findings, and the signoff receipts that resolve them.

## What it is for

A vendor's COI expires, or carries limits below what their contract requires,
or is missing an additional-insured endorsement — and nobody notices until
there is a claim. The missed expiry is an uninsured loss. This crate turns
that check into deterministic arithmetic over a clock the caller supplies:

- vendor category → required coverages, minimum limits (integer cents),
  required endorsements, criticality flag
- per-policy-line checks: coverage expiration, limit floors, endorsements,
  carrier rating
- advisory lockout **recommendation** when a breach-severity gap exists on a
  critical vendor category — a human executes any purchase-order hold; the
  engine never locks anything by itself

## Boundary

The engine consumes typed JSON, not documents. Extracting coverage data from
certificate PDFs is fuzzy and out of scope; a future extraction layer feeds
this engine, and malformed typed input is refused, never coerced
(`deny_unknown_fields`, closed vocabularies for coverage kinds, endorsements,
and carrier ratings).

## Engine purity

No clock (the as-of date is caller input), no filesystem, no network, no RNG.
Money is `i128` integer cents. Policy selection across multi-policy
certificates is deterministic: current lines only, latest expiration first,
then highest per-occurrence limit, then lowest policy number.

## Findings

| Rule | Severity |
| --- | --- |
| required coverage absent | breach |
| required coverage expired | breach |
| limit below per-occurrence or aggregate floor | breach |
| required endorsement missing | breach |
| carrier rating below floor | breach |
| coverage expires within the warning window | warn |
| vendor category absent from the matrix | warn (recommended finding: fix the matrix) |
| critical-category lockout recommendation | warn (advisory; human executes) |

Every breach finding carries `requires_signoff: true` and is resolved only by
a `spine::Signoff` receipt whose `subject` names the finding subject (the
vendor id) — enforced by the canonical `spine` crate, which this crate
depends on by path (`spine = { path = "../spine" }`). The producing engine
cannot countersign its own pack.

## Lock lifecycle

`draft → awaiting_signoff → signed`, via `spine::advance_lock`. Signing
seals the pack: a SHA-256 body hash is computed over the canonical pack body,
and `verify()` recomputes it fail-closed. Signed packs are immutable;
corrections are new packs computed from corrected inputs. Crosswalk to the
Python family: Draft ≡ pre-ADVISORY, AwaitingSignoff ≡ ADVISORY/PROVISIONAL_LOCK,
Signed ≡ LOCKED, unresolved breach ≡ HALT.

## CLI

```sh
coi-spine compute --inputs cert.json --config matrix.json --as-of 2026-09-22 --out pack.json
coi-spine sign    --pack pack.json \
    --actor "Reina Park" --role risk_manager --subject V-1001 \
    --decision approve --at 2026-09-22T15:04:05Z
coi-spine verify  --pack pack.json --inputs cert.json --config matrix.json
coi-spine explain --config matrix.json
```

Exit codes: `0` success, `1` refusal or failure, `2` usage error.

`verify` refuses (fail-closed) when the seal does not recompute, the pack is
unsealed, provenance hashes mismatch the presented inputs/config, or a breach
finding lacks a subject-scoped approval. `sign` without `--actor` signs a
breachless pack as-is; with `--actor` it records a subject-scoped receipt and
refuses to seal while a breach is unresolved.

Example requirements matrix (see `examples/`):

```json
{
  "categories": {
    "electrical_contractor": {
      "critical": true,
      "coverages": {
        "general_liability": {
          "per_occurrence_cents": 100000000,
          "aggregate_cents": 200000000,
          "endorsements": ["additional_insured"]
        }
      }
    }
  },
  "expiry_warning_days": 30,
  "min_carrier_rating": "a_minus"
}
```

## Seed data

The matrix in `examples/` and any default limits are **seed data**: plausible
placeholder values for testing, not authoritative requirements. Coverage
requirements, limits, endorsement vocabulary, and carrier-rating conventions
vary by contract and jurisdiction — derive your matrix from executed vendor
agreements and your broker's advice before production use. Carrier ratings
are a coarse AM-Best-style letter scale for demonstration; no compliance
certification is claimed or implied.

## Honesty

No benchmarks, no compliance certifications, no invented insurance standards.
The crate is a deterministic checker over config you own.

## Tests

`cargo test -p coi-spine` covers every rule branch, the inclusive expiry
warning window and its boundary day, limit floors (per-occurrence and
aggregate, strict comparison), endorsement and carrier-rating boundaries,
multi-policy selection order and non-selected-line guarantees, lockout
gating on criticality and severity, malformed-input refusals, determinism
under reordering, provenance-hash stability across JSON whitespace/key
order, engine self-countersign prevention, tampered-pack refusal, and the
full CLI round trip including exit codes.
