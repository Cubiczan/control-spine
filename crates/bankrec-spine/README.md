# bankrec-spine — Treasury bank reconciliation control spine

Deterministic statement-to-ledger matching for the Treasury close: bank
statement lines are matched to ledger entries through tiered rules, unmatched
items are escalated on the clock, and every run emits a fail-closed evidence
pack carrying SHA-256 provenance hashes and the signoff receipts that resolve
breach findings.

Part of the `control-spine` family: the engine is a pure function over
explicit inputs, the CLI is the only I/O boundary, and governance comes from
the canonical [`crates/spine`](../../crates/spine) crate (path dependency —
never vendored).

## What it does

`bankrec-spine compute --inputs inputs.json --config config.json --as-of 2026-09-22`

**Match tiers** (each statement line matches at most one item, applied
globally in this order — an exact match always outranks a looser one):

1. **Exact** — same normalized reference and amount.
2. **Tolerance** — same normalized reference, amounts within
   `tolerance_cents`; the smallest variance wins, input order breaks ties.
3. **Many-to-one** — up to `max_group_size` same-sign ledger entries summing
   to one statement line within tolerance; candidate groups are generated
   deterministically from a reference-and-date-ordered candidate list.

Sign convention is normalized at the boundary: statement amounts are signed
cash-flow cents (inflow positive); ledger amounts are positive magnitudes
with a `debit`/`credit` cash-account side.

**Findings** (typed, on the spine's `Severity` scale):

| Rule id | Condition | Severity |
| --- | --- | --- |
| `stmt-unmatched` | statement line unmatched; `stale_days` past date | warn → breach (stale) |
| `ledger-unmatched` | ledger entry unmatched; `stale_days` past date | warn → breach (stale) |
| `dup-statement` | duplicate (date, reference, amount) statement lines | warn |

Every breach finding carries `requires_signoff: true` and cannot resolve
without a human signoff receipt naming the finding's subject — the pack's own
engine id can never countersign it (`crates/spine` enforces both).

**Adjustment proposals** are derived mechanically from unmatched items (for
example, propose recording an unmatched statement-only charge), never applied:
they are inputs to the human close, not bookings.

## Evidence pack

A compute run emits a sealed pack: SHA-256 of the inputs and config bytes as
read, findings, signoff receipts, tool/spine versions, and a body-hash seal.
`bankrec-spine verify --pack out.json --inputs ... --config ...` recomputes
everything and **refuses on any doubt** — wrong hashes, tampered body,
unresolved breach findings, foreign versions. Exit code `1` means refused;
a pack that verifies is pack-identical to a fresh recomputation of the same
inputs under the same config.

`bankrec-spine explain --report out.json` renders the reconciliation as
human-readable text for the close binder.

## Purity contract

The engine never reads a clock, filesystem, or network. The reporting date
enters as `--as-of`; aging is `as_of − item date`. All money is integer cents
(`i128`); there are no floats and no randomness. Single-currency in v1.

## Config (seed data, schema-checked)

```json
{
  "tolerance_cents": 500,
  "max_group_size": 5,
  "stale_days": 14,
  "many_to_one_candidate_cap": 100
}
```

These values are **seed defaults, not policy**: they are a starting point for
a treasury team to set per entity/account, and this repository does not
represent any institution's approved tolerance policy. `deny_unknown_fields`
guards the schema; invalid configs refuse to run rather than guess.

## Honest claims

- The rules implement plain reconciliation arithmetic and set algebra. No
  regulatory certifications, audits, or third-party benchmarks are claimed or
  implied, and none should be inferred.
- The example inputs are synthetic.
- The engine consumes typed statement/ledger rows; ingesting bank feeds or
  extracting ledger entries is out of scope, as is multi-currency matching.
- v1 groups are capped at `max_group_size` candidates from a bounded
  candidate list (`many_to_one_candidate_cap`); pathological many-to-many
  entanglement falls out to the unmatched ledger for human treatment.

## Development

From the workspace root:

```sh
cargo fmt --check && cargo clippy -D warnings && cargo test --workspace
```

Tests tie to the spec's anchors: tier hits and misses, tolerance boundaries,
deterministic many-to-one grouping, stale escalation, duplicate warnings,
fail-closed pack verification (tamper refusal, subject signoff, engine
countersign refusal), and CLI exit codes.
