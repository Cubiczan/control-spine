# sox-testing-spine — Internal Audit control spine

Reproducible SOX control testing as a deterministic engine: seeded sampling,
population completeness checks, and deficiency classification, shipped as
evidence packs that fail closed. Part of the
[control-spine](https://github.com/icohangar-ops/control-spine) family —
one crate per department control function, all sharing the canonical
[`spine`] governance crate by path.

## Design intent

Internal audit testing has three properties this crate makes mechanical:

1. **The sample must be reproducible.** When an external auditor asks "why
   are these 12 instances in the sample?", the answer is a seed and a rule,
   not a spreadsheet: the seed is `SHA-256` over the canonical JSON of
   `{population_id, period}`, each instance's rank is
   `SHA-256(seed || instance_id)`, and the lowest-ranked instances are
   selected. Same inputs → same sample, forever.
2. **The population must be complete.** A control that should have run 12
   times but ran 9 is a finding before any instance is tested. A control
   with an expected frequency that produced zero instances is an automatic
   failure finding — the control did not operate.
3. **Classification must be threshold arithmetic.** Failed instances are
   classified deterministically against configured thresholds. The engine
   may say "material-weakness *candidate*"; the final material-weakness
   label is a human determination, and the evidence pack says so.

The engine is pure: no clock reads, no filesystem, no network, no unseeded
randomness. Time (signoff timestamps, period labels) and every business
fact arrive through the caller's inputs. Impact and thresholds are integer
cents (`i128`). The CLI is the only filesystem surface.

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `SOX-001` completeness gap | warn | observed instances < expected frequency |
| `SOX-002` zero population | breach | expected frequency > 0, zero observed — control not performed at all |
| `SOX-010` deficiency | warn | failed instance, uncompensated, impact at or below significance |
| `SOX-011` significant deficiency | breach | failed instance, impact strictly above significance |
| `SOX-012` material-weakness candidate | breach | failed instance, impact strictly above materiality; final label stays human |
| `SOX-013` compensated exception | info | failed instance with a compensating control, impact at or below significance |
| `SOX-020` unexpected instances | warn | instances observed for a control not scheduled this period; they are still sampled and tested |

Boundaries are strictly-above: an impact exactly at a threshold stays in
the lower class. A compensating control never downgrades a classification
above materiality.

## Evidence packs

Every `compute` run emits a pack carrying:

- `inputs_hash` / `params_hash` — SHA-256 of the exact input and config
  bytes, so `verify` reproduces the run bit-for-bit;
- typed findings with rule ids, severities, and subjects (stable business
  keys: population or instance ids);
- the producing engine's identity — separation of duties: an engine cannot
  countersign its own pack;
- the spine contract version and tool version;
- a body-hash seal — any post-production body change (finding edits,
  signoff swaps, severity downgrades) breaks `verify`.

Breach findings resolve only with an approving signoff receipt naming the
finding's subject. Warn-severity findings (`SOX-001`, `SOX-010`, `SOX-020`)
do not require signoff under the family contract — only breach severity
does. Programs whose audit methodology additionally requires management
acknowledgment of below-significance failures can record approving receipts
for those subjects too; the pack carries them and `verify` accepts packs
signed beyond the mandatory minimum. Lock lifecycle: `draft →
awaiting_signoff → signed`.
Signing refuses while any finding is unresolved (crosswalk to the family
lock progression: unresolved ≡ `HALT`, `signed` ≡ `LOCKED` — the only
evidence-qualifying state). Signed packs are immutable: a correction is a
new pack computed on corrected inputs, with the prior pack's body hash
recorded as lineage in the next cycle's inputs (`prior_cycles`), never an
edit. Retesting after remediation starts a new cycle; prior results are
history, never rewritten.

## CLI

```console
# Compute a pack (lock state: draft)
sox-testing-spine compute --inputs population.json --params plan.json --output pack.json

# Record signoff receipts and advance the lock to signed
sox-testing-spine compute --inputs population.json --params plan.json \
    --signoffs receipts.json --output signed-pack.json

# Verify a pack against the exact original bytes (exit 1 on refusal)
sox-testing-spine verify --inputs population.json --params plan.json --pack signed-pack.json

# Show the plan a config applies: sample-size table, thresholds, seed
sox-testing-spine explain --params plan.json --population-id CTRL-101 --period FY2026-Q3
```

Exit codes: 0 on success, 1 on any refusal. Refusals never produce a pack
or a PASS line.

## Inputs and config

Both are schema-checked JSON (unknown fields refused) with fail-closed
semantic validation. A population carries its id, period, frequency, risk
tier, expected frequency, cycle number, prior-cycle lineage, and the
observed instances. The config carries the full frequency × risk-tier
sample-size table (every combination exactly once) and the two
classification thresholds.

Illustrative `population.json`:

```json
{
  "population_id": "CTRL-101",
  "period": "FY2026-Q3",
  "frequency": "monthly",
  "risk_tier": "high",
  "expected_frequency": 3,
  "cycle": 1,
  "prior_cycles": [],
  "instances": [
    { "instance_id": "INST-001", "performed_by": "jdoe", "executed_on": "2026-07-15", "result": "pass" },
    { "instance_id": "INST-002", "performed_by": "jane", "executed_on": "2026-08-01", "result": "fail",
      "impact_cents": 12000000, "compensating_control": null }
  ]
}
```

Illustrative `plan.json` — **SEED DATA**: the sample sizes and thresholds
below are illustrative defaults for development and demonstration, not
audited standards, regulatory figures, or recommended audit practice. Set
them from your own audit methodology before any real use.

```json
{
  "sample_size_table": [
    { "frequency": "daily",     "risk_tier": "high",   "sample_size": 25 },
    { "frequency": "daily",     "risk_tier": "medium", "sample_size": 15 },
    { "frequency": "daily",     "risk_tier": "low",    "sample_size": 5 },
    { "frequency": "weekly",    "risk_tier": "high",   "sample_size": 20 },
    { "frequency": "weekly",    "risk_tier": "medium", "sample_size": 10 },
    { "frequency": "weekly",    "risk_tier": "low",    "sample_size": 4 },
    { "frequency": "monthly",   "risk_tier": "high",   "sample_size": 3 },
    { "frequency": "monthly",   "risk_tier": "medium", "sample_size": 3 },
    { "frequency": "monthly",   "risk_tier": "low",    "sample_size": 2 },
    { "frequency": "quarterly", "risk_tier": "high",   "sample_size": 2 },
    { "frequency": "quarterly", "risk_tier": "medium", "sample_size": 2 },
    { "frequency": "quarterly", "risk_tier": "low",    "sample_size": 1 },
    { "frequency": "annual",    "risk_tier": "high",   "sample_size": 1 },
    { "frequency": "annual",    "risk_tier": "medium", "sample_size": 1 },
    { "frequency": "annual",    "risk_tier": "low",    "sample_size": 1 }
  ],
  "significance_threshold_cents": 10000000,
  "materiality_threshold_cents": 50000000
}
```

Signoff receipts (`receipts.json`) are spine `Signoff` objects; `at` is
caller-supplied ISO-8601 — the engine never reads a clock:

```json
[
  { "actor": "sam", "role": "internal-audit-director", "subject": "INST-002",
    "decision": "approve", "at": "2026-09-22T12:00:00Z" }
]
```

## What this is not

- Not GRC software: no workflow UI, no evidence storage, no remediation
  tracking — the engine computes findings and packs; humans decide.
- Not a certification and not an audit opinion: no compliance claims of
  any kind are made or implied by this crate.
- Not a document extractor: populations arrive as typed JSON, not as
  extracted control narratives.
- Not a statistical-sampling engine: selection is seeded uniform ranking,
  not monetary-unit or statistically projected sampling. If your
  methodology requires statistical projection, this crate is not that.

## Development

```console
cargo test  -p sox-testing-spine   # unit tests (engine, sampling, packs)
cargo clippy -p sox-testing-spine --all-targets -- -D warnings
cargo fmt --check -p sox-testing-spine
```

`spine` is a path dependency (`../spine`) — the canonical governance
crate; no vendored copies. Workspace CI runs fmt, clippy, and
`cargo test --workspace` on every PR.

License: MIT.
