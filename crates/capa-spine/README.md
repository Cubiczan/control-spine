# capa-spine — Quality/EHS control spine

Deterministic corrective/preventive-action (CAPA) governance over
nonconformances: nonconformance → classified severity → containment clock →
effectiveness verification → human-locked closure. Part of the
[control-spine](../../README.md) family: a pure domain engine, evidence packs
with SHA-256 provenance, and fail-closed verification through the canonical
[`spine`](../spine) crate (path dependency — no vendored copy).

## Design intent

The control computation is deterministic arithmetic and set algebra over
typed records; a human signoff closes the loop. The engine is pure — no
clock reads (time is the caller's `--as-of` input), no filesystem, no
network, no RNG. Identical records, config, and clock produce identical
findings in identical order.

## Rules

1. **Severity** — classified from the configured matrix: category
   (`safety | regulatory | quality`) × detectability (`high | medium | low`)
   → spine severity. The matrix is validated complete (every cell present
   exactly once) before the engine runs.
2. **Containment** — required within `containment_hours[severity]` of
   opening, when a window is configured for that severity. No containment
   recorded strictly past the due instant → `CONTAINMENT_OVERDUE` (breach).
   Recorded late → `CONTAINMENT_LATE` (warn).
3. **Closure validity** — a recorded closure without a non-blank root cause,
   or without `closed_at`, is refused: `CLOSURE_BLOCKED` (breach) and the
   CAPA is treated as open (aging applies). Fail-closed — a closure the
   engine cannot honor is never honored.
4. **Effectiveness verification** — for an honored closure, the check is due
   `effectiveness_window_days` after `closed_at`; incomplete past the due
   instant → `EFFECTIVENESS_OVERDUE` (breach). While unresolved, the pack
   cannot reach `Signed`, so closure cannot finalize without the check.
5. **Aging** — open (or refused-closure) CAPAs age past `warn_after_days`
   (`AGING_WARN`) and `breach_after_days` (`AGING_BREACH`); breach
   supersedes warn. Boundaries are strict: at the threshold is not past.
6. **Reopen linkage** — a reopened CAPA is a new cycle naming its parent;
   its clocks anchor at its own `opened_at`, never the parent's. A parent
   missing from the population (or the record itself) →
   `BROKEN_REOPEN_LINK` (breach).
7. **Duplicate detection** — normalized description hashes (case- and
   whitespace-insensitive, SHA-256) that collide → `DUPLICATE_DESCRIPTION`
   (warn) on every carrier except the lexicographically smallest id, which
   is canonical.

Every breach finding carries a signoff requirement (`requires_signoff`),
resolved only by an approving `spine::Signoff` naming the finding's subject —
the rule is enforced in the canonical spine crate, not re-implemented here.
The producing engine's own receipt is void (separation of duties).

## Interpretation note: two-stage closure

The spec sentence "closure requires root cause recorded + effectiveness
check completed + signoff" is enforced deterministically in two stages:
(1) a closure request without root cause or effective date is refused
outright — the CAPA ages as open; (2) the effectiveness check is due
`effectiveness_window_days` after the recorded closure, and its lapse is a
breach that blocks the pack from reaching `Signed` — so final closure
requires the check and a human signoff. Every spec sentence stays live and
the clock never reads itself.

## Input contract

`id` must be unique within the population — findings and signoff receipts
are keyed by subject, so duplicate ids would make receipts ambiguous.
Records and config are schema-checked JSON (`deny_unknown_fields`); unknown
fields and incomplete matrices refuse to load.

## Seed data — not a validated standard

The severity matrix, containment hours, aging thresholds, and effectiveness
window shipped in the tests (and printed below) are **seed data** that make
the rules concrete, not validated regulatory values. Tune them to your
QMS before operational use.

```json
{
  "severity_matrix": [
    {"category": "safety", "detectability": "high", "severity": "warn"},
    {"category": "safety", "detectability": "medium", "severity": "breach"},
    {"category": "safety", "detectability": "low", "severity": "breach"},
    {"category": "regulatory", "detectability": "high", "severity": "warn"},
    {"category": "regulatory", "detectability": "medium", "severity": "warn"},
    {"category": "regulatory", "detectability": "low", "severity": "breach"},
    {"category": "quality", "detectability": "high", "severity": "info"},
    {"category": "quality", "detectability": "medium", "severity": "warn"},
    {"category": "quality", "detectability": "low", "severity": "breach"}
  ],
  "containment_hours": {"breach": 24, "warn": 72, "info": null},
  "aging": {"warn_after_days": 30, "breach_after_days": 90},
  "effectiveness_window_days": 60
}
```

## CLI

```console
$ capa-spine compute --capas capas.json --config config.json \
    --as-of 2026-09-22T00:00:00Z --output pack.json
capa-spine: 2 capa(s), 2 finding(s) — 1 breach, 1 warn, 0 info
capa-spine: 1 breach finding(s) require subject-scoped signoff receipts before this pack verifies

$ capa-spine verify --pack pack.json --capas capas.json --config config.json
error: refused: breach finding CONTAINMENT_OVERDUE lacks an approving signoff naming its subject — fail-closed

$ capa-spine explain --capas capas.json --config config.json \
    --as-of 2026-09-22T00:00:00Z --capa-id CAPA-1
CAPA CAPA-1 — classified BREACH (severity matrix: quality × low)
...
```

`compute` emits a sealed pack with SHA-256 `inputs_hash`/`params_hash` over
the exact input and config bytes. Appending signoff receipts to a pack body
invalidates its seal by design — re-seal (`sealed()`, or the spine lock
lifecycle's transition to `Signed`, which refuses while any finding is
unresolved) and then `verify`. Exit codes: 0 verified/success, 1 refused.

## Scope

The engine consumes typed CAPA records. Whatever produces those records
(QMS exports, incident intake) is upstream and out of scope. No benchmark
numbers and no compliance certifications are claimed or implied by this
crate.
