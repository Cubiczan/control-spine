# dqf-spine — Fleet/Logistics control spine

Deterministic DOT driver-qualification-file (DQF) compliance for the
Department Control-Spine Products family: checklist expiry detection,
out-of-service (OOS) risk flags, and fail-closed evidence packs over a
per-driver document file.

The engine is **pure**: the campaign date is an input (`--as-of`), and the
engine never reads a clock, the filesystem, or the network. No RNG occurs in
this domain, and no monetary arithmetic — the family's integer-cents rule is
not exercised here. All date arithmetic is checked (`checked_add_months` /
`checked_add_days`) and refuses overflow.

The crate depends on the canonical `spine` governance crate by path
(`../spine`); subject-scoped signoffs, separation of duties (an engine cannot
countersign its own pack), the seal gate, and the lock lifecycle are enforced
there and are never re-implemented here.

## Rule table

| Rule id | Trigger | Severity |
| --- | --- | --- |
| `DQF-CDL-EXPIRED` | Governing CDL past effective expiry | Breach if actively driving, else Warn |
| `DQF-MED-EXPIRED` | Governing medical certificate past effective expiry | Breach if actively driving, else Warn |
| `DQF-CDL-MISSING` / `DQF-MED-MISSING` | Required current-cycle document absent | Breach if actively driving (same risk class as expired), else Warn |
| `DQF-MVR-MISSING`, `DQF-ANNUAL-REVIEW-MISSING`, `DQF-ROADTEST-MISSING`, `DQF-EMPLOYMENT-HISTORY-MISSING` | Required current-cycle document absent | Warn |
| `DQF-MVR-STALE` | MVR older than its config window | Warn |
| `DQF-ANNUAL-REVIEW-STALE` | Annual review older than its config window | Warn |
| `DQF-MED-WINDOW-OVERMAX` | Printed medical validity exceeds the ceiling for its certificate type | Warn (effective expiry capped) |
| `DQF-CDL-WINDOW-OVERMAX` | Printed CDL validity exceeds a state maximum | Warn (effective expiry capped) |
| `DQF-ENDORSEMENT-MISSING` | CDL lacks an operation-required endorsement | Warn |
| `DQF-STATE-CDL-RULE` | CDL does not satisfy the operating state's rule | Warn |
| `DQF-REHIRE-LINKAGE` | Rehire's prior cycle is unknown or not a prior cycle | Warn |
| `DQF-OUT-OF-CYCLE-DOC` | Document stamped with a cycle other than the driver's current cycle | Warn |
| `DQF-EXPIRING-SOON` | Expiry or window boundary within `expiring_warn_days` of the campaign date, inclusive | Warn |

Breach-severity findings (`Finding::breach`) always require a signoff receipt
naming the driver's subject. Resolving an OOS breach — returning a driver to
service — is a privileged action under fleet policy and requires **four-eyes**
approval (two distinct human signers): `four_eyes_ok_for_subject` scopes the
check to the subject and voids engine-actor receipts.

## Boundary conventions

* An expiry-typed document (CDL, medical) is **valid through its printed
  expiry date** and expired strictly after — consistent with the family
  convention ("expired (before clock date)").
* A window-typed document (MVR, annual review) is valid through
  `issued_on + window` and stale strictly after.
* The expiring-soon warning fires when the boundary is within
  `expiring_warn_days` days of the campaign date, inclusive.
* Medical ceilings are per certificate type and may not exceed 24 months
  (full and variance alike); a certificate printed beyond its type's ceiling
  is capped — the capped date drives expiry and OOS decisions. This is the
  variance-vs-full edge case: identical printed dates expire differently by
  certificate type.
* Month arithmetic clamps to the end of the target month (e.g. Jan 31 + 1
  month = Feb 28/29).
* Endorsement codes compare trimmed and case-insensitive — distinctness and
  matches can only be under-counted, never over-counted (fail-closed
  direction).
* The governing document of a kind is the latest issuance (ties broken by
  `doc_id`); renewal history is normal and older documents are not re-checked.
* Checklist completeness is evaluated against the driver's **current file
  cycle only** — a rehired driver's prior-cycle documents trigger
  out-of-cycle warnings and current-cycle gaps; the rehire linkage must name
  a known prior cycle.
* State CDL rules key on the driver's **operating state** (`cdl_state`); the
  CDL's issuing state is recorded on the document but does not select the
  rule.

## Fail-closed input shape

Config and driver JSON are schema-checked (`deny_unknown_fields` everywhere):
unknown fields, documents contradicting their kind (e.g. an MVR carrying a
`cert_type`), future-dated documents, future hire dates, duplicate driver or
document ids, duplicate state rules, zero validity windows, and medical
ceilings above 24 months are all **refused** with a typed error — never
silently repaired.

## CLI

```console
# compute: findings + sealed evidence pack (stdout or --output)
dqf-spine compute --drivers drivers.json --config config.json --as-of 2026-09-22 --output pack.json

# verify: fail-closed recomputation against the original bytes
dqf-spine verify --pack pack.json --drivers drivers.json --config config.json

# explain: human-readable findings and signoff coverage
dqf-spine explain --pack pack.json
```

Exit codes: `0` ok · `1` verification refused · `2` usage or input error.

`compute` emits the pack **sealed in Draft lock state** — tamper-evident from
birth. Signoffs are applied through the human lock flow
(`spine::advance_lock`: `draft → awaiting_signoff → signed`, sealing on
Signed); only signed packs are evidence, and a pack with an unresolved breach
cannot progress. Any body change after sealing — including adding a signoff
by hand — breaks the seal and `verify` refuses.

## Config tables

All shipped values — window lengths, warn windows, state rules — are **seed
data** for development and testing. They are not regulatory tables, are not
legal advice, and make no claim to match any carrier's actual program or a
specific state's current requirements; operators supply their own.

## Honest claims

This crate makes no compliance certifications, emits no benchmark figures,
and claims no regulatory approval. It is a deterministic arithmetic and
set-algebra engine over caller-supplied inputs: it detects what its rules
name on the data it is given, and it is not a substitute for the carrier's
safety program or an audit.

## Tests

`cargo test -p dqf-spine` covers every anchor from the spec block: each
checklist item's expiry boundary (CDL, medical, MVR, annual review, plus the
expiring-soon window edge), OOS flags (breach while actively driving, warn
when inactive or separated), missing-document gaps (including the
breach-escalation for an active driver's missing CDL/medical), rehire
linkage (unknown prior cycle, prior-cycle documents not carrying over, clean
rehire), variance-vs-full medical windows, state rules (endorsements and
validity caps), governing-document selection, fail-closed input refusals,
determinism, and the governance path end to end — tampered body, tampered
inputs/params, foreign spine version, engine self-countersignature,
subject-scoped and four-eyes signoff resolution — plus CLI process tests for
compute/verify/explain with refusal exit codes.
