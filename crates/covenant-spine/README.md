# covenant-spine — Treasury/Finance covenant control spine

Deterministic debt-covenant testing over normalized financials: typed
covenants, effective-dated amendment resolution, equity-cure adjustments,
headroom with explicit units, and a deterministic linear-trend breach
projection — emitted as spine evidence packs.

Part of the control-spine family. The governance contract — the seal gate,
subject-scoped signoff receipts, four-eyes, immutable signed packs, and
fail-closed verification — lives in the canonical `crates/spine` crate and is
used here by path dependency. Nothing in this crate re-implements it.

## Covenant semantics

| kind | formula | direction |
| --- | --- | --- |
| `max_leverage` | total debt / EBITDA | ratio must be ≤ threshold |
| `min_interest_coverage` | EBITDA / interest expense | ratio must be ≥ threshold |
| `min_current_ratio` | current assets / current liabilities | ratio must be ≥ threshold |
| `min_fixed_charge_coverage` | (EBITDA + rent) / (interest + rent + current maturities) | ratio must be ≥ threshold |

Thresholds are per-covenant config; the kind fixes the formula and the
comparison direction. Boundaries are inclusive — exactly at the threshold is
compliant. Headroom is `threshold − ratio` for maximums and `ratio −
threshold` for minimums: positive means compliant, zero means exactly at the
threshold, negative means in breach. Headroom is reported in ratio units
("x").

## Units — no floats

* Money is integer cents (`Cents`, i128), serialized in JSON as strings
  (`"total_debt_cents": "1234500"`) so values beyond JSON's 2^53
  exact-integer ceiling survive round-trips untouched. Bare JSON numbers are
  refused at the schema.
* Ratios (thresholds, measured ratios, headroom, trend slopes) are integers
  scaled by millionths (`Ratio`): `3.5x` is stored as `3_500_000`. Thresholds
  are parsed from exact decimal strings with at most six fractional digits;
  more digits are refused rather than rounded.
* Division truncates at millionths and the suite pins the truncation
  (12/13 reads 0.923076x). All arithmetic is integer — the engine contains
  no floating-point operations.

## Inputs

* **Config** (`--config`): the typed covenant rules, equity cures, and
  projection settings, schema-checked with unknown keys rejected. All
  shipped rule and threshold tables in this repo, including every example
  here, are **seed data for tests and demos** — not advisory thresholds, and
  not regulatory or accounting guidance.
* **Financials** (`--financials`): normalized quarterly periods plus the
  `measurement_date`. **The clock is an input** — the engine never reads a
  wall-clock time. Flow items (EBITDA, interest, rent, current maturities)
  are the quarter's amounts; stock items (total debt, current assets,
  current liabilities) are the quarter-end balances. Period rows are the
  entity's fiscal quarters; the engine sorts by `period_end` and refuses
  duplicate period ids or dates.

## Rules and edge cases

* **Basis.** `quarterly` measures the single period ending on or before the
  measurement date; `ltm` sums the trailing four quarterly rows (flow items)
  and takes stock items from the last row. Insufficient history for an LTM
  covenant is a breach-severity `ltm-history-insufficient` finding — scoped
  to that covenant, never silently skipped, never padded.
* **Effective-dated amendments.** Multiple config rows may share a covenant
  id (an amendment history). The text in force at the measurement date is
  the row whose half-open window `[effective_from, effective_to)` contains
  the date. Zero rows in force → informational finding; more than one →
  breach-severity `ambiguous-covenant-versions` finding (fail-closed).
* **Equity cures.** Config-anchored adjustments (`add_to_ebitda_cents`,
  `reduce_debt_cents`) applied to the measurement evaluation when the
  measurement date falls in the cure window; matching cures sum in config
  order. Cures apply to the measurement only — the trend projection reads
  raw history.
* **Non-positive EBITDA.** Under an EBITDA-based covenant (leverage, both
  coverage kinds), negative or zero EBITDA is an automatic breach finding —
  never a panic, never a division.
* **Vacuous passes.** A non-positive denominator with a positive numerator
  (zero interest expense, zero current liabilities, zero fixed charges) is
  reported as a warn-severity `vacuous pass` with no ratio — a pass that was
  not really tested is visible, and never fabricated.
* **Breach projection.** For each passing covenant, the engine fits a linear
  trend (ordinary least squares in integer arithmetic with truncating
  division) over the covenant's ratio series on its own basis, and warns
  when the trend crosses strictly beyond the threshold within
  `horizon_quarters` (the quarter of the crossing is named). Windows with
  non-computable ratios are skipped; fewer computable points than
  `min_history_points` yields an informational skip finding; a covenant
  already in breach gets no projection finding on top.

## Governance (all canonical spine, by path dependency)

* Every compute run emits an `EvidencePack` with SHA-256 `inputs_hash` and
  `params_hash` over **canonical JSON** (sorted keys, no insignificant
  whitespace) — cosmetic reformatting never breaks verification, any value
  change does.
* Packs start in `awaiting_signoff`, unsealed. `sign` records receipts;
  spine's lock lifecycle advances the pack and seals it on the transition to
  `signed` (body hash over the canonical body). `verify` recomputes the seal,
  both provenance hashes, and signoff coverage, and refuses any doubt — a
  tampered pack fails `verify`.
* Breach-severity findings require an approving receipt naming the finding
  subject; multi-breach packs need per-subject coverage; receipts by the
  engine itself (`covenant-spine`) are void.
* **Four-eyes:** accepting a covenant breach is this product's privileged
  action — sealing a pack that contains a breach finding requires approvals
  from two distinct human signers (the engine's void receipts do not count).
  Clean packs seal without receipts, per spine semantics.
* Lock crosswalk (documented in spine): `awaiting_signoff` ≡
  ADVISORY/PROVISIONAL_LOCK, `signed` ≡ LOCKED (the only evidence-qualifying
  state), unresolved finding ≡ HALT. Signed packs are immutable; corrections
  are fresh packs computed on corrected inputs with predecessor lineage in
  tool metadata.

## CLI

```console
# Run the engine; stdout (or --out) carries the pack envelope JSON.
covenant-spine compute --config covenant.json --financials financials.json --out pack.json

# Record a receipt; seals when requirements are met (four-eyes on breach packs).
covenant-spine sign --pack pack.json --actor sam --role treasurer \
  --subject LEV-01 --decision approve --at 2026-09-22T10:00:00Z

# Fail-closed verification against the original inputs and config.
covenant-spine verify --pack pack.json --config covenant.json --financials financials.json

# Which covenant text is in force at a date (config only, no financials).
covenant-spine explain --config covenant.json --date 2026-06-30
```

Exit codes: 0 = success, 1 = verification refused, 2 = usage/config error.

## Honest claims

* No benchmarks, no compliance certifications, no audit endorsements are
  claimed or implied. This is a deterministic arithmetic engine plus
  evidence plumbing.
* All shipped config/threshold tables and README examples are seed data for
  tests and demos — not advisory thresholds, not legal, accounting, or tax
  guidance, and not a substitute for the covenant text in the underlying
  credit agreement. Covenant definitions vary; the fixed-charge formula here
  is one conventional definition, documented above and pinned by tests.
* The breach projection is a linear-trend heuristic in scaled integers — a
  simplification by design, documented so it is never mistaken for a
  forecast model.
* Design intent: the deterministic core plus the evidence trail is the
  product. Extraction of covenant terms from agreement documents is out of
  scope; the engine consumes typed, normalized inputs.
