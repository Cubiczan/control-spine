# payroll-spine — HR/Payroll control spine

Deterministic gross-to-net recomputation with fail-closed evidence packs, for
checking a payroll provider's register before funds move. Part of the
control-spine Rust workspace; depends on the canonical governance crate by
path:

```toml
[dependencies]
spine = { path = "../spine" }
```

Design intent: the value is the deterministic core plus the evidence trail,
not workflow ergonomics. The engine is a pure function over explicit inputs —
no clock, no filesystem, no network, no unseeded randomness; time is caller
input; every monetary amount is an integer number of cents (`i128`); every
rate is an integer number of millionths (`micro`, so `6_200_000` = 6.2%);
rounding is half-up to the cent, per line, exactly once.

## What it computes

For each employee over a payroll period:

- **Period gross** — annual salary divided by the calendar's period count
  (semi-monthly = 24, biweekly = 26), prorated by calendar-day fraction for
  mid-period starts and separations.
- **Pre-tax ordering** — Section 125 deductions reduce FIT, Social Security,
  and Medicare wage bases; the 401(k) deferral reduces FIT only when
  `retirement_401k_pre_tax` is true, and never reduces FICA wage bases.
- **FIT** — progressive bracket withholding from config tables, computed on
  annualized wages and de-annualized to the period with half-up rounding.
- **Social Security** — 6.2% up to the wage base; when YTD wages cross the
  cap mid-period, only the excess above the cap is taxed.
- **Medicare** — 1.45% on all wages plus the 0.9% additional rate on the
  portion of wages above the YTD threshold (employee-only; not matched).
- **Employer side** — FICA match (regular SS + Medicare only), FUTA at the
  credit-reduced rate over its wage base, SUTA from a per-state schedule.
- **Register variance** — when a provider net pay is supplied, a ±tolerance
  (default zero, i.e. the cent) check emits a `Warn` finding per mismatched
  employee.
- **Negative net** — deductions exceeding gross produce a `Breach` finding
  with `requires_signoff: true`; wage bases clamp at zero and the pack
  verifies only after a human signoff.

## CLI

```text
payroll-spine compute --inputs inputs.json --config config.json [--out pack.json]
payroll-spine verify  --pack pack.json --inputs inputs.json --config config.json
payroll-spine explain --inputs inputs.json --config config.json
```

`compute` emits an evidence pack: SHA-256 provenance hashes over canonical
input and config bytes, findings, signoffs, and a body seal. `verify` is
fail-closed — it recomputes the hashes, checks the seal, requires subject-
scoped signoffs for every breach finding, and reproduces the findings from
the presented inputs; any refusal exits nonzero. `explain` prints a
deterministic human-readable breakdown.

## Seed data — not authoritative values

Every table in `config.json` (FICA rates and bases, FUTA rate and credit,
SUTA schedules, federal bracket tables, tolerances) is **seed data** for
testing and demonstration. The defaults mirror widely published 2024-2025
US federal figures (6.2% SS to $168,600; 1.45% Medicare; 0.9% additional
Medicare over $200,000; 6.0% FUTA with a 5.4% credit to $7,000) and two
illustrative SUTA states, but they are **not maintained against legislation**
and are not tax, legal, or compliance advice. Operators must supply current,
jurisdiction-correct tables; the engine validates shape and sanity
(non-negative rates, ordered brackets, credit below the federal rate,
tolerance ≥ 0, SUTA base > 0) but cannot validate whether a number is the
law's current answer.

Optional `valid_for_tax_year` declares the year the supplied tables were
built for. A run whose period starts in a different year emits a
`PAY-TAX-YEAR` warning finding — a signal to re-check the tables, not a
refusal, because the engine cannot know current law.

Year-to-date wage balances (`ytd_*` fields) are **caller-supplied at every
run**; the engine does not accumulate them across runs. Cap-crossing logic
(Social Security base, additional Medicare threshold) is only as sound as
those YTD figures — typically sourced from the same payroll provider whose
register the engine audits. Cross-check YTD balances before relying on
cap-crossing evidence.

## Purity and determinism

- No clock: the period and every employee date are inputs; findings whose
  wording mentions "as of" a date embed the caller-supplied period end.
- No floats anywhere; no `unsafe`; no I/O in the engine or config modules.
- Canonical hashes: inputs and config are re-serialized through serde in
  fixed field order (maps are `BTreeMap`), so formatting and JSON key order
  of source files never change a hash.
- Deterministic output: same inputs + config → byte-identical pack (modulo
  the engine/tool versions).

## Honest scope

- Single-employer, single-state-per-employee, USD-only, salary-only gross in
  v1. No hourly wages, no local taxes, no pre-tax commuter/HSA ordering
  beyond Section 125 and 401(k), no multi-state proration, no garnishment
  priority ordering beyond fixed deduction order, no check-level rounding
  reconciliation against the provider's own breakdown.
- This crate does not file, remit, or authorize anything. It recomputes and
  reports; a human signs.
- No performance benchmarks are claimed. No payroll compliance certification
  is claimed or implied.
