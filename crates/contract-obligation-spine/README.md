# contract-obligation-spine

Legal department control spine: a typed contract-obligation register with
deterministic deadline and renewal-window arithmetic, evidence packs, and
fail-closed verification. Part of the control-spine family — pure Rust
engine, `spine` governance crate by path, human signoff on breach-severity
findings.

## Design intent

The engine answers, deterministically and reproducibly, three questions about
a contract register at a given date:

1. **What is due?** Every `payment`, `delivery`, `indemnity`, and
   `termination_for_convenience` obligation resolves to an effective due
   date — a contract-stated explicit date, or a dependent date: an anchor
   obligation's due (or recorded completion) date shifted by clamped month
   and day offsets ("net 30 after delivery", "within 30 days of delivery").
   Computed dates roll forward over weekends and holidays when the params
   say so; explicit contract dates are never rewritten.
2. **Which renewal windows are closing?** Every `renewal_opt_out` obligation
   gets its opt-out deadline (`renewal_date − notice_days`, business-day
   rolled), days remaining, and findings when a window closes without an
   opt-out (breach under auto-renew; an informational record under
   non-auto-renew terms, preserving the audit trail without asserting a
   breach), or when a contract has already renewed without one (breach).
3. **What do the SLAs owe?** Every `sla` obligation's measured periods land
   in a credit tier from the params table; a period below every tier floor
   is a breach, a stale measurement is a monitoring warn, and credits are
   computed in integer cents.

The register is append-only: corrections are new record versions that
supersede the prior version — never mutations. Findings always reflect the
latest version, and verifying an evidence pack over a corrected register
requires four-eyes signoff per corrected obligation (the register's one
privileged action).

Governance follows the family contract in `crates/spine`: every compute run
emits a sealed evidence pack (SHA-256 over the canonical pack body, plus
provenance hashes of the exact register and policy inputs), breach findings
carry subject-scoped signoff receipts, and `verify` recomputes everything
fail-closed — refusing hash mismatches, tampered bodies, foreign spine
versions, unresolved breaches, and unsigned corrections. An approval whose
actor matches the engine id is void: the engine cannot countersign its own
pack.

The engine is pure: no clock, filesystem, network, or randomness. Time is
caller input (`--clock YYYY-MM-DD`); money is integer cents (i128);
percentages are basis points. The same inputs always produce byte-identical
output.

## CLI

```text
contract-obligation-spine compute  --inputs register.json --params params.json --clock 2026-09-22 [--signoffs receipts.json] [--out pack.json]
contract-obligation-spine verify   --pack pack.json --inputs register.json --params params.json
contract-obligation-spine explain  --inputs register.json --params params.json --clock 2026-09-22
```

`compute` emits the sealed evidence pack (JSON) and reports finding counts
and lock state on stderr. `verify` exits 0 only when the pack proves out
against the exact register and params supplied — exit 1 means refused. Exit
2 means schema or config error (no pack was produced). `explain` prints the
same arithmetic in plain text for a human reviewer.

## Configuration (seed data)

Params JSON carries the warn windows, the business-day roll mode, the
jurisdiction calendar table, and the SLA credit-tier table. **All shipped
calendars and tier tables are illustrative seed data, not authoritative
legal, tax, or regulatory values** — operators must load their own
jurisdiction-accurate calendars and negotiated SLA tier schedules. The
engine validates their shape strictly (unknown fields rejected, tiers
strictly descending, bounded knobs) and refuses malformed config rather
than guessing.

The engine consumes **typed obligations**: extraction of obligations from
contract documents is out of scope and must be performed upstream (human or
tooling) before records enter the register. Deadline and renewal arithmetic
is the product; document extraction is a separate problem.

## Guarantees and non-guarantees

- Guarantees: deterministic evaluation; typed, versioned register with
  correction lineage; sealed, provenance-hashed evidence packs; fail-closed
  verification (tamper-evident, signoff-enforced, four-eyes on corrections).
- Non-guarantees: this crate makes no compliance certifications of any kind,
  contains no benchmarks, and does not replace legal review. Findings are
  decision support for the obligation register's owner; the register's
  accuracy depends on the correctness of the typed records fed to it.
