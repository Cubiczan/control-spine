# commission-spine

Deterministic sales commission control spine: computes rep commissions from
plan configuration and typed transactions, and emits fail-closed evidence
packs under the canonical [`crates/spine`](../spine) governance contract
(path dependency — never vendored).

Part of the Department Control-Spine family (spec: "Department Control-Spine
Products — Coverage & Build Spec", Sales block).

## What it computes

Given a plan config (effective-dated plan versions) and a transactions file
(sales and returns with credit assignments), the engine produces:

- **Credit lines** — one per credited (rep, role) share of each sale, and
  negative reversal lines for returns (clawbacks), linked to the original.
- **Per-rep summaries** — gross/returned/net credited revenue, attainment in
  parts-per-million of quota, band slices, and commission in integer cents.
- **Findings** — typed control results (breaches, warnings, notes).

### Rules

| Rule | Behavior |
|---|---|
| Plan versions | Effective-dated (`effective_from` inclusive, `effective_to` exclusive). Each transaction is credited under the version in force on its date; a transaction outside every version is a `TXN-UNASSIGNED` breach, never silently skipped. |
| Accelerator bands | `marginal` (tax-bracket style: each band's slice at its own rate) or `cliff` (all revenue at the landing band's rate). Band upper bounds are exclusive. |
| Credit collisions | Resolved by explicit `priority` per role (lowest number wins). An exact tie at the winning priority drops that role's credit entirely and raises a `CREDIT-COLLISION` breach — input order never decides. |
| Role splits | Winning credits split the transaction by the version's role weights (basis points). Shares use the **largest-remainder rule** so split cents always sum exactly to the transaction; remainder ties break in canonical (rep, role) order. |
| Windfall cap | Optional `windfall_cap_ppm` caps the payout basis (revenue counted for commission) and the rate-selection attainment; exceeding it adds an info finding. |
| Returns / clawbacks | Returns carry `original_transaction_id` and reverse the original's winning credits in the **original's plan version**. Originals are never mutated; a return of a paid sale raises a `CLAWBACK` breach (signoff required). |
| Money | Integer cents (i128) end to end. Per-slice rounding is integer half-up, summed — no floats anywhere. |
| Purity | No clock, filesystem, or network access in the engine; time is caller input; output ordering is canonical regardless of input order. |

### Evidence packs

`compute` emits an evidence document: a spine `EvidencePack` with SHA-256
provenance hashes over the exact plan/transaction bytes, the findings, and a
body-hash seal; plus the product-side lock state (`draft` →
`awaiting_signoff` → `signed`).

`verify` recomputes the engine from the presented bytes, requires the re-run
to reproduce the pack's findings exactly, then runs the spine gate: version
identity, seal integrity, provenance hashes, and subject-scoped signoffs.
Breach findings resolve only through an approving signoff receipt that names
the finding's subject; the producing engine cannot countersign its own pack.
Signed packs are immutable — a correction is a new pack computed on
corrected inputs that records its predecessor's lineage.

## CLI

```text
commission-spine compute  --plan plan.json --transactions txns.json [--out pack.json] [--engine-id <id>]
commission-spine verify   --pack pack.json --plan plan.json --transactions txns.json
commission-spine explain  --plan plan.json --transactions txns.json [--rep <id>]
commission-spine sign     --pack pack.json --actor <name> --role <role> --subject <finding-subject> [--decision approve|reject] --at <iso-8601>
commission-spine seal     --pack pack.json
```

`compute` writes the evidence document (JSON); `verify` exits 0 only when
the pack proves itself and prints `verify REFUSED: <reason>` otherwise;
`explain` renders the deterministic calculation in human-readable form
(version headers, per-rep band slices, credit lines, findings); `sign`
appends a human receipt and `seal` advances the lock — `seal` refuses while
any breach finding is unresolved.

## Configuration (seed data)

The `examples/` directory holds a **seed** plan and transactions file for
exercising the CLI. Rate tables, quotas, caps, and role weights here are
illustrative starting points — every deployment must load its own approved
plan config. Nothing in this crate is an authoritative compensation source
or a compliance certification; it computes what the config says,
deterministically, and shows its work.

```bash
cargo run -p commission-spine -- compute --plan examples/plan.seed.json --transactions examples/transactions.seed.json
```

## Tests

`cargo test -p commission-spine` covers every rule branch and boundary named
in the spec's Sales block: marginal vs cliff modes, band boundaries
(exclusive bounds on both sides), largest-remainder split rounding summing
exactly, collision resolution by priority and tie-dropping (order
independence), windfall cap application and its exact boundary, clawback
linkage to the original's plan version, effective-dated plan assignment
including version boundaries, spread-cap propagation to every band, and the
fail-closed paths — unassigned transactions, unknown signoff subjects,
engine self-approval, lock refusals, and tampered evidence packs (findings,
signoffs, inputs, and engine id each break the seal or a hash).
