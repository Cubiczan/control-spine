# access-recert-spine — quarterly access recertification (IT/IAM)

One of the department control spines: a deterministic engine, an evidence
pack with provenance hashes and human signoff, and fail-closed
verification. The engine detects entitlements that must not exist and
emits revocation queues with receipts. It decides nothing about people —
it computes findings, and humans close the loop.

Depends on the canonical governance crate `crates/spine` by path (never
vendored). Same family contract as every product crate: pure engine, no
clock reads (all dates are caller input), no filesystem or network in the
engine, deterministic sorted findings, and evidence packs that refuse to
verify on any doubt.

## Design intent

Quarterly access recertification is a set problem: for each entitlement
under review, either the entitlement must not exist (leaver access,
unmanaged systems, abandoned credentials) or its retention must be
explicitly approved (privileged access). The engine evaluates six rules
over the campaign population and emits typed findings; revocation queues
and signoff receipts make the human decision evidence.

Identity matching is by `employee_id` only. Emails are carried as
display data and are **never** used to attribute entitlements — mailboxes
are recycled, and a separated employee's address on a new hire's grant is
the classic misattribution hazard. An entitlement that cannot be matched
to an HR identity by `employee_id` is quarantined (fail-closed): it is
never silently dropped and never attributed by email.

## Rule set

| Rule | Severity | Fires when |
| --- | --- | --- |
| `leaver-active-entitlement` | breach | The identity's separation date is strictly before the campaign date and the identity retains the entitlement. |
| `orphan-system` | breach | The entitlement's owning system has no managed-system record. |
| `orphan-manager` | warn | The identity's manager of record is absent or does not resolve to an HR identity (new-hire grace exempt). |
| `stale-auth` | warn | No successful authentication within `stale_days` (strictly older fires; never-authenticated is always stale; new-hire grace exempt). |
| `privileged-four-eyes` | warn | A privileged entitlement is retained with fewer than two distinct approving signers. |
| `quarantine` | warn | The entitlement's `employee_id` does not resolve to an HR identity. |

Boundaries, pinned by tests:

- Separation **on** the campaign date has not taken effect yet — not a
  leaver. Strictly before fires.
- The new-hire grace window is inclusive: an identity hired exactly
  `new_hire_grace_days` before the campaign is exempt; one day more is
  not. Grace exempts only `stale-auth` and `orphan-manager` — never the
  leaver, orphan-system, or quarantine rules.
- An authentication exactly `stale_days` old is inside the window; one
  day older fires.
- Rules compose: one entitlement can carry several findings. Findings are
  sorted by (subject, rule_id) so identical inputs produce identical
  packs.
- Four-eyes counting is case-insensitive and deduplicates; reject
  decisions do not count; the producing engine's own approvals are void
  (separation of duties).

## Evidence packs and the lock lifecycle

`compute` emits a pack document: the spine `EvidencePack` (engine and
spine versions, SHA-256 `inputs_hash`/`params_hash` over the exact file
bytes, findings, signoffs) plus the product lock state. The lock
lifecycle follows the family crosswalk: `draft` → `awaiting_signoff` →
`signed` (≡ `LOCKED`, the only evidence-qualifying state). A pack with
unresolved gated findings parks at `awaiting_signoff`; when every gated
finding carries a subject-scoped approving receipt, the pack seals at
`Signed` (body hash over the canonical pack body — the Seal gate applies
to the Rust family with no exemption). Signed packs are immutable;
corrections are new packs computed on corrected inputs.

Retention approvals supplied at compute time are the pack's signoff
receipts: an approval for an entitlement's subject resolves gated
findings on that subject (spine-enforced; product CLIs do not re-implement
subject matching).

`verify` fails closed through three gates: lock state (`Signed` only),
the spine contract (seal, provenance hashes, signoffs), and a full
recomputation of the findings from the supplied inputs — a re-sealed but
non-reproducing pack is still refused.

## CLI

```text
access-recert-spine compute  --inputs <campaign.json> --config <config.json> [--signoffs <receipts.json>] [--out <pack.json>]
access-recert-spine verify   --pack <pack.json> --inputs <campaign.json> --config <config.json>
access-recert-spine explain  --pack <pack.json>
```

Exit codes: `0` success, `1` verification failure (fail-closed), `2`
usage/schema errors. `explain` is informational and prints the revocation,
quarantine, signoff-required, and review queues, the recorded receipts,
and the rule catalog.

## Config tables

`RecertConfig` (`stale_days`, `new_hire_grace_days`) is **seed data**, not
a regulatory or benchmark-derived recommendation. Inputs and config are
schema-checked (`deny_unknown_fields`): schema drift fails loudly.

## Honest claims

This crate ships deterministic arithmetic and an audit trail, not
assurance. There are no benchmarks here, no compliance certifications,
and no claim that a signed pack proves production access is correct —
only that the findings reproduce from the inputs and that named humans
approved the gated ones. The engine consumes typed entitlement records;
document/telemetry extraction is out of scope. No money arithmetic occurs
in this domain, so the integer-cents family rule has no application here.
