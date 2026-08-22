# control-spine

> **Cubiczan stack** — [CHP](https://github.com/Cubiczan/consensus-hardening-protocol) · **You are here:** `control-spine`

**The ICFR compliance spine under the six control-gap engines.** Domain engines compute. This package decides whether the output is evidence.

A material weakness is rarely a knowledge problem. It is a capacity-and-proof problem. Automation that produces an answer without a reviewable trail adds a new untestable control. The spine is the trail.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/consensus-hardening-protocol)](https://pypi.org/project/consensus-hardening-protocol/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## CHP dependency

Depends on the published package **[`consensus-hardening-protocol`](https://pypi.org/project/consensus-hardening-protocol/)** (`>=0.1.0`). R0 Solvable/Scoped/Valid/Worth_it come from `chp.evaluate_r0_gate`; ICFR human gate, adversary challenges, lock progression, and evidence sealing stay in this repo.

See also the promoted example: [icohangar-ops/chp-examples](https://github.com/icohangar-ops/chp-examples) → `python/control-spine-icfr`.

## What it enforces

| Gate | Rule |
|---|---|
| **R0** | Solvable (population > 0), scoped (control id + threshold), valid (engine id + inputs hash), worth_it (ICFR control), human gate (named owner ≠ engine) |
| **Adversary** | Completeness, human owner, open exceptions, foundation committed before measurement |
| **Lock** | `EXPLORING` → `ADVISORY` / `PROVISIONAL_LOCK` → `LOCKED`, or `HALT` |
| **Human** | An engine cannot countersign its own pack. `LOCKED` is the only state that is evidence. |
| **Seal** | SHA-256 of canonical inputs + envelope hash of the spine body |

Aligned to CHP session status and R0 via the published engine, not a full reimplementation of the protocol. Deterministic. No model in the gate.

UiPath handoffs can enter here as evidence packs before they are allowed to become LOCKED.

## Engines on this spine

`lease842` · `cuec-review` · `nexus-monitor` · `sbc-ledger` · `poc-revenue` · `combination-accounting`

The spine source of truth lives here. A vendored copy ships inside each engine so a prospect can open one repo and still see the gate.

## Quick start

```bash
pip install consensus-hardening-protocol
pip install -e ".[dev]"
pytest -q
```

Unsigned pack → `EXPLORING`, not evidence. Named controller + clear findings → `LOCKED`. Blocking findings + owner → `PROVISIONAL_LOCK`. Empty population → `HALT`.
