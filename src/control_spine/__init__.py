"""CHP-aligned ICFR compliance spine.

Numbers stay in the domain engines. This module is the gate that decides
whether a pack is evidence.

Lock progression matches Consensus Hardening Protocol session status:
EXPLORING → ADVISORY → PROVISIONAL_LOCK → LOCKED, or HALT.

An engine cannot countersign its own output. Open blocking findings cannot
reach LOCKED. Empty population cannot pass R0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Mapping, Sequence


SPINE_VERSION = "0.1.0"
CHP_ALIGNMENT = "consensus-hardening-protocol session status + R0 gate + human lock"


class LockState(str, Enum):
    EXPLORING = "EXPLORING"
    ADVISORY = "ADVISORY"
    PROVISIONAL_LOCK = "PROVISIONAL_LOCK"
    LOCKED = "LOCKED"
    HALT = "HALT"


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    FATAL = "FATAL"


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "blocking": self.blocking}


def canonical_hash(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(blob.encode("utf-8")).hexdigest()


def evaluate_r0(
    *,
    population_count: int,
    control_id: str,
    threshold: str,
    engine_id: str,
    inputs_hash: str,
    owner_signoff: str,
    prepared_by: str,
) -> dict[str, str]:
    """CHP R0: solvable, scoped, valid, worth_it — plus a human gate."""
    return {
        "Solvable": Verdict.PASS.value if population_count > 0 else Verdict.FATAL.value,
        "Scoped": Verdict.PASS.value if control_id and threshold else Verdict.FATAL.value,
        "Valid": Verdict.PASS.value if engine_id and inputs_hash else Verdict.FATAL.value,
        "Worth_it": Verdict.PASS.value if control_id.startswith("ICFR-") else Verdict.FATAL.value,
        "Human_gate": (
            Verdict.PASS.value
            if owner_signoff and owner_signoff.strip() != prepared_by.strip()
            else Verdict.FATAL.value
        ),
    }


def _adversary(
    *,
    population_count: int,
    owner_signoff: str,
    prepared_by: str,
    blocking: Sequence[Finding],
    foundation: Sequence[str],
) -> list[dict[str, str]]:
    challenges = [
        {
            "id": "COMPLETENESS",
            "attack": "The population is empty, so a clean pack is indistinguishable from a missed control.",
            "verdict": Verdict.PASS.value if population_count > 0 else Verdict.FAIL.value,
        },
        {
            "id": "HUMAN_OWNER",
            "attack": "The engine countersigned its own output.",
            "verdict": (
                Verdict.PASS.value
                if owner_signoff and owner_signoff.strip() != prepared_by.strip()
                else Verdict.FAIL.value
            ),
        },
        {
            "id": "OPEN_EXCEPTIONS",
            "attack": "Blocking findings remain; LOCKED would assert a control that did not operate.",
            "verdict": Verdict.PASS.value if not any(f.blocking for f in blocking) else Verdict.FAIL.value,
        },
        {
            "id": "FOUNDATION",
            "attack": "Assumptions were not committed before the numbers were shown.",
            "verdict": Verdict.PASS.value if foundation else Verdict.FAIL.value,
        },
    ]
    return challenges


def lock_state(r0: Mapping[str, str], challenges: Sequence[Mapping[str, str]], owner: str) -> LockState:
    if any(v == Verdict.FATAL.value for k, v in r0.items() if k != "Human_gate"):
        return LockState.HALT
    blocking_fail = any(c["verdict"] != Verdict.PASS.value for c in challenges if c["id"] != "HUMAN_OWNER")
    human_ok = r0.get("Human_gate") == Verdict.PASS.value
    exceptions_clear = all(c["verdict"] == Verdict.PASS.value for c in challenges if c["id"] == "OPEN_EXCEPTIONS")

    if blocking_fail and not human_ok:
        return LockState.EXPLORING
    if blocking_fail and human_ok:
        return LockState.PROVISIONAL_LOCK
    if not human_ok:
        return LockState.EXPLORING
    if exceptions_clear and human_ok and all(v == Verdict.PASS.value for v in r0.values()):
        return LockState.LOCKED
    return LockState.ADVISORY


def seal(
    pack: dict[str, Any],
    *,
    engine_id: str,
    engine_version: str,
    inputs: Any,
    foundation: Sequence[str],
    blocking_findings: Sequence[Finding] = (),
) -> dict[str, Any]:
    """Wrap a domain pack in the compliance spine. Mutates a copy, not the input."""
    sealed = dict(pack)
    owner = str(sealed.get("owner_signoff") or "")
    prepared_by = str(sealed.get("prepared_by") or engine_id)
    population = int(sealed.get("population_count") or 0)
    control_id = str(sealed.get("control_id") or "")
    threshold = str(sealed.get("threshold") or "")
    inputs_hash = canonical_hash(inputs)
    findings = tuple(blocking_findings)
    r0 = evaluate_r0(
        population_count=population,
        control_id=control_id,
        threshold=threshold,
        engine_id=engine_id,
        inputs_hash=inputs_hash,
        owner_signoff=owner,
        prepared_by=prepared_by,
    )
    challenges = _adversary(
        population_count=population,
        owner_signoff=owner,
        prepared_by=prepared_by,
        blocking=findings,
        foundation=foundation,
    )
    state = lock_state(r0, challenges, owner)
    body = {
        "spine_version": SPINE_VERSION,
        "chp_alignment": CHP_ALIGNMENT,
        "engine_id": engine_id,
        "engine_version": engine_version,
        "inputs_hash": inputs_hash,
        "foundation": list(foundation),
        "r0": r0,
        "adversary": challenges,
        "blocking_findings": [f.to_dict() for f in findings],
        "lock_state": state.value,
        "owner_signoff": owner,
        "prepared_by": prepared_by,
        "is_evidence": state is LockState.LOCKED,
    }
    body["envelope_hash"] = canonical_hash({k: v for k, v in body.items() if k != "envelope_hash"})
    sealed["spine"] = body
    sealed["lock_state"] = state.value
    sealed["is_evidence"] = body["is_evidence"]
    sealed["sealed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return sealed


def render_spine(pack: Mapping[str, Any]) -> list[str]:
    spine = pack.get("spine") or {}
    lock = pack.get("lock_state") or spine.get("lock_state") or "EXPLORING"
    evidence = "EVIDENCE" if pack.get("is_evidence") else "NOT EVIDENCE"
    lines = [
        f"**Spine:** control-spine {spine.get('spine_version', SPINE_VERSION)} · CHP-aligned",
        f"**Lock:** `{lock}` · **{evidence}**",
        f"**Inputs hash:** `{spine.get('inputs_hash', '')}`",
        f"**Envelope hash:** `{spine.get('envelope_hash', '')}`",
        "",
        "### R0 gate",
        "",
    ]
    for key, val in (spine.get("r0") or {}).items():
        lines.append(f"- {key}: **{val}**")
    lines += ["", "### Adversary", ""]
    for c in spine.get("adversary") or []:
        lines.append(f"- `{c['id']}` **{c['verdict']}** — {c['attack']}")
    if spine.get("foundation"):
        lines += ["", "### Foundation (committed before measurement)", ""]
        for item in spine["foundation"]:
            lines.append(f"- {item}")
    lines.append("")
    return lines


def exit_code(pack: Mapping[str, Any]) -> int:
    state = pack.get("lock_state")
    if state == LockState.LOCKED.value:
        return 0
    if state == LockState.EXPLORING.value:
        return 0
    return 2
