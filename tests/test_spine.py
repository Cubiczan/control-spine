from control_spine import Finding, LockState, exit_code, seal
from control_spine import Verdict
from control_spine.data_controls import DataEvidence, DataIncident, seal_data_evidence


FOUNDATION = ("IBR is an input.", "Bright lines are config.")


def _pack(**kwargs):
    base = {
        "control_id": "ICFR-LEASE-842-01",
        "control_objective": "measure leases",
        "period": "H1 2026",
        "population_count": 1,
        "threshold": "100% of leases",
        "prepared_by": "lease842-engine",
        "owner_signoff": "",
        "conclusion": "ok",
    }
    base.update(kwargs)
    return base


def test_unsigned_pack_is_exploring_not_evidence() -> None:
    sealed = seal(
        _pack(),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
    )
    assert sealed["lock_state"] == LockState.EXPLORING.value
    assert sealed["is_evidence"] is False
    assert sealed["spine"]["r0"]["Human_gate"] == "FATAL"


def test_signed_clean_pack_locks() -> None:
    sealed = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
    )
    assert sealed["lock_state"] == LockState.LOCKED.value
    assert sealed["is_evidence"] is True
    assert sealed["spine"]["envelope_hash"]
    assert sealed["spine"]["inputs_hash"]


def test_engine_cannot_countersign_itself() -> None:
    sealed = seal(
        _pack(owner_signoff="lease842-engine"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
    )
    assert sealed["lock_state"] != LockState.LOCKED.value
    assert sealed["is_evidence"] is False


def test_blocking_finding_caps_at_provisional() -> None:
    sealed = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
        blocking_findings=(Finding("CUEC-GAP", "evidence missing"),),
    )
    assert sealed["lock_state"] == LockState.PROVISIONAL_LOCK.value
    assert sealed["is_evidence"] is False


def test_empty_population_halts() -> None:
    sealed = seal(
        _pack(population_count=0, owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": []},
        foundation=FOUNDATION,
    )
    assert sealed["lock_state"] == LockState.HALT.value


def test_same_inputs_same_hash() -> None:
    a = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": ["HQ-3YR"]},
        foundation=FOUNDATION,
    )
    b = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": ["HQ-3YR"]},
        foundation=FOUNDATION,
    )
    assert a["spine"]["inputs_hash"] == b["spine"]["inputs_hash"]


def test_exit_code_exploring_and_locked_are_zero() -> None:
    exploring = seal(
        _pack(),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
    )
    locked = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
    )
    halt = seal(
        _pack(population_count=0, owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": []},
        foundation=FOUNDATION,
    )
    provisional = seal(
        _pack(owner_signoff="Controller"),
        engine_id="lease842-engine",
        engine_version="0.1.0",
        inputs={"leases": 1},
        foundation=FOUNDATION,
        blocking_findings=(Finding("CUEC-GAP", "evidence missing"),),
    )
    assert exit_code(exploring) == 0
    assert exit_code(locked) == 0
    assert exit_code(halt) == 2
    assert exit_code(provisional) == 2


def test_data_evidence_can_lock_with_named_owner() -> None:
    sealed = seal_data_evidence(DataEvidence(
        dataset="spend",
        schema_version="v1",
        source_system="erp",
        source_extract_hash="abc123",
        row_count=10,
        owner_signoff="Controller",
    ))
    assert sealed["lock_state"] == LockState.LOCKED.value
    assert sealed["is_evidence"] is True
    assert sealed["spine"]["r0"]["Worth_it"] == Verdict.PASS.value


def test_data_incident_requires_verify_after_remediation() -> None:
    incident = DataIncident("INC-1", "spend", "SCHEMA_DRIFT", "HIGH", "field removed")
    incident = incident.acknowledge("Data Owner")
    incident = incident.remediate("Restored compatible schema.")
    assert incident.verify().status == "VERIFIED"
