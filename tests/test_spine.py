from control_spine import Finding, LockState, exit_code, seal


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
