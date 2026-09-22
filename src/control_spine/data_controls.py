"""Data-evidence helpers for datasets feeding governed control packs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Sequence

from . import Finding, seal


@dataclass(frozen=True)
class DataEvidence:
    dataset: str
    schema_version: str
    source_system: str
    source_extract_hash: str
    row_count: int
    quality_findings: Sequence[Finding] = ()
    owner_signoff: str = ""
    prepared_by: str = "data-pipeline"

    def as_pack(self, *, control_id: str = "DATA-QUALITY-01", threshold: str = "schema and source checks pass") -> dict[str, Any]:
        return {
            "control_id": control_id,
            "control_objective": "govern source data used by downstream analytics",
            "threshold": threshold,
            "population_count": self.row_count,
            "dataset": self.dataset,
            "schema_version": self.schema_version,
            "source_system": self.source_system,
            "source_extract_hash": self.source_extract_hash,
            "owner_signoff": self.owner_signoff,
            "prepared_by": self.prepared_by,
            "quality_findings": [finding.to_dict() for finding in self.quality_findings],
        }


def seal_data_evidence(evidence: DataEvidence, *, engine_version: str = "0.1.0") -> dict[str, Any]:
    return seal(
        evidence.as_pack(),
        engine_id="data-quality-engine",
        engine_version=engine_version,
        inputs={
            "dataset": evidence.dataset,
            "schema_version": evidence.schema_version,
            "source_extract_hash": evidence.source_extract_hash,
            "row_count": evidence.row_count,
        },
        foundation=(
            "The source extract hash identifies the data population used.",
            "The schema version identifies the expected field contract.",
            "Quality findings are complete for the declared controls.",
        ),
        blocking_findings=evidence.quality_findings,
    )


@dataclass(frozen=True)
class DataIncident:
    incident_id: str
    dataset: str
    code: str
    severity: str
    message: str
    status: str = "OPEN"
    owner: str = ""
    resolution: str = ""
    resolved_at: str = ""

    def acknowledge(self, owner: str) -> "DataIncident":
        if self.status != "OPEN" or not owner.strip():
            raise ValueError("An OPEN incident requires a named owner.")
        return replace(self, status="ACKNOWLEDGED", owner=owner)

    def remediate(self, resolution: str) -> "DataIncident":
        if self.status not in {"OPEN", "ACKNOWLEDGED"} or not resolution.strip():
            raise ValueError("An open incident requires a non-empty resolution.")
        return replace(self, status="REMEDIATED", resolution=resolution)

    def verify(self) -> "DataIncident":
        if self.status != "REMEDIATED":
            raise ValueError("Only REMEDIATED incidents can be verified.")
        return replace(self, status="VERIFIED", resolved_at=datetime.now(timezone.utc).isoformat())
