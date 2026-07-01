"""Shared data models passed between pipeline stages.

These schemas are the contract between stages: every stage consumes an artifact
reference and produces a `StageResult`. See docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    BLOCK = "BLOCK"


class Finding(BaseModel):
    """A single detection emitted by a stage."""

    stage: str
    severity: Severity
    rule_id: str
    message: str
    evidence: dict = Field(default_factory=dict)


class StageResult(BaseModel):
    """Outcome of running one stage.

    `ok` reflects whether the stage *ran* successfully, not whether it found
    something. A stage that is skipped (e.g. Docker unavailable) sets ok=False
    and should emit a WARNING-level finding explaining why.
    """

    stage: str
    ok: bool = True
    skipped: bool = False
    findings: list[Finding] = Field(default_factory=list)
    bom_fragment: dict | None = None


class ScanReport(BaseModel):
    """Aggregate result for a full pipeline run."""

    artifact: str
    verdict: Verdict
    stage_results: list[StageResult] = Field(default_factory=list)
    bom: dict | None = None
