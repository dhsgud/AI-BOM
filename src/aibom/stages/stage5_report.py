"""Stage 5 — AI-BOM Report: serialize findings into a CycloneDX ML-BOM.

Aggregates all prior-stage findings + artifact metadata into a CycloneDX 1.6
ML-BOM (JSON) via cyclonedx-python-lib. The scanned model is the metadata
component (type machine-learning-model); each finding becomes a Vulnerability
whose rating severity maps from the AI-BOM Severity and which `affects` the
model. The overall SAFE/WARNING/BLOCK verdict is attached as a metadata
property.

Unlike other stages, `run()` receives the accumulated prior results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, StageResult
from ..verdict import aggregate

STAGE = "stage5"

# AI-BOM Severity -> CycloneDX vulnerability severity (names align 1:1).
_CDX_SEVERITY = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


def _model_hashes(prior: list[StageResult]) -> dict[str, str]:
    """Pull artifact hashes surfaced by earlier stages (e.g. Stage 1's c4nary)."""
    out: dict[str, str] = {}
    for r in prior:
        frag = r.bom_fragment or {}
        for key in ("sha256", "template_sha256"):
            val = frag.get(key)
            if isinstance(val, str):
                out[key] = val
    return out


def build_bom(artifact: Path, prior: list[StageResult]) -> dict[str, Any]:
    """Build a CycloneDX 1.6 ML-BOM dict from accumulated findings."""
    from cyclonedx.model import Property
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.bom_ref import BomRef
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.vulnerability import (
        BomTarget,
        Vulnerability,
        VulnerabilityRating,
        VulnerabilitySeverity,
        VulnerabilitySource,
    )
    from cyclonedx.output import make_outputter
    from cyclonedx.schema import OutputFormat, SchemaVersion

    verdict = aggregate(prior)
    findings: list[Finding] = [f for r in prior for f in r.findings]

    model_ref = "model"
    hashes = _model_hashes(prior)
    component = Component(
        name=artifact.name,
        type=ComponentType.MACHINE_LEARNING_MODEL,
        bom_ref=BomRef(model_ref),
        properties=[Property(name=f"aibom:{k}", value=v) for k, v in sorted(hashes.items())],
    )

    bom = Bom()
    bom.metadata.component = component
    bom.metadata.properties.add(Property(name="aibom:verdict", value=verdict.value))
    # Determinism: drop the auto-generated uuid/timestamp so identical inputs
    # produce identical BOMs (mirrors c4nary's deterministic-output invariant).
    bom.serial_number = None  # type: ignore[assignment]
    bom.metadata.timestamp = None  # type: ignore[assignment]

    source = VulnerabilitySource(name="AI-BOM")
    for i, f in enumerate(findings):
        severity = VulnerabilitySeverity[_CDX_SEVERITY[f.severity]]
        bom.vulnerabilities.add(
            Vulnerability(
                bom_ref=BomRef(f"finding-{i}"),
                id=f.rule_id,
                source=source,
                description=f.message,
                detail=json.dumps(f.evidence, ensure_ascii=True, sort_keys=True) or None,
                ratings=[VulnerabilityRating(source=source, severity=severity)],
                affects=[BomTarget(ref=model_ref)],  # references component bom-ref
                properties=[Property(name="aibom:stage", value=f.stage)],
            )
        )

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    bom_dict: dict[str, Any] = json.loads(outputter.output_as_string())
    return bom_dict


def run(artifact: Path, prior: list[StageResult]) -> StageResult:
    return StageResult(stage=STAGE, ok=True, bom_fragment=build_bom(artifact, prior))
