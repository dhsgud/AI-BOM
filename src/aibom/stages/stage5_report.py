"""Stage 5 — AI-BOM Report: serialize findings into a CycloneDX ML-BOM.

Aggregates all prior stage findings + artifact metadata into a CycloneDX
ML-BOM (JSON). Extends the c4nary report format with components, evidence, and
the final verdict. Unlike other stages, `run()` receives the accumulated
results.

TODO(M1): emit a real CycloneDX ML-BOM via cyclonedx-python-lib.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage5"


def run(artifact: Path, prior: list[StageResult]) -> StageResult:
    # Minimal placeholder BOM until cyclonedx-python-lib integration (M1).
    findings = [f.model_dump() for r in prior for f in r.findings]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "machine-learning-model", "name": artifact.name}},
        "components": [],
        "aibom:findings": findings,
    }
    return StageResult(stage=STAGE, ok=True, bom_fragment=bom)
