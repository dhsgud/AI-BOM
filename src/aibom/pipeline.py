"""Stage orchestrator.

Runs the enabled stages in order, accumulates `StageResult`s, and produces a
final `ScanReport`. Stage implementations live in `aibom.stages` and are
currently stubs — see docs/DEVELOPMENT_PLAN.md for the milestone order.
"""

from __future__ import annotations

from pathlib import Path

from . import verdict as verdict_mod
from .models import ScanReport, StageResult
from .stages import (
    stage1_c4nary,
    stage2_format,
    stage3_sandbox,
    stage4_behavioral,
    stage5_report,
)

# Ordered stage registry. `key` is used by the CLI `--until` option.
STAGES = [
    ("stage1", stage1_c4nary.run),
    ("stage2", stage2_format.run),
    ("stage3", stage3_sandbox.run),
    ("stage4", stage4_behavioral.run),  # optional; gated by run_behavioral
]


def scan(
    artifact: Path,
    until: str = "stage5",
    run_behavioral: bool = False,
) -> ScanReport:
    """Run the pipeline against a model artifact and return a ScanReport."""
    results: list[StageResult] = []

    for key, run in STAGES:
        if key == "stage4" and not run_behavioral:
            continue
        results.append(run(artifact))
        if key == until:
            break

    # Stage 5 always runs last: it serializes accumulated findings into a BOM.
    bom_result = stage5_report.run(artifact, results)
    results.append(bom_result)

    return ScanReport(
        artifact=str(artifact),
        verdict=verdict_mod.aggregate(results),
        stage_results=results,
        bom=bom_result.bom_fragment,
    )
