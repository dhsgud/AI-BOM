"""Stage 3 — Docker Sandbox: isolated load test with strace monitoring.

Loads (does NOT infer) the model inside a locked-down container:
`--network none`, `--read-only`, `--cap-drop ALL`, a custom seccomp profile,
and memory/CPU limits. strace watches for unexpected filesystem writes,
network attempts, and process spawns. Gracefully skips (WARNING) when Docker
is unavailable.

TODO(M4): build the minimal image, wire up docker SDK + seccomp profile + strace
log parsing.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity, StageResult

STAGE = "stage3"


def run(artifact: Path) -> StageResult:
    # Stub: report as skipped so the verdict reflects incomplete coverage.
    return StageResult(
        stage=STAGE,
        ok=True,
        skipped=True,
        findings=[
            Finding(
                stage=STAGE,
                severity=Severity.INFO,
                rule_id="stage3.not-implemented",
                message="Docker sandbox stage is not yet implemented.",
            )
        ],
    )
