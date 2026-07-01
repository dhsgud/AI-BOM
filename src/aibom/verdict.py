"""Aggregate stage findings into a final SAFE / WARNING / BLOCK verdict."""

from __future__ import annotations

from .models import Finding, Severity, StageResult, Verdict

_BLOCK_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}
_WARN_SEVERITIES = {Severity.LOW, Severity.MEDIUM}


def aggregate(stage_results: list[StageResult]) -> Verdict:
    """Reduce all stage findings to a single verdict.

    Rules (see docs/ARCHITECTURE.md):
      - any HIGH/CRITICAL finding      -> BLOCK
      - any LOW/MEDIUM, or skipped stage -> WARNING
      - otherwise                      -> SAFE
    """
    findings: list[Finding] = [f for r in stage_results for f in r.findings]

    if any(f.severity in _BLOCK_SEVERITIES for f in findings):
        return Verdict.BLOCK
    if any(f.severity in _WARN_SEVERITIES for f in findings) or any(
        r.skipped for r in stage_results
    ):
        return Verdict.WARNING
    return Verdict.SAFE
