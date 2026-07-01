"""Unit tests for verdict aggregation."""

from aibom.models import Finding, Severity, StageResult
from aibom.verdict import aggregate


def _result(stage: str, *severities: Severity, skipped: bool = False) -> StageResult:
    findings = [
        Finding(stage=stage, severity=s, rule_id=f"{stage}.r{i}", message="x")
        for i, s in enumerate(severities)
    ]
    return StageResult(stage=stage, findings=findings, skipped=skipped)


def test_safe_when_no_findings():
    assert aggregate([_result("stage1"), _result("stage2")]).value == "SAFE"


def test_block_on_high_or_critical():
    assert aggregate([_result("stage2", Severity.HIGH)]).value == "BLOCK"
    assert aggregate([_result("stage2", Severity.CRITICAL)]).value == "BLOCK"


def test_warning_on_medium_low():
    assert aggregate([_result("stage2", Severity.MEDIUM)]).value == "WARNING"
    assert aggregate([_result("stage2", Severity.LOW)]).value == "WARNING"


def test_warning_when_stage_skipped():
    assert aggregate([_result("stage3", skipped=True)]).value == "WARNING"


def test_block_takes_precedence():
    results = [_result("stage2", Severity.LOW), _result("stage3", Severity.CRITICAL)]
    assert aggregate(results).value == "BLOCK"
