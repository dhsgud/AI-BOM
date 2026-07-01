"""Tests for Stage 5 (CycloneDX ML-BOM serialization)."""

from pathlib import Path

import pytest

from aibom.models import Finding, Severity, StageResult

pytest.importorskip("cyclonedx", reason="cyclonedx-python-lib not installed")
from aibom.stages import stage5_report as s5  # noqa: E402


def _prior(*findings: Finding) -> list[StageResult]:
    return [StageResult(stage="stage1", findings=list(findings),
                        bom_fragment={"source": "c4nary", "sha256": "deadbeef"})]


def _crit() -> Finding:
    return Finding(stage="stage1", severity=Severity.CRITICAL, rule_id="c4nary:TPL021",
                   message="Content-gated instruction injection", evidence={"loc": "L1"})


def test_valid_cyclonedx_ml_bom():
    bom = s5.build_bom(Path("m.gguf"), _prior(_crit()))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["type"] == "machine-learning-model"
    assert bom["metadata"]["component"]["name"] == "m.gguf"


def test_verdict_property_block():
    bom = s5.build_bom(Path("m.gguf"), _prior(_crit()))
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["aibom:verdict"] == "BLOCK"


def test_finding_becomes_vulnerability():
    bom = s5.build_bom(Path("m.gguf"), _prior(_crit()))
    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    assert "c4nary:TPL021" in vulns
    assert vulns["c4nary:TPL021"]["ratings"][0]["severity"] == "critical"
    assert vulns["c4nary:TPL021"]["affects"][0]["ref"] == "model"


def test_model_hash_property_surfaced():
    bom = s5.build_bom(Path("m.gguf"), _prior(_crit()))
    props = {p["name"]: p["value"] for p in bom["metadata"]["component"]["properties"]}
    assert props["aibom:sha256"] == "deadbeef"


def test_clean_bom_has_no_vulnerabilities():
    bom = s5.build_bom(Path("clean.gguf"), _prior())  # no findings
    assert bom.get("vulnerabilities", []) == []
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["aibom:verdict"] == "SAFE"


def test_deterministic_output():
    prior = _prior(_crit())
    assert s5.build_bom(Path("m.gguf"), prior) == s5.build_bom(Path("m.gguf"), prior)
