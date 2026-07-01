"""Stage 1 — c4nary scan: GGUF static analysis via the c4nary auditor.

Integrates the external, GGUF-only c4nary tool (https://github.com/paraxaQQ/canary,
MIT) via its Python API rather than reimplementing a GGUF parser. c4nary runs
template (TPL: SSTI + behavioral-backdoor), metadata (MET), tokenizer (TOK),
structure (STR), and integrity (INT) rules — never rendering the template or
executing the model.

Non-GGUF artifacts (pickle/safetensors) are out of c4nary's scope and pass
through to Stage 2. c4nary findings (FAIL/WARN/INFO) map to AI-BOM Severity per
``map_severity`` below; rule ids are preserved as ``c4nary:<RULE_ID>``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..models import Finding, Severity, StageResult

STAGE = "stage1"

# GGUF files begin with the ASCII magic "GGUF" (little-endian u32 0x46554747).
_GGUF_MAGIC = b"GGUF"

# c4nary FAIL findings that represent code execution (SSTI) or instruction
# injection — escalated to CRITICAL. Other FAILs (structural impossibilities,
# tampering, tokenizer/metadata desync) stay HIGH. See c4nary rules/registry.py.
CRITICAL_RULE_IDS: frozenset[str] = frozenset(
    {
        "TPL001",  # dunder attribute access (SSTI)
        "TPL002",  # SSTI gadget identifier
        "TPL003",  # dangerous callable / module name
        "TPL004",  # abusable attribute filter
        "TPL005",  # reconstructed dangerous token
        "TPL021",  # content-gated instruction injection
    }
)

# c4nary severity string -> AI-BOM Severity (before CRITICAL escalation).
_BASE_SEVERITY = {
    "FAIL": Severity.HIGH,
    "WARN": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


class _C4naryFinding(Protocol):
    """Structural type of a c4nary report.Finding (avoids importing at module load)."""

    rule_id: str
    severity: str
    title: str
    detail: str
    location: str | None


def map_severity(c4nary_severity: str, rule_id: str) -> Severity:
    """Map a c4nary severity + rule id to an AI-BOM Severity."""
    if c4nary_severity == "FAIL" and rule_id in CRITICAL_RULE_IDS:
        return Severity.CRITICAL
    return _BASE_SEVERITY.get(c4nary_severity, Severity.INFO)


def translate_finding(cf: _C4naryFinding) -> Finding:
    """Translate one c4nary Finding into an AI-BOM Finding, preserving the rule id."""
    return Finding(
        stage=STAGE,
        severity=map_severity(cf.severity, cf.rule_id),
        rule_id=f"c4nary:{cf.rule_id}",
        message=cf.title,
        evidence={
            "detail": cf.detail,
            "location": cf.location,
            "c4nary_severity": cf.severity,
        },
    )


def is_gguf(artifact: Path) -> bool:
    """True if the file starts with the GGUF magic. Cheap format router."""
    try:
        with artifact.open("rb") as fh:
            return fh.read(4) == _GGUF_MAGIC
    except OSError:
        return False


def run(artifact: Path) -> StageResult:
    """Scan a GGUF artifact with c4nary; pass non-GGUF through to Stage 2."""
    if not is_gguf(artifact):
        # Not GGUF: c4nary does not apply. Empty result routes to Stage 2.
        return StageResult(stage=STAGE, ok=True)

    try:
        from c4nary.integrity import model_template_sha256, sha256_file
        from c4nary.parser import GGUFParseError, parse_gguf
        from c4nary.rules.metadata import analyze_metadata
        from c4nary.rules.structure import analyze_structure
        from c4nary.rules.template import analyze_template
        from c4nary.rules.tokenizer import analyze_tokenizer
    except ImportError:
        # c4nary is a declared dependency; if missing, surface it rather than
        # silently passing a GGUF file as clean.
        return StageResult(
            stage=STAGE,
            ok=False,
            skipped=True,
            findings=[
                Finding(
                    stage=STAGE,
                    severity=Severity.MEDIUM,
                    rule_id="stage1.c4nary-unavailable",
                    message="c4nary is not installed; GGUF analysis was skipped.",
                    evidence={"hint": "pip install 'c4nary>=0.1,<0.2'"},
                )
            ],
        )

    try:
        model = parse_gguf(str(artifact))
    except GGUFParseError as exc:
        # Claims GGUF magic but does not parse: suspicious in its own right.
        return StageResult(
            stage=STAGE,
            ok=False,
            findings=[
                Finding(
                    stage=STAGE,
                    severity=Severity.HIGH,
                    rule_id="stage1.parse-error",
                    message="File has GGUF magic but failed to parse.",
                    evidence={"error": str(exc)},
                )
            ],
        )

    c4nary_findings = (
        analyze_template(model.chat_template)
        + analyze_metadata(model)
        + analyze_tokenizer(model)
        + analyze_structure(model)
    )
    findings = [translate_finding(cf) for cf in c4nary_findings]

    bom_fragment = {
        "source": "c4nary",
        "format": "gguf",
        "sha256": sha256_file(str(artifact)),
        "template_sha256": model_template_sha256(model),
    }
    return StageResult(stage=STAGE, ok=True, findings=findings, bom_fragment=bom_fragment)
