"""Stage 1 — c4nary scan: GGUF static analysis via the c4nary auditor.

Integrates the external, GGUF-only c4nary tool (https://github.com/paraxaQQ/canary,
MIT) rather than reimplementing a GGUF parser. c4nary runs template (TPL: SSTI +
behavioral-backdoor), metadata (MET), structure (STR), tokenizer (TOK), and
integrity (INT) rules — never rendering the template or executing the model.
Non-GGUF artifacts (pickle/safetensors) are out of c4nary's scope and pass
through to Stage 2.

Integration options (M3): c4nary Python API (parse_gguf + analyze_*), or the
`canary scan --json` CLI. c4nary findings (FAIL/WARN/INFO) map to AI-BOM
Severity per docs/DEVELOPMENT_PLAN.md §8.3; rule ids are preserved as
`c4nary:<RULE_ID>`. c4nary's SHA-256 is for local manifest-drift detection, not
a remote hash-catalog comparison.

TODO(M3): call c4nary, translate its Finding list into StageResult.findings.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage1"


def run(artifact: Path) -> StageResult:
    # Stub: no findings until the GGUF parser lands.
    return StageResult(stage=STAGE, ok=True)
