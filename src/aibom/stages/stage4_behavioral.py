"""Stage 4 — Behavioral Test (optional, research-grade).

The ONLY stage that actually executes the model, so it must run INSIDE the
Stage 3 sandbox — the "never execute untrusted models" invariant is preserved
by isolation, not by avoidance. This is entirely new work: c4nary explicitly
places weight/behavioral execution out of scope.

Uses FGSM/PGD input perturbations to score output consistency/anomalies.

Trigger inputs are extracted by AI-BOM itself (decision: keep c4nary unmodified).
`trigger_extract.py` reuses c4nary's `parse_gguf` to get the chat_template, then
walks the Jinja AST for content-keyed conditions (`in` / `==` / `.startswith` /
`.find`) and pulls their literal operands (e.g. 'deploy') as probe candidates —
preferred over string-parsing c4nary's human-readable `detail`. The probe then
compares model output with vs without each trigger inside the sandbox.

Opt-in via `--behavioral` and only when Docker is available; skips as INFO
otherwise.

TODO(M5): implement trigger_extract + FGSM/PGD probe, gated by the sandbox.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage4"


def run(artifact: Path) -> StageResult:
    # Stub: only reached when run_behavioral=True.
    return StageResult(stage=STAGE, ok=True)
