"""Stage 1 — c4nary scan: GGUF AST static analysis + SHA-256 remote comparison.

NEVER renders templates or executes code. Networking is limited to HTTP
HEAD/Range header fetches for hash comparison. Non-GGUF artifacts pass through
to Stage 2.

TODO(M3): parse GGUF magic/version/KV metadata into an AST, parse (not render)
chat_template, compute SHA-256, and compare against a remote catalog.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage1"


def run(artifact: Path) -> StageResult:
    # Stub: no findings until the GGUF parser lands.
    return StageResult(stage=STAGE, ok=True)
