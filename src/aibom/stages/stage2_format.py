"""Stage 2 — Format Scanner: pickle opcode analysis + safetensors validation.

Detects executable code without ever unpickling. Uses picklescan plus a custom
opcode walker for GLOBAL/STACK_GLOBAL/REDUCE/INST/OBJ/NEWOBJ, and validates
safetensors header offsets/dtypes for tampering.

TODO(M2): integrate picklescan, add the safetensors header validator.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage2"


def run(artifact: Path) -> StageResult:
    # Stub: no findings until picklescan + safetensors validators land.
    return StageResult(stage=STAGE, ok=True)
