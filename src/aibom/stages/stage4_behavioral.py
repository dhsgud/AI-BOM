"""Stage 4 — Behavioral Test (optional, research-grade).

The ONLY stage that actually executes the model, so it must run INSIDE the
Stage 3 sandbox — the "never execute untrusted models" invariant is preserved
by isolation, not by avoidance. This is entirely new work: c4nary explicitly
places weight/behavioral execution out of scope.

Uses FGSM/PGD input perturbations to score output consistency/anomalies.
c4nary's content-trigger rules (TPL020/021) *may* supply candidate trigger
literals as probe inputs, but only if c4nary exposes them structurally — its
current Finding has no structured trigger field, so that link is a pending
c4nary-side enhancement (see DEVELOPMENT_PLAN §Stage 4). Opt-in via
`--behavioral` and only when Docker is available; skips as INFO otherwise.

TODO(M5): implement FGSM/PGD probe and anomaly scoring, gated by the sandbox.
"""

from __future__ import annotations

from pathlib import Path

from ..models import StageResult

STAGE = "stage4"


def run(artifact: Path) -> StageResult:
    # Stub: only reached when run_behavioral=True.
    return StageResult(stage=STAGE, ok=True)
