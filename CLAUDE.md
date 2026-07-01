# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AI-BOM is a security scanner for untrusted AI model artifacts (GGUF / pickle / SafeTensors). It analyzes models **without executing them** and emits a CycloneDX ML-BOM (JSON) plus a `SAFE / WARNING / BLOCK` verdict. See `docs/DEVELOPMENT_PLAN.md` for the milestone roadmap and `docs/ARCHITECTURE.md` for design detail.

Status: **alpha** — the pipeline and data-model scaffold exist; each stage's `run()` is currently a stub. Milestone order (Stage 5→2→1→3→4) is deliberate; do not assume a stage is implemented just because its file exists.

## Commands

```bash
pip install -e ".[dev]"        # install with dev tooling
pip install -e ".[sandbox]"    # + docker SDK (Stage 3)
pip install -e ".[behavioral]" # + torch/numpy (Stage 4, heavy/optional)

ruff check src tests           # lint
mypy src                       # type check (strict)
pytest                         # all tests
pytest --cov=aibom             # with coverage
pytest tests/test_verdict.py::test_block_on_high_or_critical  # single test

aibom scan ./model.gguf --until stage3 --output bom.json  # run the CLI
```

CI (`.github/workflows/ci.yml`) runs ruff + mypy + pytest on 3.11.

## Architecture

Data flows through an ordered stage pipeline; every stage shares one contract.

- **`models.py`** — the contract between stages. `StageResult` carries `findings` (list of `Finding`, each with a `Severity`) and an optional `bom_fragment`. Note `ok` means the stage *ran*, not that it found nothing; a stage that can't run (e.g. Docker missing) sets `skipped=True`.
- **`pipeline.py`** — `scan()` walks the `STAGES` registry in order, honoring `--until` and gating Stage 4 behind `run_behavioral`. Stage 5 is special: it always runs last and its `run()` receives the accumulated results (different signature from other stages).
- **`verdict.py`** — pure reducer from all findings to one `Verdict`: any HIGH/CRITICAL → `BLOCK`; any LOW/MEDIUM or any skipped stage → `WARNING`; else `SAFE`. The CLI exits non-zero on `BLOCK` so it can gate CI.
- **`stages/`** — one file per stage; each exposes `run(artifact) -> StageResult` (Stage 5: `run(artifact, prior)`).

To add a **new stage/format**: implement `run()` returning a `StageResult`, register it in `pipeline.STAGES`, and route by artifact type. Rules are namespaced via `Finding.rule_id` (e.g. `stage2.stack-global`).

## Non-negotiable invariant

**Never execute or render untrusted model content.** Analysis is static-only (opcode/AST inspection) or fully isolated (Stage 3 Docker sandbox: `--network none`, seccomp, `--cap-drop ALL`). Parsers must not `unpickle`, `eval`, or render Jinja templates. Any change touching a parser must preserve this — it is the core security property, not an optimization.
