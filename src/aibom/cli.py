"""Command-line entry point: `aibom scan <artifact>`."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from . import __version__, pipeline

app = typer.Typer(add_completion=False, help="AI model security scanner & ML-BOM generator.")


@app.command()
def scan(
    artifact: Path = typer.Argument(..., exists=True, readable=True, help="Model file to scan."),
    until: str = typer.Option("stage5", help="Run stages up to this key (stage1..stage5)."),
    behavioral: bool = typer.Option(False, help="Enable optional Stage 4 behavioral tests."),
    output: Path | None = typer.Option(None, help="Write the ML-BOM JSON to this path."),
) -> None:
    """Scan a model artifact and print/write its ML-BOM + verdict."""
    report = pipeline.scan(artifact, until=until, run_behavioral=behavioral)

    typer.echo(f"artifact : {report.artifact}")
    typer.echo(f"verdict  : {report.verdict.value}")

    if output and report.bom is not None:
        output.write_text(json.dumps(report.bom, indent=2), encoding="utf-8")
        typer.echo(f"bom      : {output}")

    # Non-zero exit on BLOCK so CI gates can fail the build.
    if report.verdict.value == "BLOCK":
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the AI-BOM version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
