"""Stage 3 — Docker Sandbox: isolated load test with syscall monitoring.

Loads (does NOT infer) the model inside a locked-down container so that a
loader-exploitation payload detonates in isolation, not on the host. The
container runs with no network, a read-only rootfs, all capabilities dropped,
no-new-privileges, and memory/pid/cpu limits; a probe inside attempts the load
under strace and reports observed filesystem writes, network attempts, and
spawned processes.

This is the only stage that runs untrusted code, and it does so only inside the
sandbox — the "never execute on the host" invariant holds by isolation. When
Docker (or the optional ``[sandbox]`` extra) is unavailable, the stage skips and
the run is reported as WARNING rather than silently trusted.

Pure, security-critical parts (hardening config, report translation, gating) are
unit-tested; the live container run degrades to a safe skip on any error.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Finding, Severity, StageResult

STAGE = "stage3"

DEFAULT_IMAGE = "aibom-sandbox:latest"

# Conservative resource caps for the throwaway load probe.
_MEM_LIMIT = "512m"
_PIDS_LIMIT = 128
_NANO_CPUS = 1_000_000_000  # 1.0 CPU
_TMPFS_SIZE = "size=64m"


def build_run_kwargs(
    model_path: Path,
    image: str = DEFAULT_IMAGE,
    seccomp_profile: str | None = None,
) -> dict[str, Any]:
    """Build hardened ``docker run`` kwargs for the isolated load probe.

    Pure and deterministic so the security posture can be asserted in tests.
    """
    security_opt = ["no-new-privileges:true"]
    if seccomp_profile is not None:
        security_opt.append(f"seccomp={seccomp_profile}")
    # else: Docker's default seccomp profile still applies.

    bind_name = model_path.name or "model"
    return {
        "image": image,
        "command": ["--model", f"/model/{bind_name}"],
        "network_mode": "none",       # no network reachability
        "network_disabled": True,
        "read_only": True,            # read-only rootfs
        "cap_drop": ["ALL"],          # drop every Linux capability
        "security_opt": security_opt,  # no-new-privileges (+ optional seccomp)
        "privileged": False,
        "mem_limit": _MEM_LIMIT,
        "pids_limit": _PIDS_LIMIT,
        "nano_cpus": _NANO_CPUS,
        "volumes": {str(model_path.resolve()): {"bind": f"/model/{bind_name}", "mode": "ro"}},
        "tmpfs": {"/tmp": _TMPFS_SIZE},  # the only writable path
        "remove": True,
        "detach": False,
    }


def translate_probe_report(report: dict[str, Any]) -> list[Finding]:
    """Translate the in-container probe's structured report into findings.

    Expected report keys (all optional): ``spawned_processes`` (list),
    ``network_attempts`` (list), ``file_writes`` (list, outside /tmp),
    ``oom`` (bool), ``timed_out`` (bool), ``loaded`` (bool), ``error`` (str).
    """
    findings: list[Finding] = []

    def _f(sev: Severity, rule: str, msg: str, **ev: Any) -> None:
        findings.append(Finding(stage=STAGE, severity=sev, rule_id=rule, message=msg,
                                evidence=dict(ev)))

    if report.get("spawned_processes"):
        _f(Severity.CRITICAL, "sandbox.process-spawn",
           "Model load spawned a process inside the sandbox.",
           processes=report["spawned_processes"])
    if report.get("network_attempts"):
        _f(Severity.HIGH, "sandbox.network-attempt",
           "Model load attempted network I/O in a no-network sandbox.",
           attempts=report["network_attempts"])
    if report.get("file_writes"):
        _f(Severity.HIGH, "sandbox.filesystem-write",
           "Model load wrote outside the permitted tmpfs.",
           writes=report["file_writes"])
    if report.get("oom"):
        _f(Severity.MEDIUM, "sandbox.oom",
           "Model load exceeded the memory limit (possible resource attack).")
    if report.get("timed_out"):
        _f(Severity.MEDIUM, "sandbox.timeout",
           "Model load exceeded the time limit.")
    if report.get("error") and not report.get("loaded", False):
        _f(Severity.MEDIUM, "sandbox.load-error",
           "Model failed to load in the sandbox (possibly malformed).",
           error=report["error"])
    return findings


def _skipped(message: str, **evidence: Any) -> StageResult:
    """A safe skip: reported so the verdict reflects incomplete coverage (WARNING)."""
    return StageResult(
        stage=STAGE, ok=False, skipped=True,
        findings=[Finding(stage=STAGE, severity=Severity.INFO,
                          rule_id="stage3.skipped", message=message,
                          evidence=dict(evidence))],
    )


def sandbox_available() -> tuple[bool, str]:
    """Return (available, reason). Available only if the SDK imports and the daemon pings."""
    try:
        import docker
    except ImportError:
        return False, "docker SDK not installed (pip install 'ai-bom[sandbox]')"
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # docker.errors.DockerException and friends
        return False, f"Docker daemon unavailable: {exc}"
    return True, "ok"


def run(artifact: Path, image: str = DEFAULT_IMAGE) -> StageResult:
    """Load-test the artifact in a hardened container; skip safely if unavailable."""
    available, reason = sandbox_available()
    if not available:
        return _skipped(f"Docker sandbox skipped: {reason}", reason=reason)

    try:
        import json

        import docker

        client = docker.from_env()
        kwargs = build_run_kwargs(artifact, image)
        # The probe writes a single JSON report line to stdout, then exits.
        raw = client.containers.run(**kwargs)
        report = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except Exception as exc:  # image missing, run failure, bad report -> safe skip
        return _skipped(f"Docker sandbox could not run the probe: {exc}", error=str(exc))

    return StageResult(stage=STAGE, ok=True, findings=translate_probe_report(report))
