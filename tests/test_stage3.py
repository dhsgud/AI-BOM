"""Tests for Stage 3 (Docker sandbox): hardening config, report translation, gating.

The live container run is not exercised here (needs a running Docker daemon +
built probe image); the security-critical pure functions and the safe-skip path
are. In any CI without the sandbox extra / daemon, run() takes the skip path.
"""

from pathlib import Path

from aibom.models import Severity
from aibom.stages import stage3_sandbox as s3


def test_hardening_flags():
    kw = s3.build_run_kwargs(Path("/models/m.gguf"))
    assert kw["network_mode"] == "none"
    assert kw["network_disabled"] is True
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kw["security_opt"]
    assert kw["privileged"] is False
    assert kw["pids_limit"] == 128
    assert kw["mem_limit"] == "512m"
    # Model is bound read-only; /tmp is the only writable path.
    (bind,) = kw["volumes"].values()
    assert bind["mode"] == "ro"
    assert "/tmp" in kw["tmpfs"]


def test_seccomp_profile_opt_in():
    kw = s3.build_run_kwargs(Path("/m.gguf"), seccomp_profile="/etc/seccomp.json")
    assert "seccomp=/etc/seccomp.json" in kw["security_opt"]
    # Default: no explicit seccomp opt (Docker's default profile still applies).
    kw2 = s3.build_run_kwargs(Path("/m.gguf"))
    assert not any(o.startswith("seccomp=") for o in kw2["security_opt"])


def test_translate_process_spawn_is_critical():
    f = s3.translate_probe_report({"spawned_processes": ["/bin/sh"], "loaded": True})
    assert any(x.severity == Severity.CRITICAL and x.rule_id == "sandbox.process-spawn"
               for x in f)


def test_translate_network_and_filesystem_are_high():
    f = s3.translate_probe_report({"network_attempts": ["1.2.3.4:443"],
                                   "file_writes": ["/etc/passwd"], "loaded": True})
    ids = {x.rule_id: x.severity for x in f}
    assert ids["sandbox.network-attempt"] == Severity.HIGH
    assert ids["sandbox.filesystem-write"] == Severity.HIGH


def test_translate_oom_timeout_loaderror_medium():
    assert s3.translate_probe_report({"oom": True})[0].severity == Severity.MEDIUM
    assert s3.translate_probe_report({"timed_out": True})[0].severity == Severity.MEDIUM
    le = s3.translate_probe_report({"error": "bad magic", "loaded": False})
    assert le[0].rule_id == "sandbox.load-error" and le[0].severity == Severity.MEDIUM


def test_translate_clean_load_no_findings():
    assert s3.translate_probe_report({"loaded": True}) == []
    # An error is not a load-error if the model still loaded.
    assert s3.translate_probe_report({"error": "warn", "loaded": True}) == []


def test_sandbox_available_returns_reason():
    ok, reason = s3.sandbox_available()
    assert isinstance(ok, bool) and isinstance(reason, str) and reason


def test_run_skips_safely_without_sandbox(tmp_path):
    art = tmp_path / "m.gguf"
    art.write_bytes(b"GGUF\x03\x00\x00\x00")
    result = s3.run(art)
    # No daemon/extra in the test env -> safe skip that drives a WARNING verdict.
    assert result.skipped is True
    assert result.findings[0].rule_id == "stage3.skipped"
