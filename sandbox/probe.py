"""In-container load probe for AI-BOM Stage 3.

Runs in two roles:

* **parent** (default): re-executes itself under ``strace``, waits for the load,
  parses the syscall trace, and prints a single JSON report line to stdout.
* **child** (``_AIBOM_CHILD=1``): actually attempts to *load* the model (no
  inference) and writes the load result to a temp file. For pickle inputs this
  detonates any payload — safely, because the container is fully isolated.

The report schema is consumed by
``aibom.stages.stage3_sandbox.translate_probe_report``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

TRACE_LOG = "/tmp/trace.log"
RESULT = "/tmp/load_result.json"
TIMEOUT_S = 60

_PICKLE_SUFFIXES = {".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".pdparams"}
# Writes to these prefixes are expected/benign; anything else is suspicious.
_WRITE_ALLOW = ("/tmp/", "/dev/null", "/proc/self/", "/var/tmp/")
_OPEN_RE = re.compile(r'openat?\([^,]+,\s*"([^"]+)"[^)]*\)')
_EXECVE_RE = re.compile(r'execve\("([^"]+)"')


def child_load(model_path: str) -> None:
    """Attempt to load the model; record success/error. Runs traced."""
    result: dict[str, object] = {"loaded": False, "error": None}
    try:
        with open(model_path, "rb") as fh:
            magic = fh.read(8)
        suffix = Path(model_path).suffix.lower()
        if magic[:4] == b"GGUF":
            with open(model_path, "rb") as fh:
                fh.read(4096)  # touch the header region
        elif suffix == ".safetensors":
            import struct
            with open(model_path, "rb") as fh:
                n = struct.unpack("<Q", fh.read(8))[0]
                fh.read(min(n, 10_000_000))
        elif suffix in _PICKLE_SUFFIXES or magic[:1] == b"\x80":
            import pickle
            with open(model_path, "rb") as fh:
                pickle.load(fh)  # noqa: S301 - detonation is the point, in isolation
        else:
            with open(model_path, "rb") as fh:
                fh.read(4096)
        result["loaded"] = True
    except Exception as exc:  # noqa: BLE001 - any load failure is data, not a crash
        result["error"] = f"{type(exc).__name__}: {exc}"
    with open(RESULT, "w") as fh:
        json.dump(result, fh)


def parse_trace() -> dict[str, list[str]]:
    """Extract network / process-spawn / out-of-bounds-write events from the trace."""
    net: list[str] = []
    procs: list[str] = []
    writes: list[str] = []
    try:
        lines = Path(TRACE_LOG).read_text(errors="replace").splitlines()
    except OSError:
        return {"network_attempts": [], "spawned_processes": [], "file_writes": []}

    seen_first_execve = False
    for ln in lines:
        if ("socket(" in ln and "AF_INET" in ln) or "connect(" in ln:
            net.append(ln.strip()[:200])
        m = _EXECVE_RE.search(ln)
        if m:
            if not seen_first_execve:
                seen_first_execve = True  # the probe interpreter's own bootstrap
            else:
                procs.append(m.group(1))
        if "openat(" in ln or "open(" in ln:
            if any(flag in ln for flag in ("O_WRONLY", "O_RDWR", "O_CREAT")):
                pm = _OPEN_RE.search(ln)
                if pm and not pm.group(1).startswith(_WRITE_ALLOW):
                    writes.append(pm.group(1))
    return {"network_attempts": net, "spawned_processes": procs, "file_writes": writes}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    args = ap.parse_args()

    if os.environ.get("_AIBOM_CHILD") == "1":
        child_load(args.model)
        return 0

    report: dict[str, object] = {
        "loaded": False, "error": None, "traced": True, "timed_out": False,
        "network_attempts": [], "spawned_processes": [], "file_writes": [],
    }
    child_env = {**os.environ, "_AIBOM_CHILD": "1"}
    strace_cmd = [
        "strace", "-f", "-qq", "-e", "trace=execve,socket,connect,openat,open",
        "-o", TRACE_LOG, sys.executable, "/probe/probe.py", "--model", args.model,
    ]
    try:
        subprocess.run(strace_cmd, env=child_env, timeout=TIMEOUT_S,
                       capture_output=True, check=False)
    except subprocess.TimeoutExpired:
        report["timed_out"] = True
    except FileNotFoundError:
        report["traced"] = False

    if not Path(RESULT).exists():
        # strace unavailable/blocked: fall back to an untraced load so we still
        # learn whether the model loads (events just can't be observed).
        report["traced"] = False
        try:
            subprocess.run([sys.executable, "/probe/probe.py", "--model", args.model],
                           env=child_env, timeout=TIMEOUT_S, capture_output=True, check=False)
        except subprocess.TimeoutExpired:
            report["timed_out"] = True

    try:
        with open(RESULT) as fh:
            r = json.load(fh)
        report["loaded"] = r.get("loaded", False)
        report["error"] = r.get("error")
    except (OSError, json.JSONDecodeError):
        pass

    if report["traced"]:
        report.update(parse_trace())

    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
