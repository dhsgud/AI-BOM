"""Stage 2 — Format Scanner: pickle opcode analysis + safetensors validation.

Handles the non-GGUF formats c4nary does not cover:

* **Pickle-based** (.pt/.pth/.bin/.ckpt/.pkl/.pickle, incl. torch zip archives):
  scanned with `picklescan`, which inspects pickle opcodes/globals **without
  unpickling**. Dangerous globals (os.system, eval, ...) mean arbitrary code
  runs on load.
* **safetensors**: the header is parsed directly from bytes (never loaded via a
  tensor backend, so no untrusted C loader touches the file) and validated for
  out-of-bounds / overlapping / inconsistent tensor offsets — the loader-
  exploitation class, analogous to c4nary's STR* checks for GGUF.

GGUF and unrecognized formats pass through untouched.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from ..models import Finding, Severity, StageResult

STAGE = "stage2"

# Extensions that carry a Python pickle (possibly inside a zip, which picklescan
# unpacks itself).
_PICKLE_EXTS = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".pdparams"}
_ZIP_MAGIC = b"PK\x03\x04"
_PICKLE_PROTO_OP = 0x80  # PROTO opcode that starts protocol >= 2 pickles
_GGUF_MAGIC = b"GGUF"

# safetensors dtype -> element size in bytes (for offset/size consistency checks).
_ST_DTYPE_SIZES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4,
    "I64": 8, "U64": 8, "F64": 8,
}

# Reject a header claiming to be larger than this (DoS / absurd allocation).
_MAX_ST_HEADER = 100_000_000  # 100 MB of JSON header is never legitimate


# --------------------------------------------------------------------------- #
# Format routing
# --------------------------------------------------------------------------- #
def _magic(artifact: Path, n: int = 8) -> bytes:
    try:
        with artifact.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def is_safetensors(artifact: Path) -> bool:
    if artifact.suffix.lower() == ".safetensors":
        return True
    # Sniff: 8-byte little-endian header length, immediately followed by a JSON
    # object (which always starts with '{').
    head = _magic(artifact, 9)
    if len(head) < 9:
        return False
    n = struct.unpack("<Q", head[:8])[0]
    return head[8:9] == b"{" and 0 < n < _MAX_ST_HEADER


def looks_like_pickle(artifact: Path) -> bool:
    if artifact.suffix.lower() in _PICKLE_EXTS:
        return True
    head = _magic(artifact, 4)
    return head.startswith(_ZIP_MAGIC) or (len(head) >= 1 and head[0] == _PICKLE_PROTO_OP)


# --------------------------------------------------------------------------- #
# Pickle scanning (picklescan)
# --------------------------------------------------------------------------- #
def _map_pickle_safety(safety_name: str) -> Severity | None:
    # picklescan SafetyLevel: Innocuous | Suspicious | Dangerous.
    if safety_name == "Dangerous":
        return Severity.CRITICAL  # arbitrary code executes on unpickle
    if safety_name == "Suspicious":
        return Severity.MEDIUM
    return None  # Innocuous -> not reported


def scan_pickle(artifact: Path) -> list[Finding]:
    try:
        from picklescan.scanner import scan_file_path
    except ImportError:
        return [
            Finding(
                stage=STAGE, severity=Severity.MEDIUM,
                rule_id="stage2.picklescan-unavailable",
                message="picklescan is not installed; pickle analysis skipped.",
                evidence={"hint": "pip install picklescan"},
            )
        ]

    result = scan_file_path(str(artifact))
    findings: list[Finding] = []

    for g in result.globals:
        severity = _map_pickle_safety(g.safety.name)
        if severity is None:
            continue
        findings.append(
            Finding(
                stage=STAGE, severity=severity,
                rule_id=f"pickle.{g.safety.name.lower()}-global",
                message=f"{g.safety.name} pickle global: {g.module}.{g.name}",
                evidence={"module": g.module, "name": g.name, "safety": g.safety.name},
            )
        )

    if result.scan_err:
        findings.append(
            Finding(
                stage=STAGE, severity=Severity.HIGH,
                rule_id="stage2.pickle-scan-error",
                message="picklescan reported an error parsing the file.",
                evidence={"scanned_files": result.scanned_files},
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# safetensors header validation (manual, no tensor backend)
# --------------------------------------------------------------------------- #
def _fail(rule_id: str, message: str, **evidence: object) -> Finding:
    return Finding(stage=STAGE, severity=Severity.HIGH, rule_id=rule_id,
                   message=message, evidence=dict(evidence))


def scan_safetensors(artifact: Path) -> list[Finding]:
    file_size = artifact.stat().st_size
    if file_size < 8:
        return [_fail("safetensors.truncated", "File is too small to hold a safetensors header.")]

    with artifact.open("rb") as fh:
        header_len = struct.unpack("<Q", fh.read(8))[0]
        if header_len == 0:
            return [_fail("safetensors.empty-header", "Declared header length is zero.")]
        if header_len > _MAX_ST_HEADER:
            return [Finding(stage=STAGE, severity=Severity.MEDIUM,
                            rule_id="safetensors.oversized-header",
                            message="Declared header length is implausibly large.",
                            evidence={"header_len": header_len})]
        if 8 + header_len > file_size:
            return [_fail("safetensors.header-out-of-bounds",
                          "Declared header length exceeds the file size.",
                          header_len=header_len, file_size=file_size)]
        header_bytes = fh.read(header_len)

    try:
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [_fail("safetensors.bad-json", "Header is not valid JSON.", error=str(exc))]
    if not isinstance(header, dict):
        return [_fail("safetensors.bad-json", "Header JSON is not an object.")]

    buffer_size = file_size - 8 - header_len
    findings: list[Finding] = []
    spans: list[tuple[int, int, str]] = []

    for name, spec in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(spec, dict) or "data_offsets" not in spec:
            findings.append(_fail("safetensors.bad-entry",
                                  f"Tensor entry {name!r} is malformed.", tensor=name))
            continue
        offsets = spec.get("data_offsets")
        dtype = spec.get("dtype")
        shape = spec.get("shape", [])
        if (not isinstance(offsets, list) or len(offsets) != 2
                or not all(isinstance(x, int) for x in offsets)):
            findings.append(_fail("safetensors.bad-offsets",
                                  f"Tensor {name!r} has malformed data_offsets.", tensor=name))
            continue
        begin, end = offsets
        if not (0 <= begin <= end <= buffer_size):
            findings.append(_fail("safetensors.offset-out-of-bounds",
                                  f"Tensor {name!r} offsets fall outside the data buffer.",
                                  tensor=name, data_offsets=offsets, buffer_size=buffer_size))
            continue
        # Offset span vs declared dtype/shape must agree.
        elem = _ST_DTYPE_SIZES.get(dtype) if isinstance(dtype, str) else None
        if elem is not None and isinstance(shape, list):
            n_elems = 1
            for d in shape:
                n_elems *= d if isinstance(d, int) and d >= 0 else 0
            if elem * n_elems != end - begin:
                findings.append(_fail("safetensors.size-mismatch",
                                      f"Tensor {name!r} byte span disagrees with dtype/shape.",
                                      tensor=name, dtype=dtype, shape=shape,
                                      span=end - begin, expected=elem * n_elems))
        spans.append((begin, end, name))

    # Overlap detection (no legitimate safetensors aliases tensor data).
    spans.sort()
    for (b1, e1, n1), (b2, e2, n2) in zip(spans, spans[1:]):
        if b2 < e1:
            findings.append(_fail("safetensors.overlap",
                                  f"Tensor data regions overlap: {n1!r} and {n2!r}.",
                                  a=n1, b=n2))
    return findings


# --------------------------------------------------------------------------- #
def run(artifact: Path) -> StageResult:
    """Route the artifact to the pickle or safetensors scanner; else pass through."""
    if _magic(artifact, 4).startswith(_GGUF_MAGIC):
        return StageResult(stage=STAGE, ok=True)  # handled by Stage 1

    if is_safetensors(artifact):
        return StageResult(stage=STAGE, ok=True, findings=scan_safetensors(artifact))
    if looks_like_pickle(artifact):
        return StageResult(stage=STAGE, ok=True, findings=scan_pickle(artifact))

    # Unrecognized format: nothing to assert here.
    return StageResult(stage=STAGE, ok=True)
