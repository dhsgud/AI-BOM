"""Tests for Stage 2 (Format Scanner): safetensors validation + picklescan."""

import json
import pickle
import struct

import pytest

from aibom.models import Severity
from aibom.stages import stage2_format as s2


def _write_safetensors(path, header: dict, data: bytes) -> None:
    hb = json.dumps(header).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(hb)) + hb + data)


# --- safetensors --------------------------------------------------------- #
def test_safetensors_valid(tmp_path):
    p = tmp_path / "m.safetensors"
    _write_safetensors(p, {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}},
                       b"\x00" * 16)
    assert s2.scan_safetensors(p) == []


def test_safetensors_offset_out_of_bounds(tmp_path):
    p = tmp_path / "m.safetensors"
    _write_safetensors(p, {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 999]}},
                       b"\x00" * 16)
    ids = {f.rule_id for f in s2.scan_safetensors(p)}
    assert "safetensors.offset-out-of-bounds" in ids


def test_safetensors_size_mismatch(tmp_path):
    p = tmp_path / "m.safetensors"
    # F32 [2,2] should be 16 bytes but the span is only 8.
    _write_safetensors(p, {"w": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 8]}},
                       b"\x00" * 8)
    findings = s2.scan_safetensors(p)
    assert any(f.rule_id == "safetensors.size-mismatch" and f.severity == Severity.HIGH
               for f in findings)


def test_safetensors_overlap(tmp_path):
    p = tmp_path / "m.safetensors"
    header = {
        "a": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        "b": {"dtype": "F32", "shape": [4], "data_offsets": [8, 24]},
    }
    _write_safetensors(p, header, b"\x00" * 24)
    assert any(f.rule_id == "safetensors.overlap" for f in s2.scan_safetensors(p))


def test_safetensors_bad_json(tmp_path):
    p = tmp_path / "m.safetensors"
    body = b"not-json!!"
    p.write_bytes(struct.pack("<Q", len(body)) + body)
    assert any(f.rule_id == "safetensors.bad-json" for f in s2.scan_safetensors(p))


def test_safetensors_oversized_header(tmp_path):
    p = tmp_path / "m.safetensors"
    p.write_bytes(struct.pack("<Q", 200_000_000) + b"{}")
    findings = s2.scan_safetensors(p)
    assert any(f.rule_id == "safetensors.oversized-header" and f.severity == Severity.MEDIUM
               for f in findings)


# --- routing ------------------------------------------------------------- #
def test_routing(tmp_path):
    st = tmp_path / "x.safetensors"
    _write_safetensors(st, {"w": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, b"\x00")
    assert s2.is_safetensors(st) is True

    pk = tmp_path / "x.pkl"
    assert s2.looks_like_pickle(pk) is True

    gguf = tmp_path / "x.gguf"
    gguf.write_bytes(b"GGUF\x03\x00\x00\x00")
    result = s2.run(gguf)  # GGUF is Stage 1's job
    assert result.findings == []


# --- picklescan integration --------------------------------------------- #
pytest.importorskip("picklescan", reason="picklescan not installed")


class _Evil:
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))


def test_malicious_pickle_is_critical(tmp_path):
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps(_Evil()))  # building bytes does not execute the payload
    findings = s2.scan_pickle(p)
    assert any(f.severity == Severity.CRITICAL and f.rule_id.startswith("pickle.dangerous")
               for f in findings)


def test_benign_pickle_no_dangerous(tmp_path):
    p = tmp_path / "clean.pkl"
    p.write_bytes(pickle.dumps({"weights": [1, 2, 3], "name": "ok"}))
    findings = s2.scan_pickle(p)
    assert all(f.severity != Severity.CRITICAL for f in findings)
