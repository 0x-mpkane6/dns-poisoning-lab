from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def subject():
    spec = importlib.util.spec_from_file_location("supplement_validation", HERE / "validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_decision_window_rebuild_accepts_negative_outcome():
    validator = subject()
    events = [{"mono_s": 10.0, "ipid": 777}, {"mono_s": 10.1, "ipid": 777}]
    decision = {"mono_s": 10.2, "samples": 2, "unique_ipids": 1, "entropy": 0.0, "unique_ratio": 0.5}
    assert validator.rebuild_windows(events, [decision], 2.0) == []


def test_decision_window_rebuild_rejects_incorrect_count():
    validator = subject()
    decision = {"mono_s": 10.2, "samples": 2, "unique_ipids": 1, "entropy": 0.0, "unique_ratio": 0.5}
    assert validator.rebuild_windows([], [decision], 2.0)


def test_pcap_rejects_truncated_capture(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"abc")
    with pytest.raises(ValueError):
        subject().pcap_summary(path)


def test_pcap_counts_real_noninitial_ipv4_fragment(tmp_path):
    packet = bytes(12) + b"\x08\x00" + bytes.fromhex("4500001400010005001100000a5000640a500035")
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 256, 1)
    path = tmp_path / "one.pcap"
    path.write_bytes(header + struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet)
    result = subject().pcap_summary(path)
    assert result["noninitial_ipv4_fragments"] == 1
    assert result["packets"] == 1
