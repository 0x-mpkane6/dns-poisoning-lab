"""Regression tests: run against legacy code until its supplement exists."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

HERE = Path(__file__).resolve().parent
LAB = HERE.parent


def load_subject(name: str, legacy: Path):
    path = HERE / f"{name}.py"
    path = path if path.exists() else legacy
    spec = importlib.util.spec_from_file_location(f"e5_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_window_uses_monotonic_time(monkeypatch):
    detector = load_subject("detector", LAB / "resolver" / "detector.py")
    monkeypatch.setattr(detector.time, "time", lambda: 1_800_000_000.0)
    monkeypatch.setattr(detector.time, "monotonic", lambda: 100.0)
    detector._events.extend([(97.0, 1), (99.0, 2)])
    assert detector.occupancy_now()[0] == 1


def test_failed_firewall_install_is_not_reported_installed(monkeypatch, tmp_path):
    detector = load_subject("detector", LAB / "resolver" / "detector.py")
    monkeypatch.setattr(detector, "append", Mock())
    monkeypatch.setattr(detector.subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 4, "", "denied")))
    detector.set_drop(True)
    assert detector._blocking is False


def test_rate_workload_starts_exactly_one_occupancy_sender(monkeypatch):
    campaign = load_subject("campaign", LAB / "e5_unbound_campaign.py")
    calls = []
    monkeypatch.setattr(campaign, "run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(campaign.time, "sleep", lambda _: None)
    campaign.start_sender(campaign.CASES["C2_benign_boundary"], 42)
    occupancy = [cmd for cmd in calls if "occupancy" in cmd]
    assert len(occupancy) == 1


def test_tail_latency_is_available_without_treating_rounds_as_runs():
    campaign = load_subject("campaign", LAB / "e5_unbound_campaign.py")
    metrics = campaign.summarize_run(
        case_id="C1_benign_low", spec={"defense": "on", "control": False},
        result_text="203.0.113.80\n", trigger_lat_text="10\n20\n30\n",
        bank_lat_text="1\n2\n3\n", decision_text='{"action":"allow","samples":1}\n',
        stats={}, wall_s=1.0,
    )
    assert metrics["trigger_command_latency_p99_ms"] == pytest.approx(29.8)
    assert metrics["bank_lookup_latency_p99_ms"] == pytest.approx(2.98)
