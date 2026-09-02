from __future__ import annotations

import json
import sys
from pathlib import Path

E5_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E5_ROOT))

from e5_v2_validate import validate_trial_records  # noqa: E402


def trial(qname: str, cache_hit: bool = False) -> dict:
    return {
        "event": "trial",
        "run_id": "E5-v2-routed-s20260902-r001",
        "rep": 1,
        "policy": "B0_OFF",
        "workload": "BENIGN_LOW",
        "trial_id": "r01-t000-abcdef01",
        "qname": qname,
        "trial": 0,
        "cache_before": {"cache_hit": cache_hit},
        "cache_after": {"cache_hit": False, "answers": []},
        "status": "no_answer",
        "query_start_mono_ns": 100,
        "client_answer_end_mono_ns": 200,
    }


def test_trial_validator_accepts_unique_cache_miss() -> None:
    result = validate_trial_records([trial("r01-t000-abcdef01.bank.com.")], expected_trials=1)
    assert result["status"] == "PASS"


def test_trial_validator_rejects_cache_hit_before_trial() -> None:
    result = validate_trial_records([trial("r01-t000-abcdef01.bank.com.", cache_hit=True)], expected_trials=1)
    assert result["status"] == "FAIL"
    assert any("cache-before" in error for error in result["errors"])
