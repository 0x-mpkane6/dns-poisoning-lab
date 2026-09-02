from __future__ import annotations

import json
import sys
from pathlib import Path

E5_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E5_ROOT))

from run_e5_v2 import build_stage_jobs, source_guard  # noqa: E402


def protocol() -> dict:
    return {
        "experiment_seed": 20260902,
        "k_runs_per_cell": 20,
        "trials_per_run": 50,
        "policies": ["B0_OFF", "B1_RL2_TC", "B5_LOCKED_TC", "RFC_DROP_NATIVE"],
        "workloads": ["BENIGN_LOW", "BENIGN_BOUNDARY", "ATTACK_FIXED_MATCHED", "ATTACK_SWEEP_FLOOD"],
        "pilot": [
            ["B0_OFF", "ATTACK_FIXED_MATCHED"],
            ["PREARM_TAIL_DROP", "ATTACK_FIXED_MATCHED"],
        ],
    }


def test_confirmatory_jobs_are_randomized_complete_blocks() -> None:
    jobs = build_stage_jobs("confirmatory", protocol())
    assert len(jobs) == 320
    assert (jobs[0]["policy"], jobs[0]["workload"]) != ("B0_OFF", "BENIGN_LOW") or jobs[1]["policy"] != "B0_OFF"
    for rep in range(1, 21):
        block = [row for row in jobs if row["rep"] == rep]
        assert len(block) == 16
        assert len({(row["policy"], row["workload"]) for row in block}) == 16


def test_sanity_has_one_complete_block_and_pilot_excludes_confirmatory_only() -> None:
    sanity = build_stage_jobs("sanity", protocol())
    assert len(sanity) == 16
    assert {row["rep"] for row in sanity} == {0}
    pilot = build_stage_jobs("pilot", protocol())
    assert len(pilot) == 2
    assert all(row["rep"] == 0 and row["policy"] in {"B0_OFF", "PREARM_TAIL_DROP"} for row in pilot)


def test_source_guard_rejects_resolver_local_poisoner(tmp_path: Path) -> None:
    (tmp_path / "resolver").mkdir()
    (tmp_path / "resolver" / "poisoner.py").write_text("", encoding="utf-8")
    result = source_guard(tmp_path)
    assert result["status"] == "FAIL"
    assert result["errors"]
