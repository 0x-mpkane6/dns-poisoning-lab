"""Deterministic replay schedules for the E5-v2 routed campaign."""

from __future__ import annotations

import hashlib
import json
import math
import random
from typing import Any

from e5_v2_lib import build_trial_qname


WORKLOAD_SPECS: dict[str, dict[str, Any]] = {
    "BENIGN_LOW": {
        "rate_pps": 2.5,
        "kind": "benign",
        "ipid_mode": "random",
        "fixed_ipid": None,
        "attack_tail": False,
    },
    "BENIGN_BOUNDARY": {
        "rate_pps": 12.0,
        "kind": "benign",
        "ipid_mode": "random",
        "fixed_ipid": None,
        "attack_tail": False,
    },
    "ATTACK_FIXED_MATCHED": {
        "rate_pps": 12.0,
        "kind": "attack",
        "ipid_mode": "fixed",
        "fixed_ipid": 777,
        "attack_tail": True,
    },
    "ATTACK_SWEEP_FLOOD": {
        "rate_pps": 200.0,
        "kind": "attack",
        "ipid_mode": "sweep",
        "fixed_ipid": None,
        "attack_tail": True,
    },
}


def _seed_value(seed: int, rep: int, workload: str, stream: str) -> int:
    digest = hashlib.sha256(f"{seed}:{rep}:{workload}:{stream}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _auth_ipid(spec: dict[str, Any], trial: int, rng: random.Random) -> int:
    if spec["fixed_ipid"] is not None:
        return int(spec["fixed_ipid"])
    # Keep the authoritative stream deterministic and separate from the
    # occupancy stream.  Avoid zero so packet captures are easy to inspect.
    return (rng.randrange(1, 65536) + trial) & 0xFFFF or 1


def build_replay_schedule(
    *,
    run_id: str,
    rep: int,
    workload: str,
    seed: int,
    trials: int = 50,
    duration_s: float = 120.0,
) -> dict[str, Any]:
    """Create one immutable workload schedule.

    The schedule contains both client qnames/authoritative IPIDs and the
    external occupancy arrival stream.  It is intentionally independent of
    policy, so a complete block can replay the same workload under every
    policy cell.
    """

    if workload not in WORKLOAD_SPECS:
        raise ValueError(f"unknown workload: {workload}")
    if rep < 0 or trials <= 0 or duration_s <= 0:
        raise ValueError("rep, trials, and duration_s must be positive where applicable")
    spec = WORKLOAD_SPECS[workload]
    trial_rng = random.Random(_seed_value(seed, rep, workload, "trials"))
    occupancy_rng = random.Random(_seed_value(seed, rep, workload, "occupancy"))

    trial_rows: list[dict[str, Any]] = []
    for trial in range(trials):
        nonce = trial_rng.randrange(0, 16**8)
        qname = build_trial_qname(run_id, rep, trial, nonce)
        trial_rows.append(
            {
                "trial_id": f"r{rep:02d}-t{trial:03d}-{nonce:08x}",
                "trial": trial,
                "qname": qname,
                "nonce": nonce,
                "auth_ipid": _auth_ipid(spec, trial, trial_rng),
                "tail_delay_s": 0.03,
            }
        )

    rate = float(spec["rate_pps"])
    count = int(math.ceil(rate * duration_s))
    occupancy: list[dict[str, Any]] = []
    sweep_value = 0
    for index in range(count):
        if spec["ipid_mode"] == "fixed":
            ipid = int(spec["fixed_ipid"])
        elif spec["ipid_mode"] == "sweep":
            ipid = sweep_value & 0xFFFF
            sweep_value += 1
        else:
            ipid = occupancy_rng.randrange(0, 65536)
        occupancy.append(
            {
                "seq": index,
                "at_s": round((index + 1) / rate, 9),
                "ipid": ipid,
                "payload_tag": f"occ-{rep:02d}-{index:07d}",
            }
        )

    return {
        "schema_version": 1,
        "run_id": run_id,
        "rep": rep,
        "workload": workload,
        "kind": spec["kind"],
        "rate_pps": rate,
        "ipid_mode": spec["ipid_mode"],
        "fixed_ipid": spec["fixed_ipid"],
        "attack_tail": bool(spec["attack_tail"]),
        "duration_s": duration_s,
        "trials": trial_rows,
        "occupancy": occupancy,
    }


def schedule_digest(schedule: dict[str, Any]) -> str:
    """Return the registration digest for a JSON schedule."""

    encoded = json.dumps(schedule, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
