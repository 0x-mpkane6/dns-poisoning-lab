"""Deterministic reconstruction of E5-v2 metrics from raw artifacts."""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter, deque
from pathlib import Path
from typing import Any

from e5_v2_lib import classify_outcome, raw_shannon_entropy


POISON_IP = "6.6.6.6"
LEGITIMATE_IP = "203.0.113.80"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSONL row at {path}:{line_number}")
        rows.append(value)
    return rows


def _quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def _trial_events(rows: list[dict[str, Any]], trial: dict[str, Any]) -> list[dict[str, Any]]:
    qname = trial.get("qname")
    trial_id = trial.get("trial_id")
    return [
        row
        for row in rows
        if (qname and row.get("qname") == qname) or (trial_id and row.get("trial_id") == trial_id)
    ]


def _has_event(rows: list[dict[str, Any]], event: str) -> bool:
    return any(row.get("event") == event for row in rows)


def _has_drop(rows: list[dict[str, Any]], *, noninitial_only: bool = False) -> bool:
    return any(
        row.get("event") == "packet_verdict"
        and row.get("verdict") == "drop"
        and (not noninitial_only or int(row.get("offset", 0)) > 0)
        for row in rows
    )


def reconstruct_b5_windows(
    ips_rows: list[dict[str, Any]],
    *,
    window_seconds: float = 2.0,
    min_samples: int = 8,
    entropy_threshold: float = 6.0,
    unique_ratio_threshold: float = 0.90,
) -> list[dict[str, Any]]:
    """Rebuild B5 state from raw non-initial-fragment observations only."""

    if window_seconds <= 0 or min_samples < 0:
        raise ValueError("window_seconds must be positive and min_samples non-negative")
    observations = sorted(
        (row for row in ips_rows if row.get("event") == "fragment_observed" and row.get("ipid") is not None),
        key=lambda row: int(row["mono_ns"]),
    )
    states: list[dict[str, Any]] = []
    state: deque[tuple[int, int]] = deque()
    window_ns = int(window_seconds * 1_000_000_000)
    for row in observations:
        timestamp = int(row["mono_ns"])
        cutoff = timestamp - window_ns
        while state and state[0][0] < cutoff:
            state.popleft()
        previous_n = len(state)
        previous_entropy = raw_shannon_entropy([ipid for _, ipid in state])
        previous_ratio = len({ipid for _, ipid in state}) / previous_n if previous_n else 0.0
        previous_active = previous_n >= min_samples and previous_entropy >= entropy_threshold and previous_ratio >= unique_ratio_threshold
        state.append((timestamp, int(row["ipid"])))
        ipids = [ipid for _, ipid in state]
        n = len(ipids)
        entropy = raw_shannon_entropy(ipids)
        unique_ratio = len(set(ipids)) / n if n else 0.0
        active = n >= min_samples and entropy >= entropy_threshold and unique_ratio >= unique_ratio_threshold
        states.append(
            {
                "mono_ns": timestamp,
                "b5_active": active,
                "triggered": active and not previous_active,
                "samples": n,
                "entropy": entropy,
                "unique_ratio": unique_ratio,
            }
        )
    return states


def compute_run_metrics(run_dir: Path, *, expected_trials: int | None = None) -> dict[str, Any]:
    """Reconstruct one run without treating its 50 trials as independent runs."""

    trials = read_jsonl(run_dir / "trials.jsonl")
    ips = read_jsonl(run_dir / "ips_events.jsonl")
    auth = read_jsonl(run_dir / "auth_events.jsonl")
    attacker = read_jsonl(run_dir / "attacker_events.jsonl")
    cache = read_jsonl(run_dir / "cache_events.jsonl")
    if expected_trials is not None and len(trials) != expected_trials:
        raise ValueError(f"expected {expected_trials} trial rows, found {len(trials)}")
    if not trials:
        raise ValueError(f"no trial rows in {run_dir}")

    first = trials[0]
    workload = str(first.get("workload", "unknown"))
    policy = str(first.get("policy", "unknown"))
    attack = workload.startswith("ATTACK_")
    reconstructed_states = reconstruct_b5_windows(ips)
    reconstructed_triggers = [row["mono_ns"] for row in reconstructed_states if row.get("triggered")]
    runtime_triggers = [int(row.get("mono_ns", 0)) for row in ips if row.get("event") == "detector_trigger"]
    trigger_times = reconstructed_triggers or runtime_triggers
    trigger_trials = 0
    forged_ingress_trials = 0
    forged_drop_trials = 0
    tc_trials = 0
    tcp_trials = 0
    poison_trials = 0
    legit_trials = 0
    noanswer_trials = 0
    latencies: list[float] = []
    per_trial: list[dict[str, Any]] = []
    root_causes: Counter[str] = Counter()

    for trial in sorted(trials, key=lambda row: int(row.get("trial", 0))):
        qname = trial.get("qname")
        events = _trial_events(ips, trial)
        auth_events = _trial_events(auth, trial)
        attacker_events = _trial_events(attacker, trial)
        query_start = int(trial.get("client_query_start_mono_ns", trial.get("mono_ns", 0)))
        trigger_before = any(
            int(timestamp) <= query_start for timestamp in trigger_times
        )
        forged_sends = [row for row in attacker_events if row.get("event") == "forged_tail_send"]
        candidate_ipids = {int(row["ipid"]) for row in forged_sends if row.get("ipid") is not None}
        forged_hashes = {
            packet_hash
            for row in forged_sends
            for packet_hash in row.get("packet_sha256", [])
            if isinstance(packet_hash, str)
        }
        packet_events = [row for row in events if row.get("event") in {"packet_ingress", "packet_verdict"}]
        if forged_hashes:
            forged_ingress = any(
                row.get("event") == "packet_ingress"
                and int(row.get("offset", 0)) > 0
                and row.get("payload_sha256") in forged_hashes
                for row in packet_events
            )
            forged_drop = any(
                row.get("event") == "packet_verdict"
                and row.get("verdict") == "drop"
                and int(row.get("offset", 0)) > 0
                and row.get("payload_sha256") in forged_hashes
                for row in packet_events
            )
        elif candidate_ipids:
            forged_ingress = any(
                row.get("event") == "packet_ingress"
                and int(row.get("offset", 0)) > 0
                and int(row.get("ipid", -1)) in candidate_ipids
                for row in packet_events
            )
            forged_drop = any(
                row.get("event") == "packet_verdict"
                and row.get("verdict") == "drop"
                and int(row.get("offset", 0)) > 0
                and int(row.get("ipid", -1)) in candidate_ipids
                for row in packet_events
            )
        else:
            forged_ingress = _has_event(events, "packet_ingress") and any(int(row.get("offset", 0)) > 0 for row in packet_events)
            forged_drop = _has_drop(events, noninitial_only=True)
        tc_injected = _has_event(events, "tc_injected")
        tcp_retry = any(row.get("event") in {"tcp_receive", "tcp_query"} for row in auth_events)
        answer_ip = trial.get("answer_ip")
        poisoned = answer_ip == POISON_IP or POISON_IP in trial.get("cache_after", {}).get("answers", [])
        legitimate = answer_ip == LEGITIMATE_IP
        noanswer = answer_ip is None
        if trigger_before:
            trigger_trials += 1
        if forged_ingress:
            forged_ingress_trials += 1
        if forged_drop:
            forged_drop_trials += 1
        if tc_injected:
            tc_trials += 1
        if tcp_retry:
            tcp_trials += 1
        if poisoned:
            poison_trials += 1
        if legitimate:
            legit_trials += 1
        if noanswer:
            noanswer_trials += 1
        latency = trial.get("client_latency_ms", trial.get("latency_ms"))
        if latency is not None and math.isfinite(float(latency)):
            latencies.append(float(latency))
        cause = classify_outcome(
            poisoned=poisoned,
            trigger_before=trigger_before,
            drop_observed=forged_drop or _has_drop(events),
            tcp_retry=tcp_retry,
            legitimate=legitimate,
            attack=attack,
        )
        if attack:
            root_causes[cause] += 1
        per_trial.append(
            {
                "trial_id": trial.get("trial_id"),
                "qname": qname,
                "answer_ip": answer_ip,
                "status": trial.get("status"),
                "poisoned": poisoned,
                "legitimate": legitimate,
                "trigger_before": trigger_before,
                "forged_tail_ingress": forged_ingress,
                "forged_tail_drop": forged_drop,
                "tc_injected": tc_injected,
                "tcp_retry": tcp_retry,
                "root_cause": cause,
            }
        )

    n = len(trials)
    cache_before_hits = sum(bool(row.get("cache_before", {}).get("cache_hit")) for row in trials)
    cache_after_poison = sum(POISON_IP in row.get("cache_after", {}).get("answers", []) for row in trials)
    cache_after_legit = sum(LEGITIMATE_IP in row.get("cache_after", {}).get("answers", []) for row in trials)
    metrics: dict[str, Any] = {
        "schema_version": 1,
        "run_id": first.get("run_id"),
        "rep": first.get("rep"),
        "policy": policy,
        "workload": workload,
        "n_trials": n,
        "attack_workload": attack,
        "poison_trials": poison_trials,
        "run_asr": poison_trials / n if attack else None,
        "any_poison": bool(poison_trials),
        "first_trial_poison": bool(per_trial and per_trial[0]["poisoned"]),
        "legitimate_trials": legit_trials,
        "legitimate_answer_rate": legit_trials / n,
        "noanswer_trials": noanswer_trials,
        "noanswer_rate": noanswer_trials / n,
        "trigger_trials": trigger_trials,
        "trigger_rate": trigger_trials / n,
        "b5_reconstruction_available": bool(reconstructed_states),
        "b5_reconstructed_state_count": len(reconstructed_states),
        "b5_reconstructed_trigger_count": len(reconstructed_triggers),
        "b5_runtime_trigger_count": len(runtime_triggers),
        "b5_trigger_mismatch": bool(reconstructed_states) and len(reconstructed_triggers) != len(runtime_triggers),
        "forged_tail_ingress_trials": forged_ingress_trials,
        "forged_tail_ingress_rate": forged_ingress_trials / n,
        "forged_tail_drop_trials": forged_drop_trials,
        "forged_tail_drop_rate": forged_drop_trials / n,
        "tc_injection_trials": tc_trials,
        "tc_injection_rate": tc_trials / n,
        "tcp_retry_trials": tcp_trials,
        "tcp_retry_rate": tcp_trials / n,
        "cache_before_hits": cache_before_hits,
        "cache_after_poison_trials": cache_after_poison,
        "cache_after_legitimate_trials": cache_after_legit,
        "latency_median_ms": statistics.median(latencies) if latencies else None,
        "latency_p95_ms": _quantile(latencies, 0.95),
        "latency_p99_ms": _quantile(latencies, 0.99),
        "status_counts": dict(Counter(str(row.get("status")) for row in trials)),
        "root_cause_counts": dict(root_causes),
        "per_trial": per_trial,
        "cache_probe_rows": len(cache),
        "ips_event_rows": len(ips),
        "auth_event_rows": len(auth),
        "attacker_event_rows": len(attacker),
    }
    return metrics
