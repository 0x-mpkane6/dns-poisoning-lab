"""Integrity and engineering gates for E5-v2 raw artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from e5_v2_analysis import read_jsonl


IDENTITY_FIELDS = ("run_id", "rep", "policy", "workload", "mono_ns", "wall_ns")
REQUIRED_LOGS = (
    "trials.jsonl",
    "client_events.jsonl",
    "auth_events.jsonl",
    "attacker_events.jsonl",
    "ips_events.jsonl",
    "unbound_events.jsonl",
    "cache_events.jsonl",
    "unbound_version.txt",
    "firewall_before.rules",
    "firewall_after.rules",
    "ips_inside.pcapng",
    "ips_outside.pcapng",
    "metrics.json",
    "resource_samples.jsonl",
)


def validate_trial_records(
    rows: list[dict[str, Any]],
    *,
    expected_trials: int,
    expected_qnames: Iterable[str] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    if len(rows) != expected_trials:
        errors.append(f"expected {expected_trials} trial rows, found {len(rows)}")
    qnames = [row.get("qname") for row in rows]
    if any(not isinstance(qname, str) for qname in qnames):
        errors.append("every trial is missing qname")
    if len(set(qnames)) != len(qnames):
        errors.append("duplicate qname in trial records")
    trial_ids = [row.get("trial_id") for row in rows]
    if len(set(trial_ids)) != len(trial_ids):
        errors.append("duplicate trial_id in trial records")
    expected = list(expected_qnames or [])
    if expected and set(qnames) != set(expected):
        errors.append("trial qnames do not match the registered replay schedule")
    for index, row in enumerate(rows):
        if not row.get("trial_id"):
            errors.append(f"trial {index} is missing trial_id")
        before = row.get("cache_before")
        after = row.get("cache_after")
        if not isinstance(before, dict) or "cache_hit" not in before:
            errors.append(f"trial {index} is missing cache-before result")
        elif bool(before.get("cache_hit")):
            errors.append(f"trial {index} has cache-before hit")
        if not isinstance(after, dict) or "cache_hit" not in after:
            errors.append(f"trial {index} is missing cache-after result")
        if "query_start_mono_ns" not in row or "client_answer_end_mono_ns" not in row:
            errors.append(f"trial {index} is missing client event timestamps")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "n_trials": len(rows)}


def _event_identity_errors(rows: list[dict[str, Any]], expected: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for index, row in enumerate(rows):
        for field in IDENTITY_FIELDS:
            if field not in row:
                errors.append(f"event row {index} missing {field}")
        for field in ("run_id", "policy", "workload"):
            if field in row and row[field] != expected[field]:
                errors.append(f"event row {index} has inconsistent {field}")
        if "rep" in row and int(row["rep"]) != int(expected["rep"]):
            errors.append(f"event row {index} has inconsistent rep")
    return errors


def _has_nonzero_nfqueue_counter(text: str) -> bool:
    return any(int(packet_count) > 0 for packet_count in re.findall(r"\[(\d+):\d+\]", text))


def _pcapng(path: Path) -> bool:
    try:
        payload = path.read_bytes()
        # Section + interface headers alone are not evidence of a capture;
        # require room for at least one packet block as well.
        return payload[:4] == b"\x0a\x0d\x0d\x0a" and len(payload) > 128
    except OSError:
        return False


def validate_run(
    run_dir: Path,
    *,
    expected: dict[str, Any],
    expected_qnames: Iterable[str] | None = None,
    expected_trials: int,
    require_pcap: bool = True,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    missing = [name for name in REQUIRED_LOGS if not (run_dir / name).exists()]
    errors.extend(f"missing artifact: {name}" for name in missing)
    if not missing:
        trial_rows = read_jsonl(run_dir / "trials.jsonl")
        trial_check = validate_trial_records(trial_rows, expected_trials=expected_trials, expected_qnames=expected_qnames)
        errors.extend(trial_check["errors"])
        log_rows = {
            name: read_jsonl(run_dir / name)
            for name in ("client_events.jsonl", "auth_events.jsonl", "attacker_events.jsonl", "ips_events.jsonl", "unbound_events.jsonl", "cache_events.jsonl")
        }
        for name, rows in log_rows.items():
            errors.extend(f"{name}: {error}" for error in _event_identity_errors(rows, expected))
        if not any(row.get("event") == "fragment_observed" for row in log_rows["ips_events.jsonl"]):
            errors.append("IPS raw fragment observation log is empty")
        trial_ids = {row.get("trial_id") for row in trial_rows}
        for trial_id in trial_ids:
            if not trial_id:
                continue
            for name in ("auth_events.jsonl", "ips_events.jsonl", "cache_events.jsonl"):
                if not any(row.get("trial_id") == trial_id for row in log_rows[name]):
                    errors.append(f"{trial_id}: missing {name} event mapping")
            for phase in ("before", "after"):
                if not any(row.get("event") == f"cache_{phase}" and row.get("trial_id") == trial_id for row in log_rows["cache_events.jsonl"]):
                    errors.append(f"{trial_id}: missing cache_{phase} event")
            if not any(row.get("event") == "client_query_send" and row.get("trial_id") == trial_id for row in log_rows["client_events.jsonl"]):
                errors.append(f"{trial_id}: missing client query event")
            if not any(row.get("event") == "client_answer_receive" and row.get("trial_id") == trial_id for row in log_rows["client_events.jsonl"]):
                errors.append(f"{trial_id}: missing client answer event")
            if not any(row.get("event") == "udp_receive" and row.get("trial_id") == trial_id for row in log_rows["auth_events.jsonl"]):
                errors.append(f"{trial_id}: missing auth UDP receive")
            if not any(row.get("event") == "packet_ingress" and row.get("trial_id") == trial_id for row in log_rows["ips_events.jsonl"]):
                errors.append(f"{trial_id}: missing IPS packet ingress")
        if expected["workload"].startswith("ATTACK_"):
            if not any(row.get("event") == "forged_tail_send" for row in log_rows["attacker_events.jsonl"]):
                errors.append("attack workload has no external forged-tail send evidence")
        elif any(row.get("event") == "forged_tail_send" for row in log_rows["attacker_events.jsonl"]):
            errors.append("benign workload contains an unexpected forged-tail send")

        ready_path = run_dir / "ips_ready.json"
        if ready_path.exists():
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            if ready.get("queue_num") != 5:
                errors.append("IPS ready record does not use NFQUEUE 5")
            for key, value in (("min_samples", 8), ("entropy_threshold", 6.0), ("unique_ratio_threshold", 0.90), ("window_seconds", 2.0)):
                if ready.get(key) != value:
                    errors.append(f"IPS ready record has unlocked/mismatched {key}")
        else:
            errors.append("missing IPS ready record")
        for firewall_name in ("firewall_before.rules", "firewall_after.rules"):
            firewall = (run_dir / firewall_name).read_text(encoding="utf-8", errors="replace") if (run_dir / firewall_name).exists() else ""
            if "NFQUEUE" not in firewall or "--queue-num 5" not in firewall:
                errors.append(f"{firewall_name} does not prove NFQUEUE queue 5")
            if "queue-bypass" in firewall:
                errors.append(f"{firewall_name} contains forbidden NFQUEUE fallback")
            if firewall_name.endswith("after.rules") and not _has_nonzero_nfqueue_counter(firewall):
                errors.append("NFQUEUE/firewall counters did not increase")
            if "raw" not in firewall.lower() or "PREROUTING" not in firewall:
                errors.append(f"{firewall_name} does not preserve raw pre-defragmentation visibility")
        version_text = (run_dir / "unbound_version.txt").read_text(encoding="utf-8", errors="replace")
        if "1.26.1" not in version_text:
            errors.append("resolver is not the registered Unbound 1.26.1 build")
        try:
            metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
            if metrics.get("b5_trigger_mismatch"):
                errors.append("independent B5 window reconstruction disagrees with detector trigger log")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"metrics.json cannot be read: {exc}")
    if require_pcap:
        for pcap in (run_dir / "ips_inside.pcapng", run_dir / "ips_outside.pcapng"):
            if pcap.exists() and not _pcapng(pcap):
                errors.append(f"{pcap.name} is not a PCAPNG artifact")
    if (run_dir / "resource_samples.jsonl").exists() and not (run_dir / "resource_samples.jsonl").read_text(encoding="utf-8", errors="replace").strip():
        errors.append("runtime CPU/memory sample artifact is empty")
    if not (run_dir / "resolver_local_poisoner.present").exists():
        pass
    else:
        errors.append("resolver-local poisoner marker is present")
    return {
        "schema_version": 1,
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "run_dir": str(run_dir),
        "expected": expected,
    }


def pilot_gate(metrics: dict[str, Any], *, policy: str, workload: str) -> dict[str, Any]:
    """Engineering/root-cause acceptance checks; never used as an inference gate."""

    errors: list[str] = []
    if policy == "B0_OFF" and workload == "ATTACK_FIXED_MATCHED" and not metrics.get("any_poison"):
        errors.append("B0 positive-control attack did not poison")
    if policy == "PREARM_TAIL_DROP" and workload == "ATTACK_FIXED_MATCHED":
        if not metrics.get("forged_tail_ingress_trials"):
            errors.append("PREARM saw no forged-tail ingress")
        if not metrics.get("forged_tail_drop_trials"):
            errors.append("PREARM dropped no forged tail")
        if metrics.get("any_poison"):
            errors.append("PREARM forged tail reached a poisoned cache")
    if policy == "B1_RL2_TC":
        if not metrics.get("tc_injection_trials"):
            errors.append("B1 produced no TC injection")
        if not metrics.get("tcp_retry_trials"):
            errors.append("B1 produced no TCP retry")
        if workload == "BENIGN_BOUNDARY" and not metrics.get("legitimate_trials"):
            errors.append("B1 benign pilot produced no legitimate answer")
    if policy == "B5_LOCKED_TC" and workload == "ATTACK_SWEEP_FLOOD":
        if not metrics.get("trigger_trials"):
            errors.append("B5 flood pilot produced no detector trigger")
        if not metrics.get("forged_tail_drop_trials"):
            errors.append("B5 flood pilot produced no enforced drop")
    if policy == "RFC_DROP_NATIVE":
        if not metrics.get("forged_tail_drop_trials") and workload.startswith("ATTACK_"):
            errors.append("RFC attack pilot dropped no fragmented response")
        if metrics.get("tc_injection_trials"):
            errors.append("RFC pilot unexpectedly injected TC")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "policy": policy, "workload": workload}
