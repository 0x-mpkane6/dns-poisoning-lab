#!/usr/bin/env python3
"""Integrity checks for event/tick Unbound logs; adverse outcomes remain data."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import re
import statistics
import struct
from collections import Counter, deque
from pathlib import Path


def json_file(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q / 100
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] * (high - rank) + ordered[high] * (rank - low) if high != low else ordered[low]


def rebuild_windows(events: list[dict], decisions: list[dict], window: float) -> list[str]:
    errors = []
    queue = deque()
    pointer = 0
    for index, row in enumerate(decisions):
        now = row["mono_s"]
        while pointer < len(events) and events[pointer]["mono_s"] <= now:
            queue.append(events[pointer])
            pointer += 1
        while queue and queue[0]["mono_s"] < now - window:
            queue.popleft()
        counts = Counter(event["ipid"] for event in queue)
        n = len(queue)
        h = -sum((count / n) * math.log2(count / n) for count in counts.values()) if n else 0.0
        u = len(counts) / n if n else 0.0
        if n != row["samples"] or len(counts) != row["unique_ipids"] or abs(h - row["entropy"]) > 1e-9 or abs(u - row["unique_ratio"]) > 1e-9:
            errors.append(f"window {index}: raw n/H/U={n}/{h}/{u}; logged={row['samples']}/{row['entropy']}/{row['unique_ratio']}")
    return errors


def pcap_summary(path: Path) -> dict:
    counts = Counter()
    sources = Counter()
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24 or header[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("missing or unsupported PCAP header")
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        if struct.unpack(endian + "I", header[20:24])[0] != 1:
            raise ValueError("expected Ethernet PCAP")
        while record := handle.read(16):
            if len(record) != 16:
                raise ValueError("truncated PCAP record header")
            _, _, captured, original = struct.unpack(endian + "IIII", record)
            if captured > 65535:
                raise ValueError("invalid captured packet length")
            packet = handle.read(captured)
            if len(packet) != captured:
                raise ValueError("truncated PCAP packet")
            counts["packets"] += 1
            counts["truncated_packets"] += captured < original
            if len(packet) < 34 or packet[12:14] != b"\x08\x00":
                continue
            ip = packet[14:]
            counts["ipv4_packets"] += 1
            flags_offset = int.from_bytes(ip[6:8], "big")
            if flags_offset & 0x1FFF:
                counts["noninitial_ipv4_fragments"] += 1
                sources[".".join(str(value) for value in ip[12:16])] += 1
            if flags_offset & 0x2000:
                counts["more_fragment_packets"] += 1
    return {**counts, "fragment_sources": dict(sources)}


def validate_run(root: Path, metrics: dict, protocol: dict) -> dict:
    out = root / metrics["artifact_dir"]
    checks = []

    def check(name: str, passed: bool, detail="") -> None:
        checks.append({"name": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    try:
        answers = (out / "result.txt").read_text(encoding="utf-8").splitlines()
        with (out / "rounds.tsv").open(encoding="utf-8", newline="") as handle:
            rounds = list(csv.DictReader(handle, delimiter="\t"))
        with (out / "trigger_raw.tsv").open(encoding="utf-8", newline="") as handle:
            raw_trigger = list(csv.DictReader(handle, delimiter="\t"))
        expected = protocol["rounds_per_run"]
        check("complete_rounds", len(answers) == len(rounds) == len(raw_trigger) == expected, f"{len(answers)}/{len(rounds)}/{len(raw_trigger)}")
        check("valid_answers", all(answer in {"6.6.6.6", "203.0.113.80", "NOANSWER"} for answer in answers))
        check("bank_raw_matches_table", answers == [row["bank_ip"] for row in rounds])
        check("unique_queries", len({row["qname"] for row in rounds}) == expected)
        check("round_numbers", [int(row["round"]) for row in rounds] == list(range(1, expected + 1)))
        check("asr_reconstructed", abs(answers.count("6.6.6.6") / len(answers) - metrics["run_asr"]) < 1e-12)
        check("poison_count", answers.count("6.6.6.6") == metrics["poisoned"])
        check("noanswer_count", answers.count("NOANSWER") == metrics["noanswer"])
        check("client_completed", metrics["client_exit_code"] == 0)
        raw_ok = True
        for logged, raw in zip(rounds, raw_trigger):
            base64.b64decode(raw["output_b64"], validate=True).decode("utf-8")
            raw_ok &= all(logged[key] == raw[key] for key in ("round", "qname", "trigger_status", "trigger_rc"))
        check("trigger_evidence_matches", raw_ok)
        for filename, column, prefix in (("trigger_latency_ms.txt", "trigger_ms", "trigger_command"),
                                         ("bank_latency_ms.txt", "bank_ms", "bank_lookup")):
            values = [float(line) for line in (out / filename).read_text(encoding="utf-8").splitlines()]
            check(prefix + "_latency_count", len(values) == expected)
            check(prefix + "_latency_finite", all(math.isfinite(value) and value >= 0 for value in values))
            check(prefix + "_latency_table", values == [float(row[column]) for row in rounds])
            for q in (50, 95, 99):
                check(f"{prefix}_p{q}", abs(percentile(values, q) - metrics[f"{prefix}_latency_p{q}_ms"]) < 1e-9)

        interval = json_file(out / "measurement.json")
        start, end = interval["start_mono_s"], interval["end_mono_s"]
        check("measurement_interval", math.isfinite(start) and math.isfinite(end) and end > start)
        all_decisions = json_lines(out / "r2_decisions.jsonl")
        events = json_lines(out / "frag2_events.jsonl")
        for label, rows in (("decision", all_decisions), ("event", events)):
            check(label + "_monotonic", all(b["mono_s"] >= a["mono_s"] for a, b in zip(rows, rows[1:])))
        check("decision_sequence", [row["decision_seq"] for row in all_decisions] == list(range(1, len(all_decisions) + 1)))
        decisions = [row for row in all_decisions if start <= row["mono_s"] <= end]
        check("measured_decisions_present", len(decisions) > 0)
        check("decision_counts", len(decisions) == metrics["n_decisions"] and len(all_decisions) == metrics["n_decisions_all"])
        check("real_fragment_events", bool(events) and all(row["offset"] > 0 for row in events))
        locked = protocol["locked_operating_point"]
        check("locked_thresholds", all(all(row[key] == value for key, value in locked.items()) and row["window_seconds"] == protocol["window_seconds"] for row in decisions))
        expected_defense = metrics["case_id"] != "C0_attack_flood_b0"
        check("defense_config", all(row["defense_on"] == expected_defense for row in decisions))
        check("rule_logic", all((row["action"] == "tc_block") == (row["defense_on"] and row["samples"] >= 8 and row["entropy"] >= 6.0 and row["unique_ratio"] >= 0.9) for row in decisions))
        check("enforcement_status", all(row["enforcement_ok"] and row["rule_installed"] == row["drop_requested"] for row in decisions))
        enforcement = json_lines(out / "enforcement.jsonl")
        check("enforcement_commands", all(row["ok"] for row in enforcement), f"transitions={len(enforcement)}")
        check("trigger_reconstructed", abs(sum(row["action"] == "tc_block" for row in decisions) / len(decisions) - metrics["trigger_rate"]) < 1e-12)
        ticks = [row for row in decisions if row["reason"] == "tick"]
        check("tick_coverage", len(ticks) >= max(1, int((end - start) / 0.25 * 0.5)), f"ticks={len(ticks)} duration={end-start:.3f}")
        check("tick_rate_reconstructed", bool(ticks) and abs(sum(row["action"] == "tc_block" for row in ticks) / len(ticks) - metrics["tick_trigger_rate"]) < 1e-12)
        discrepancies = rebuild_windows(events, decisions, protocol["window_seconds"])
        check("windows_reconstructed", not discrepancies, discrepancies[:5])
        for field, logged_key in (("samples", "mean_samples"), ("entropy", "mean_entropy"), ("unique_ratio", "mean_unique_ratio")):
            check(field + "_mean", abs(statistics.fmean(row[field] for row in decisions) - metrics[logged_key]) < 1e-9)
        processes = (out / "attacker_processes.txt").read_text(encoding="utf-8")
        occupancy_workers = sum("sender.py --role occupancy" in line for line in processes.splitlines())
        check("one_occupancy_sender", occupancy_workers == (0 if metrics["case_id"] == "C0_attack_flood_b0" else 1), str(occupancy_workers))
        stats = json_file(out / "docker_stats.json")
        check("resource_samples", bool(stats))
        for source, mean_key, max_key in (("cpu_percent", "cpu_percent_mean", "cpu_percent_max"), ("memory_mib", "memory_mib_mean", "memory_mib_max")):
            values = [row[source] for row in stats]
            check(source + "_reconstructed", bool(values) and abs(statistics.fmean(values) - metrics[mean_key]) < 1e-9 and max(values) == metrics[max_key])
    except (OSError, ValueError, KeyError, ZeroDivisionError, TypeError) as exc:
        check("raw_parse", False, repr(exc))
    failed = [row for row in checks if row["status"] == "FAIL"]
    return {"status": "FAIL" if failed else "PASS", "n_checks": len(checks), "n_fail": len(failed), "failed": failed, "checks": checks}


def validate_stage(root: Path, stage: str) -> dict:
    protocol = json_file(root / "e5_protocol.json")
    rows = json_file(root / f"metrics_{stage}.json")
    reports = [{"case_id": row["case_id"], "rep": row["rep"], **validate_run(root, row, protocol)} for row in rows]
    issues = []
    k = 1 if stage == "sanity" else protocol["k_runs_per_case"]
    expected_reps = {0} if stage == "sanity" else set(range(1, k + 1))
    groups = {case: [row for row in rows if row["case_id"] == case] for case in protocol["case_ids"]}
    for case, items in groups.items():
        if len(items) != k or {row["rep"] for row in items} != expected_reps:
            issues.append(f"missing/duplicate repetitions: {case}")
    if [dict(case_id=row["case_id"], rep=row["rep"]) for row in rows] != json_file(root / f"schedule_{stage}.json"):
        issues.append("recorded order differs from registered schedule")
    if any(report["status"] != "PASS" for report in reports):
        issues.append("one or more raw-run integrity checks failed")
    for case in ("C0_attack_flood_b0",):
        if not any(row["poisoned"] > 0 for row in groups[case]):
            issues.append(f"positive control absent: {case}")
    occupancy = {}
    for case in ("C2_benign_boundary", "C3_attack_matched"):
        occupancy[case] = statistics.fmean(row["mean_samples"] for row in groups[case]) if groups[case] else 0
    a, b = occupancy.values()
    relative = abs(a - b) / ((a + b) / 2) if a + b else 1
    if relative > protocol["sanity"]["occupancy_relative_difference_max"]:
        issues.append("C2/C3 measured occupancy relative difference exceeds registered bound")
    hashes = json_file(root / "provenance.json")["file_sha256"]
    for name, expected in hashes.items():
        path = root / "source_snapshot" / name
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            issues.append(f"source snapshot hash mismatch: {name}")
    return {"status": "FAIL" if issues else "PASS", "stage": stage, "runs": len(rows),
            "n_checks": sum(report["n_checks"] for report in reports),
            "n_fail": sum(report["n_fail"] for report in reports), "issues": issues,
            "occupancy": {**occupancy, "relative_difference": relative},
            "negative_outcomes_are_integrity_failures": False, "run_checks": reports}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root", type=Path)
    parser.add_argument("--stage", choices=("sanity", "confirmatory"), default="confirmatory")
    args = parser.parse_args()
    result = validate_stage(args.run_root, args.stage)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
