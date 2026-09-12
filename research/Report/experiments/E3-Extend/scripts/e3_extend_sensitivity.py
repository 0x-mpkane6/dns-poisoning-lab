#!/usr/bin/env python3
"""Score the E3-Extend post-hoc grid on E3 validation only; never select a threshold."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import itertools
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
REQUIRED_COLUMNS = {
    "source_e2_split", "e3_split", "profile", "condition", "role", "level", "pair_id",
    "arrival_schedule_sha256", "query_schedule_sha256", "query_idx", "samples", "entropy",
    "unique_ratio", "block_volume",
}
TRACE_FIELDS = ("source_e2_split", "profile", "level", "pair_id", "arrival_schedule_sha256", "query_schedule_sha256")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def csv_bool(value: str) -> bool:
    if value not in {"0", "1"}:
        raise ValueError(f"Expected binary detector flag, got {value!r}")
    return value == "1"


def trace_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[field] for field in TRACE_FIELDS)


def new_b5_block(row: dict[str, str], candidate: tuple[int, float, float]) -> bool:
    n, h, u = candidate
    return int(row["samples"]) >= n and float(row["entropy"]) >= h and float(row["unique_ratio"]) >= u


def pair_metrics(attack_rows: list[dict[str, str]], benign_rows: list[dict[str, str]], candidate: tuple[int, float, float]) -> dict[str, float]:
    if len(attack_rows) != len(benign_rows):
        raise ValueError("Paired traces have different decision counts")
    attack_index = [row["query_idx"] for row in attack_rows]
    benign_index = [row["query_idx"] for row in benign_rows]
    if attack_index != benign_index:
        raise ValueError("Paired traces have different query_idx sequences")
    new_attack = fmean(new_b5_block(row, candidate) for row in attack_rows)
    new_benign = fmean(new_b5_block(row, candidate) for row in benign_rows)
    b2_attack = fmean(csv_bool(row["block_volume"]) for row in attack_rows)
    b2_benign = fmean(csv_bool(row["block_volume"]) for row in benign_rows)
    new_j, b2_j = new_attack - new_benign, b2_attack - b2_benign
    return {
        "attack_alert_rate": new_attack,
        "benign_trigger_rate": new_benign,
        "FNR": 1.0 - new_attack,
        "balanced_precision": (new_attack + 1.0 - new_benign) / 2.0,
        "J": new_j,
        "B2_J": b2_j,
        "delta_J_new_vs_B2": new_j - b2_j,
    }


def summarize_cell(traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]], attack: str, benign: str, level: int, candidate: tuple[int, float, float], expected_decisions: int) -> dict[str, Any]:
    values: list[dict[str, float]] = []
    for key, conditions in sorted(traces.items()):
        if int(key[2]) != level or attack not in conditions:
            continue
        if benign not in conditions:
            raise ValueError(f"Missing paired benign trace for {attack}: {key}")
        if len(conditions[attack]) != expected_decisions or len(conditions[benign]) != expected_decisions:
            raise ValueError(f"Expected {expected_decisions} decisions per condition-trace: {key}")
        values.append(pair_metrics(conditions[attack], conditions[benign], candidate))
    if not values:
        raise ValueError(f"No paired traces for {attack} at level {level}")
    return {"attack_condition": attack, "benign_condition": benign, "level": level, "n_pairs": len(values), **{metric: fmean(item[metric] for item in values) for metric in values[0]}}


def macro(cells: list[dict[str, Any]]) -> dict[str, float]:
    names = ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J", "B2_J", "delta_J_new_vs_B2")
    return {name: fmean(float(cell[name]) for cell in cells) for name in names}


def load_traces(validation: Path, expected_rows: int) -> tuple[dict[tuple[str, ...], dict[str, list[dict[str, str]]]], int]:
    traces: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    rows_read = 0
    with gzip.open(validation, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Validation schema missing: {', '.join(sorted(missing))}")
        for row in reader:
            if row["e3_split"] != "validation":
                raise ValueError(f"Non-validation row found: {row['e3_split']!r}")
            traces[trace_key(row)][row["condition"]].append(row)
            rows_read += 1
    if rows_read != expected_rows:
        raise ValueError(f"Expected {expected_rows} rows, read {rows_read}")
    for conditions in traces.values():
        for rows in conditions.values():
            rows.sort(key=lambda row: int(row["query_idx"]))
    return traces, rows_read


def evaluate(protocol: dict[str, Any], validation: Path) -> dict[str, Any]:
    input_spec = protocol["decision_level_input"]
    traces, rows_read = load_traces(validation, int(input_spec["expected_rows"]))
    if len(traces) != int(input_spec["expected_paired_traces"]):
        raise ValueError(f"Expected {input_spec['expected_paired_traces']} paired traces, found {len(traces)}")
    grid_spec, analysis = protocol["candidate_grid"], protocol["analysis"]
    grid = list(itertools.product(grid_spec["min_samples"], grid_spec["entropy_threshold"], grid_spec["unique_ratio_threshold"]))
    if len(grid) != int(grid_spec["total_candidates"]) or len(set(grid)) != len(grid):
        raise ValueError("Post-hoc grid is not the registered 16 unique candidates")
    expected_decisions = int(input_spec["decisions_per_condition_trace"])
    primary_mapping = analysis["matching_benign_conditions"]
    levels = analysis["levels"]
    candidates = []
    for candidate in grid:
        primary = [summarize_cell(traces, attack, benign, level, candidate, expected_decisions) for attack, benign in primary_mapping.items() for level in levels]
        negative = [summarize_cell(traces, analysis["secondary_reporting"]["negative_control"], "benign_continuous", level, candidate, expected_decisions) for level in levels]
        probes = {attack: [summarize_cell(traces, attack, "benign_continuous", level, candidate, expected_decisions) for level in levels] for attack in analysis["secondary_reporting"]["failure_probes"]}
        candidates.append({"candidate": {"min_samples": candidate[0], "entropy_threshold": candidate[1], "unique_ratio_threshold": candidate[2]}, "primary": {"macro": macro(primary), "cells": primary}, "secondary_reports": {"negative_control": negative, "failure_probes": probes}})
    return {"rows_read": rows_read, "paired_traces": len(traces), "candidates": candidates}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=ROOT / "e3_extend_protocol.json")
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--csv-output", type=Path, default=ROOT / "e3_extend_sensitivity_grid.csv")
    parser.add_argument("--json-output", type=Path, default=ROOT / "e3_extend_sensitivity_grid.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    protocol = load_json(args.protocol)
    if protocol.get("classification") != "post_hoc_descriptive_sensitivity_analysis":
        raise SystemExit("Protocol is not explicitly post-hoc descriptive")
    policy = protocol.get("data_access_policy", {})
    if policy.get("held_out_test_access_by_this_extension") is not False or policy.get("allowed_decision_level_input") != "validation.csv.gz only":
        raise SystemExit("Protocol data-access guard is invalid")
    expected = (args.protocol.parent / protocol["decision_level_input"]["permitted_file"]).resolve()
    validation = (args.validation or expected).resolve()
    if validation != expected or validation.name != "validation.csv.gz":
        raise SystemExit("E3-Extend only accepts the protocol-pinned E3 validation.csv.gz")
    if not validation.is_file() or sha256_file(validation) != protocol["decision_level_input"]["sha256"]:
        raise SystemExit("Validation input is missing or does not match the pinned SHA-256")
    result = evaluate(protocol, validation)
    result.update({
        "schema_version": 1,
        "experiment": protocol["experiment"],
        "status": "post_hoc_validation_sensitivity_complete_no_selection",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "classification": protocol["classification"],
        "protocol": {"path": str(args.protocol), "sha256": sha256_file(args.protocol)},
        "validation_input": {"path": str(validation), "sha256": sha256_file(validation)},
        "data_access_policy": {"opened_decision_dataset": str(validation), "held_out_test_csv_opened": False, "selection_performed": False, "threshold_locked": False},
        "interpretation": "Descriptive post-hoc validation sensitivity only. No candidate is ranked, selected, locked, or evaluated on held-out data.",
    })
    args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fields = ["min_samples", "entropy_threshold", "unique_ratio_threshold", "primary_cell_count", "macro_attack_alert_rate", "macro_benign_trigger_rate", "macro_FNR", "macro_balanced_precision", "macro_J", "macro_B2_J", "macro_delta_J_new_vs_B2"]
    with args.csv_output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for entry in result["candidates"]:
            values = entry["primary"]["macro"]
            writer.writerow({**entry["candidate"], "primary_cell_count": len(entry["primary"]["cells"]), **{f"macro_{key}": values[key] for key in ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J", "B2_J", "delta_J_new_vs_B2")}})
    print(f"E3-Extend complete: {len(result['candidates'])} post-hoc candidates; no selection; held-out not opened.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
