#!/usr/bin/env python3
"""Independently audit E3-Extend's validation-only, post-hoc sensitivity output."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from e3_extend_sensitivity import evaluate, load_json, sha256_file


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
TOLERANCE = 1e-12


def close(left: float, right: float) -> bool:
    return math.isclose(float(left), float(right), abs_tol=TOLERANCE, rel_tol=0.0)


def add_check(checks: list[dict[str, Any]], name: str, passed: bool, details: Any, critical: bool = True) -> None:
    checks.append({"name": name, "status": "PASS" if passed else "FAIL", "critical": critical, "details": details})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=ROOT / "e3_extend_protocol.json")
    parser.add_argument("--grid", type=Path, default=ROOT / "e3_extend_sensitivity_grid.json")
    parser.add_argument("--grid-csv", type=Path, default=ROOT / "e3_extend_sensitivity_grid.csv")
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "e3_extend_validation.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checks: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": 1,
        "experiment": "E3-Extend independent artifact audit",
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checks": checks,
        "audit_scope": "Validation-only replay of post-hoc descriptive sensitivity analysis; no selection, lock, or held-out access.",
    }
    try:
        protocol, observed = load_json(args.protocol), load_json(args.grid)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add_check(checks, "required_artifacts_readable", False, str(exc))
        report.update({"status": "FAIL", "critical_failures": ["required_artifacts_readable"]})
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    expected_validation = (args.protocol.parent / protocol["decision_level_input"]["permitted_file"]).resolve()
    validation = (args.validation or expected_validation).resolve()
    add_check(checks, "post_hoc_protocol_and_access_guard", protocol.get("classification") == "post_hoc_descriptive_sensitivity_analysis"
              and protocol.get("data_access_policy", {}).get("held_out_test_access_by_this_extension") is False
              and protocol.get("analysis", {}).get("ranking_or_selection") == "forbidden"
              and protocol.get("analysis", {}).get("threshold_lock") == "forbidden"
              and protocol.get("analysis", {}).get("held_out_evaluation") == "forbidden",
              {"classification": protocol.get("classification"), "policy": protocol.get("data_access_policy")})
    add_check(checks, "only_protocol_pinned_validation_is_accepted", validation == expected_validation and validation.name == "validation.csv.gz"
              and validation.is_file() and sha256_file(validation) == protocol["decision_level_input"]["sha256"],
              {"validation": str(validation), "expected": str(expected_validation), "sha256": sha256_file(validation) if validation.is_file() else None})
    add_check(checks, "output_provenance_and_no_selection", observed.get("protocol", {}).get("sha256") == sha256_file(args.protocol)
              and observed.get("validation_input", {}).get("sha256") == protocol["decision_level_input"]["sha256"]
              and observed.get("data_access_policy", {}).get("held_out_test_csv_opened") is False
              and observed.get("data_access_policy", {}).get("selection_performed") is False
              and observed.get("data_access_policy", {}).get("threshold_locked") is False,
              observed.get("data_access_policy"))

    candidate_spec = protocol["candidate_grid"]
    expected_keys = {(n, h, u) for n in candidate_spec["min_samples"] for h in candidate_spec["entropy_threshold"] for u in candidate_spec["unique_ratio_threshold"]}
    observed_candidates = observed.get("candidates", [])
    observed_keys = {(item["candidate"]["min_samples"], item["candidate"]["entropy_threshold"], item["candidate"]["unique_ratio_threshold"]) for item in observed_candidates}
    add_check(checks, "complete_16_candidate_post_hoc_grid", len(observed_candidates) == 16 and observed_keys == expected_keys,
              {"expected_count": 16, "observed_count": len(observed_candidates), "unique_count": len(observed_keys)})
    add_check(checks, "primary_cells_and_validation_shape", observed.get("rows_read") == 27600 and observed.get("paired_traces") == 64
              and all(len(item.get("primary", {}).get("cells", [])) == 8 for item in observed_candidates)
              and all(cell.get("n_pairs") == 6 for item in observed_candidates for cell in item.get("primary", {}).get("cells", [])),
              {"rows_read": observed.get("rows_read"), "paired_traces": observed.get("paired_traces")})

    try:
        recomputed = evaluate(protocol, validation)
        recomputed_by_key = {(item["candidate"]["min_samples"], item["candidate"]["entropy_threshold"], item["candidate"]["unique_ratio_threshold"]): item for item in recomputed["candidates"]}
        output_matches = True
        metrics = ("attack_alert_rate", "benign_trigger_rate", "FNR", "balanced_precision", "J", "B2_J", "delta_J_new_vs_B2")
        def same_cells(actual_cells: list[dict[str, Any]], expected_cells: list[dict[str, Any]]) -> bool:
            return len(actual_cells) == len(expected_cells) and all(
                all(close(actual[metric], expected[metric]) for metric in metrics)
                for actual, expected in zip(actual_cells, expected_cells)
            )

        for item in observed_candidates:
            key = (item["candidate"]["min_samples"], item["candidate"]["entropy_threshold"], item["candidate"]["unique_ratio_threshold"])
            expected = recomputed_by_key.get(key)
            if expected is None:
                output_matches = False
                break
            if not same_cells(item["primary"]["cells"], expected["primary"]["cells"]):
                output_matches = False
                break
            if any(not close(item["primary"]["macro"][metric], expected["primary"]["macro"][metric]) for metric in metrics):
                output_matches = False
                break
            actual_secondary, expected_secondary = item["secondary_reports"], expected["secondary_reports"]
            if not same_cells(actual_secondary["negative_control"], expected_secondary["negative_control"]):
                output_matches = False
                break
            if set(actual_secondary["failure_probes"]) != set(expected_secondary["failure_probes"]):
                output_matches = False
                break
            if any(not same_cells(actual_secondary["failure_probes"][name], expected_secondary["failure_probes"][name]) for name in expected_secondary["failure_probes"]):
                output_matches = False
                break
            if not output_matches:
                break
        add_check(checks, "all_primary_and_secondary_metrics_recompute_exactly_from_validation", output_matches,
                  {"metrics": list(metrics), "tolerance": TOLERANCE})
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        add_check(checks, "all_primary_and_secondary_metrics_recompute_exactly_from_validation", False, str(exc))

    try:
        with args.grid_csv.open(encoding="utf-8", newline="") as handle:
            csv_rows = list(csv.DictReader(handle))
        csv_keys = {(int(row["min_samples"]), float(row["entropy_threshold"]), float(row["unique_ratio_threshold"])) for row in csv_rows}
        json_by_key = {(item["candidate"]["min_samples"], item["candidate"]["entropy_threshold"], item["candidate"]["unique_ratio_threshold"]): item for item in observed_candidates}
        csv_matches = len(csv_rows) == 16 and csv_keys == observed_keys and all(
            close(float(row["macro_delta_J_new_vs_B2"]), json_by_key[(int(row["min_samples"]), float(row["entropy_threshold"]), float(row["unique_ratio_threshold"]))]["primary"]["macro"]["delta_J_new_vs_B2"])
            for row in csv_rows
        )
        add_check(checks, "csv_has_complete_grid_and_matches_json_delta_J", csv_matches,
                  {"csv_rows": len(csv_rows), "csv_unique_candidates": len(csv_keys)})
    except (OSError, KeyError, ValueError, csv.Error) as exc:
        add_check(checks, "csv_has_complete_grid_and_matches_json_delta_J", False, str(exc))

    add_check(checks, "asr_remains_not_measured", "not measured" in protocol.get("interpretation_guardrails", {}).get("asr", "").lower()
              and "not ASR" in protocol.get("interpretation_guardrails", {}).get("asr", ""),
              protocol.get("interpretation_guardrails", {}).get("asr"))
    failures = [item["name"] for item in checks if item["critical"] and item["status"] == "FAIL"]
    report.update({"status": "PASS" if not failures else "FAIL", "critical_failures": failures, "artifact_hashes": {"protocol": sha256_file(args.protocol), "validation": sha256_file(validation), "grid": sha256_file(args.grid), "grid_csv": sha256_file(args.grid_csv)}})
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"E3-Extend audit {report['status']}: {len(checks) - len(failures)}/{len(checks)} checks passed.")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
