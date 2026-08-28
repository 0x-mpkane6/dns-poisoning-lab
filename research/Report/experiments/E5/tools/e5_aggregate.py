#!/usr/bin/env python3
"""Aggregate E5 run-level metrics with bootstrap and Wilson CIs. Do not treat rounds as IID."""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

E5_DIR = Path(__file__).resolve().parent.parent
PRIMARY = [
    "run_asr",
    "trigger_rate",
    "trigger_command_latency_p50_ms",
    "trigger_command_latency_p95_ms",
    "bank_lookup_latency_p50_ms",
    "bank_lookup_latency_p95_ms",
    "probe_rounds_per_s",
    "cpu_percent_mean",
    "cpu_percent_max",
    "memory_mib_mean",
    "memory_mib_max",
    "mean_samples",
    "mean_entropy",
    "mean_unique_ratio",
]


def bootstrap_ci(values: list[float], replicates: int = 5000, seed: int = 20260827) -> tuple[float, float]:
    finite = [value for value in values if value == value]
    if not finite:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    n = len(finite)
    means: list[float] = []
    for _ in range(replicates):
        sample = [finite[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo = means[int(0.025 * (replicates - 1))]
    hi = means[int(0.975 * (replicates - 1))]
    return lo, hi


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return float("nan"), float("nan")
    p = k / n
    z2 = z * z
    den = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / den
    margin = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)) / den
    return max(0.0, center - margin), min(1.0, center + margin)


def mean(values: list[float]) -> float:
    finite = [value for value in values if value == value]
    if not finite:
        return float("nan")
    return sum(finite) / len(finite)


def load_rows(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def gate_histogram(items: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        for gate in item.get("allow_failed_gates") or []:
            counts[str(gate)] += 1
    return dict(counts)


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["case_id"])].append(row)
    summary: list[dict[str, Any]] = []
    for case_id, items in grouped.items():
        n = len(items)
        any_poison = sum(1 for item in items if item.get("any_poison") or int(item.get("poisoned") or 0) > 0)
        any_false_trigger = sum(1 for item in items if int(item.get("n_tc_block") or 0) > 0)
        poison_lo, poison_hi = wilson_ci(any_poison, n)
        entry: dict[str, Any] = {
            "case_id": case_id,
            "n_runs": n,
            "defense": items[0].get("defense"),
            "control": items[0].get("control"),
            "allow_failed_gates": gate_histogram(items),
            "any_poison": {
                "k": any_poison,
                "n": n,
                "rate": any_poison / n if n else float("nan"),
                "wilson95_lo": poison_lo,
                "wilson95_hi": poison_hi,
            },
        }
        if case_id in {"C1_benign_low", "C2_benign_boundary"}:
            ft_lo, ft_hi = wilson_ci(any_false_trigger, n)
            entry["any_false_trigger"] = {
                "k": any_false_trigger,
                "n": n,
                "rate": any_false_trigger / n if n else float("nan"),
                "wilson95_lo": ft_lo,
                "wilson95_hi": ft_hi,
            }
        for key in PRIMARY:
            values = [float(item.get(key)) for item in items if item.get(key) is not None]
            lo, hi = bootstrap_ci(values)
            finite = [value for value in values if value == value]
            entry[key] = {
                "mean": mean(values),
                "ci95_lo": lo,
                "ci95_hi": hi,
                "min": min(finite, default=float("nan")),
                "max": max(finite, default=float("nan")),
            }
        summary.append(entry)
    order = [
        "C0_attack_flood_b0",
        "C1_benign_low",
        "C2_benign_boundary",
        "C3_attack_matched",
        "C4_attack_flood",
    ]
    summary.sort(key=lambda row: order.index(row["case_id"]) if row["case_id"] in order else 99)
    return summary


def write_csv(path: Path, summary: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "n_runs",
        "defense",
        "control",
        "any_poison_k",
        "any_poison_rate",
        "any_poison_wilson95_lo",
        "any_poison_wilson95_hi",
    ]
    for key in PRIMARY:
        fieldnames.extend([f"{key}_mean", f"{key}_ci95_lo", f"{key}_ci95_hi"])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            poison = row["any_poison"]
            flat = {
                "case_id": row["case_id"],
                "n_runs": row["n_runs"],
                "defense": row["defense"],
                "control": row["control"],
                "any_poison_k": poison["k"],
                "any_poison_rate": poison["rate"],
                "any_poison_wilson95_lo": poison["wilson95_lo"],
                "any_poison_wilson95_hi": poison["wilson95_hi"],
            }
            for key in PRIMARY:
                cell = row[key]
                flat[f"{key}_mean"] = cell["mean"]
                flat[f"{key}_ci95_lo"] = cell["ci95_lo"]
                flat[f"{key}_ci95_hi"] = cell["ci95_hi"]
            writer.writerow(flat)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="E5-unbound-supplement-20260828-s202608281")
    parser.add_argument("--stage", default="confirmatory")
    args = parser.parse_args()
    run_root = E5_DIR / "output" / args.run_id
    source = run_root / f"metrics_{args.stage}.json"
    if not source.exists():
        source = run_root / "metrics_all.json"
    loaded = load_rows(source)
    if args.stage != "all":
        rows = [row for row in loaded if row.get("stage") == args.stage]
        if not rows:
            rows = loaded
    else:
        rows = loaded
    summary = aggregate(rows)
    out_json = run_root / f"e5_summary_{args.stage}.json"
    out_csv = run_root / f"e5_summary_{args.stage}.csv"
    out_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_csv(out_csv, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"wrote {out_json}")
    print(f"wrote {out_csv}")


if __name__ == "__main__":
    main()
