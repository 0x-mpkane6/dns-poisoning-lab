"""Analyze the p2 metrics CSV emitted by ``run_p2_pipeline.sh``.

Outputs:
- A per-(lab, case) summary with mean/min/max/std for ASR and latency.
- An optional Markdown table that can be pasted into the report.

Usage:
    python3 analyze_metrics.py path/to/p2_metrics.csv [--md OUT.md]
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from typing import Dict, List, Tuple


def aggregate(rows: List[Dict[str, str]]) -> Dict[Tuple[str, str], Dict[str, float]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, float]]] = defaultdict(list)
    for row in rows:
        key = (row["lab"], row["case"])
        grouped[key].append(
            {
                "asr": float(row["asr_pct"]),
                "avg": float(row["latency_avg_ms"]),
                "p95": float(row["latency_p95_ms"]),
            }
        )

    out: Dict[Tuple[str, str], Dict[str, float]] = {}
    for key, samples in grouped.items():
        n = len(samples)

        def stats(values: List[float]) -> Dict[str, float]:
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n if n > 0 else 0.0
            std = math.sqrt(variance)
            return {
                "mean": mean,
                "min": min(values),
                "max": max(values),
                "std": std,
            }

        out[key] = {
            "n": n,
            **{f"asr_{k}": v for k, v in stats([s["asr"] for s in samples]).items()},
            **{f"avg_{k}": v for k, v in stats([s["avg"] for s in samples]).items()},
            **{f"p95_{k}": v for k, v in stats([s["p95"] for s in samples]).items()},
        }
    return out


def render_md(stats: Dict[Tuple[str, str], Dict[str, float]]) -> str:
    lines = []
    lines.append("| Lab | Case | Runs | ASR mean (%) | ASR min/max | Latency avg (ms) | Latency p95 (ms) |")
    lines.append("|-----|------|------|--------------|-------------|-------------------|-------------------|")
    order_lab = ["oob", "sfrag", "bfrag"]
    order_case = ["baseline", "attack-off", "attack-on"]

    def order_key(item):
        lab, case = item[0]
        return (
            order_lab.index(lab) if lab in order_lab else 99,
            order_case.index(case) if case in order_case else 99,
        )

    for (lab, case), s in sorted(stats.items(), key=order_key):
        lines.append(
            f"| {lab} | {case} | {int(s['n'])} | "
            f"{s['asr_mean']:.2f} | {s['asr_min']:.2f}/{s['asr_max']:.2f} | "
            f"{s['avg_mean']:.3f} | {s['p95_mean']:.3f} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="path to p2_metrics.csv")
    parser.add_argument("--md", help="optional Markdown output path", default=None)
    args = parser.parse_args()

    with open(args.csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    if not rows:
        print("[!] CSV is empty", file=sys.stderr)
        return 1

    stats = aggregate(rows)

    print("\n=== Per-(lab, case) statistics ===")
    for (lab, case), s in sorted(stats.items()):
        print(
            f"{lab:7s} {case:12s} n={int(s['n'])}  "
            f"ASR mean={s['asr_mean']:6.2f}% (min {s['asr_min']:.2f}, max {s['asr_max']:.2f}, std {s['asr_std']:.2f})  "
            f"avg_lat={s['avg_mean']:.3f}ms  p95_lat={s['p95_mean']:.3f}ms"
        )

    md = render_md(stats)
    print()
    print(md)

    if args.md:
        with open(args.md, "w", encoding="utf-8") as out:
            out.write(md + "\n")
        print(f"\n[+] Markdown table saved to {args.md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
