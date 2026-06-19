"""Generate Person-2 report charts from the metrics CSVs.

Inputs:
- --core CSV: rows with columns lab,case,run,rounds,total,poisoned,asr_pct,
  latency_avg_ms,latency_p95_ms (output of run_p2_pipeline.sh or sim_runner.py).
- --sweep CSV (optional): same schema + ipid_space (output of ipid_sweep.sh
  or ipid_sweep_sim.py).
- --outdir: directory to write PNGs into.

Outputs:
- asr_by_case.png            ASR(%) bar chart, grouped by lab × case.
- latency_by_case.png        Latency p95 bar chart, grouped by lab × case.
- sfrag_asr_vs_ipid.png      ASR(%) vs IPID space (log-x), one point per run
                             plus a mean curve.

Usage:
    python3 make_charts.py --core p2_metrics_sim.csv \\
        [--sweep sfrag_ipid_sweep_sim.csv] --outdir ../../../Report/data/
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


LAB_ORDER = ["oob", "sfrag", "bfrag"]
CASE_ORDER = [
    "baseline",
    "attack-off",
    "attack-on",
    "attack-off-multi",
    "attack-on-multi",
]


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _aggregate_core(rows: List[Dict[str, str]]):
    """Returns mean ASR / latency per (lab, case)."""
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["lab"], row["case"])].append(row)

    out = {}
    for key, items in grouped.items():
        out[key] = {
            "n": len(items),
            "asr": sum(float(r["asr_pct"]) for r in items) / len(items),
            "asr_min": min(float(r["asr_pct"]) for r in items),
            "asr_max": max(float(r["asr_pct"]) for r in items),
            "avg": sum(float(r["latency_avg_ms"]) for r in items) / len(items),
            "p95": sum(float(r["latency_p95_ms"]) for r in items) / len(items),
        }
    return out


def chart_asr_by_case(stats, outpath: Path) -> None:
    cases_present = sorted(
        {case for (_lab, case) in stats.keys()},
        key=lambda c: CASE_ORDER.index(c) if c in CASE_ORDER else 99,
    )
    labs_present = [lab for lab in LAB_ORDER if any((lab, c) in stats for c in cases_present)]

    width = 0.8 / max(1, len(labs_present))
    x_positions = list(range(len(cases_present)))

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, lab in enumerate(labs_present):
        values = []
        for case in cases_present:
            s = stats.get((lab, case))
            values.append(s["asr"] if s else 0.0)
        offset = (i - (len(labs_present) - 1) / 2) * width
        bars = ax.bar([x + offset for x in x_positions], values, width=width, label=lab)
        for x, v in zip([x + offset for x in x_positions], values):
            ax.text(x, v + 1.5, f"{v:.0f}", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(cases_present, rotation=20, ha="right")
    ax.set_ylim(0, 110)
    ax.set_ylabel("Mean ASR (%)")
    ax.set_title("Person-2 labs: Attack Success Rate by case (mean across runs)")
    ax.legend(title="Lab")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"[+] {outpath}")


def chart_latency_by_case(stats, outpath: Path) -> None:
    cases_present = sorted(
        {case for (_lab, case) in stats.keys()},
        key=lambda c: CASE_ORDER.index(c) if c in CASE_ORDER else 99,
    )
    labs_present = [lab for lab in LAB_ORDER if any((lab, c) in stats for c in cases_present)]

    width = 0.8 / max(1, len(labs_present))
    x_positions = list(range(len(cases_present)))

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, lab in enumerate(labs_present):
        values = []
        for case in cases_present:
            s = stats.get((lab, case))
            values.append(s["p95"] if s else 0.0)
        offset = (i - (len(labs_present) - 1) / 2) * width
        ax.bar([x + offset for x in x_positions], values, width=width, label=lab)

    ax.set_xticks(x_positions)
    ax.set_xticklabels(cases_present, rotation=20, ha="right")
    ax.set_ylabel("Mean p95 latency (ms)")
    ax.set_title("Person-2 labs: latency p95 by case (mean across runs)")
    ax.legend(title="Lab")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"[+] {outpath}")


def chart_sfrag_sweep(rows: List[Dict[str, str]], outpath: Path) -> None:
    if not rows:
        print("[!] sweep CSV has no rows; skipping sfrag_asr_vs_ipid.png")
        return

    by_ipid: Dict[int, List[float]] = defaultdict(list)
    for row in rows:
        try:
            ipid = int(row["ipid_space"])
            asr = float(row["asr_pct"])
        except (KeyError, ValueError):
            continue
        by_ipid[ipid].append(asr)

    if not by_ipid:
        print("[!] sweep CSV had no parseable rows; skipping chart")
        return

    ipid_values = sorted(by_ipid.keys())
    means = [sum(by_ipid[i]) / len(by_ipid[i]) for i in ipid_values]
    raw_x: List[int] = []
    raw_y: List[float] = []
    for i in ipid_values:
        for v in by_ipid[i]:
            raw_x.append(i)
            raw_y.append(v)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.scatter(raw_x, raw_y, alpha=0.5, label="per-run ASR")
    ax.plot(ipid_values, means, marker="o", color="red", label="mean ASR")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("IPID_SPACE (log scale)")
    ax.set_ylabel("ASR (%)")
    ax.set_ylim(0, 110)
    ax.set_title("SFrag attack-off: ASR vs IPID_SPACE")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"[+] {outpath}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True, help="path to core metrics CSV")
    parser.add_argument("--sweep", default=None, help="path to IPID sweep CSV (optional)")
    parser.add_argument("--outdir", required=True, help="directory to write PNGs into")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    core_rows = _read_csv(Path(args.core))
    stats = _aggregate_core(core_rows)
    chart_asr_by_case(stats, outdir / "asr_by_case.png")
    chart_latency_by_case(stats, outdir / "latency_by_case.png")

    if args.sweep:
        sweep_rows = _read_csv(Path(args.sweep))
        chart_sfrag_sweep(sweep_rows, outdir / "sfrag_asr_vs_ipid.png")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
