"""Simulator-based IPID sweep for the SFrag lab.

Runs `attack-off` over a list of IPID_SPACE values and writes a CSV row per
(IPID, run). Useful when no Docker is available (CI, thin laptop).

Usage:
    python3 ipid_sweep_sim.py [--rounds 50] [--runs 2] \\
        [--out sfrag_ipid_sweep_sim.csv] [--ipid-list 256,512,1024,2048,4096,8192]

CSV schema: lab,case,run,rounds,total,poisoned,asr_pct,latency_avg_ms,
            latency_p95_ms,ipid_space
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

# Reuse run_case from sim_runner.
import sim_runner


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=50)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--out", default="sfrag_ipid_sweep_sim.csv")
    parser.add_argument("--ipid-list", default="256,512,1024,2048,4096,8192")
    parser.add_argument("--entropy", default="full", choices=["full", "realistic", "weak", "demo", "bruteforce", "paper"])
    args = parser.parse_args()

    ipid_values = [int(x) for x in args.ipid_list.split(",") if x.strip()]
    out_path = Path(args.out)

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["lab", "case", "run", "rounds", "total", "poisoned",
             "asr_pct", "latency_avg_ms", "latency_p95_ms", "ipid_space"]
        )
        for ipid in ipid_values:
            print(f"\n=== sfrag attack-off IPID_SPACE={ipid} ===")
            for run_idx in range(1, args.runs + 1):
                print(f"  run {run_idx}/{args.runs} (rounds={args.rounds})")
                metrics = sim_runner.run_case(
                    lab="sfrag",
                    case="attack-off",
                    rounds=args.rounds,
                    ipid_space=ipid,
                    entropy_mode=args.entropy,
                )
                writer.writerow(
                    [
                        "sfrag",
                        "attack-off",
                        run_idx,
                        args.rounds,
                        metrics["total"],
                        metrics["poisoned"],
                        f"{metrics['asr_pct']:.2f}",
                        f"{metrics['latency_avg_ms']:.3f}",
                        f"{metrics['latency_p95_ms']:.3f}",
                        ipid,
                    ]
                )
                fh.flush()
                print(
                    f"      poisoned={metrics['poisoned']}/{metrics['total']} "
                    f"ASR={metrics['asr_pct']:.2f}%"
                )

    print(f"\n[+] CSV: {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
