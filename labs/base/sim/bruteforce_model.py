"""Monte Carlo model for full source-port brute-force experiments.

This does not replace the Docker labs. It answers a narrower question that is
hard to measure quickly on a laptop: if the attacker must blindly brute-force
the resolver's upstream source port plus TXID/IPID, how often should poisoning
land within a fixed query race window?

The output starts with the same core columns used by the pipeline CSV, then
adds entropy-space and expectation columns for report discussion.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path
from typing import Iterable, List


DEFAULT_SEED = 20260619
VALID_LABS = {"oob", "sfrag"}


def parse_labs(raw: str) -> List[str]:
    if raw == "all":
        return ["oob", "sfrag"]
    labs = [item.strip() for item in raw.split(",") if item.strip()]
    invalid = [lab for lab in labs if lab not in VALID_LABS]
    if invalid:
        raise ValueError(f"unknown lab(s): {','.join(invalid)}")
    return labs


def parse_cases(raw: str) -> List[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def success_probability(space_size: int, packet_budget: int) -> float:
    if space_size <= 0:
        return 0.0
    return min(1.0, max(0, packet_budget) / float(space_size))


def trial_count(rounds: int, probability: float, rng: random.Random) -> int:
    poisoned = 0
    for _ in range(rounds):
        if rng.random() < probability:
            poisoned += 1
    return poisoned


def rows_for_lab(
    *,
    lab: str,
    cases: Iterable[str],
    runs: int,
    rounds: int,
    rng: random.Random,
    port_count: int,
    txid_space: int,
    ipid_space: int,
    packet_budget_oob: int,
    packet_budget_sfrag: int,
    src_port_start: int,
    src_port_end: int,
    latency_ms: float,
    seed: int,
):
    if lab == "oob":
        entropy_component = "source_port_x_txid"
        entropy_space = port_count * txid_space
        packet_budget = packet_budget_oob
    else:
        entropy_component = "source_port_x_ipid"
        entropy_space = port_count * ipid_space
        packet_budget = packet_budget_sfrag

    p_attack = success_probability(entropy_space, packet_budget)
    expected_poisoned = rounds * p_attack
    expected_asr = p_attack * 100.0

    for case in cases:
        for run_idx in range(1, runs + 1):
            if case == "attack-off":
                poisoned = trial_count(rounds, p_attack, rng)
                expected_for_case = expected_poisoned
                expected_asr_for_case = expected_asr
            else:
                poisoned = 0
                expected_for_case = 0.0
                expected_asr_for_case = 0.0

            asr = (poisoned / rounds * 100.0) if rounds else 0.0
            yield [
                lab,
                case,
                run_idx,
                rounds,
                rounds,
                poisoned,
                f"{asr:.2f}",
                f"{latency_ms:.3f}",
                f"{latency_ms:.3f}",
                entropy_component,
                entropy_space,
                packet_budget,
                f"{expected_for_case:.6f}",
                f"{expected_asr_for_case:.8f}",
                src_port_start,
                src_port_end,
                txid_space if lab == "oob" else "",
                ipid_space if lab == "sfrag" else "",
                seed,
            ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labs", default="oob,sfrag", help="'all' or comma-separated labs: oob,sfrag")
    parser.add_argument("--cases", default="baseline,attack-off,attack-on")
    parser.add_argument("--rounds", type=int, default=150)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--out", default="p2_bruteforce_model.csv")
    parser.add_argument("--src-port-start", type=int, default=1024)
    parser.add_argument("--src-port-end", type=int, default=65535)
    parser.add_argument("--txid-space", type=int, default=65536)
    parser.add_argument("--ipid-space", type=int, default=65535)
    parser.add_argument("--packet-budget-oob", type=int, default=65536)
    parser.add_argument("--packet-budget-sfrag", type=int, default=65535)
    parser.add_argument("--latency-ms", type=float, default=50.0)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    labs = parse_labs(args.labs)
    cases = parse_cases(args.cases)
    src_port_start = max(1, min(65535, args.src_port_start))
    src_port_end = max(1, min(65535, args.src_port_end))
    if src_port_end < src_port_start:
        src_port_start, src_port_end = src_port_end, src_port_start
    port_count = src_port_end - src_port_start + 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    header = [
        "lab",
        "case",
        "run",
        "rounds",
        "total",
        "poisoned",
        "asr_pct",
        "latency_avg_ms",
        "latency_p95_ms",
        "entropy_components",
        "entropy_space",
        "packet_budget_per_query",
        "expected_poisoned",
        "expected_asr_pct",
        "src_port_start",
        "src_port_end",
        "txid_space",
        "ipid_space",
        "seed",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for lab in labs:
            writer.writerows(
                rows_for_lab(
                    lab=lab,
                    cases=cases,
                    runs=args.runs,
                    rounds=args.rounds,
                    rng=rng,
                    port_count=port_count,
                    txid_space=args.txid_space,
                    ipid_space=args.ipid_space,
                    packet_budget_oob=args.packet_budget_oob,
                    packet_budget_sfrag=args.packet_budget_sfrag,
                    src_port_start=src_port_start,
                    src_port_end=src_port_end,
                    latency_ms=args.latency_ms,
                    seed=args.seed,
                )
            )

    print(f"[+] CSV: {out_path.resolve()}")
    print(f"[+] source-port candidates: {src_port_start}-{src_port_end} ({port_count})")
    for lab in labs:
        if lab == "oob":
            space = port_count * args.txid_space
            budget = args.packet_budget_oob
            label = "source_port_x_txid"
        else:
            space = port_count * args.ipid_space
            budget = args.packet_budget_sfrag
            label = "source_port_x_ipid"
        p = success_probability(space, budget)
        print(
            f"[+] {lab}: {label} space={space} budget/query={budget} "
            f"expected ASR={p * 100.0:.8f}% expected poisoned/run={args.rounds * p:.6f}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
