"""E2 -- Volume-matched benign vs attack (cô lập sức phân biệt của entropy/unique_ratio).

Câu hỏi (RQ2): entropy / unique_ratio có sức phân biệt ĐỘC LẬP khi benign và attack
có CÙNG volume (samples/window) không? Hay detector chỉ đang tách attack khỏi benign
nhờ ĐẾM SỐ LƯỢNG?

Bối cảnh từ E1 + testbed thật
-----------------------------
* Attack thật (sweep) chạy ở ~1700 mẫu/cửa sổ, entropy ~10.8, unique_ratio=1.0.
* Benign thật chạy ở ~6 mẫu/cửa sổ. => Ở framing gốc, hai lớp tách nhau CHỦ YẾU
  bằng volume (~300x), không phải bằng entropy.
* E1 cho thấy benign IPID đa dạng ở tải cao cũng có entropy cao & unique_ratio ~1.0.
E2 ép benign và attack về CÙNG samples/window rồi hỏi: entropy còn tách được không?

Tính trung thực
---------------
Dùng lại nguyên các primitive detector thật từ resolver.py (shannon_entropy,
r2_should_block) và cùng mô hình cửa sổ trượt Poisson như E1. Mô hình IPID của
attacker lấy đúng từ attacker/scripts/spoof_r2entropy.py:
  - 'sweep'  : ATTACK_VARIANT=random -> build_packet cho MỌI ipid in range(IPID_SPACE)
               => quét toàn dải 0..2047 (entropy cao, unique_ratio~1.0). [continuous]
  - 'random' : spoof IPID ngẫu nhiên đều 0..2047 (thống kê ~ giống benign). [worst case]
  - 'fixed'  : ATTACK_VARIANT=fixed -> FIXED_IPID=777 lặp lại (entropy~0). [adaptive/evasion]
  - 'bursty' : sweep nhưng arrival bursty (E2 yêu cầu >= continuous và bursty).
Attacker spoof src=AUTH_IP nên FRAG2 giả rơi vào CÙNG bucket (src,dst) với benign
=> cửa sổ attack là hỗn hợp benign + attacker (tham số benign_frac).

Đầu ra
------
* e2_windows.csv  -- mọi decision-window (condition,level,run,samples,entropy,unique,blocks/variant)
* e2_summary.csv  -- TPR/FPR theo (condition,level,variant) + PR-AUC + FPR@TPR + paired CI
* e2_results.json -- toàn bộ + meta/provenance (P0 logging)
* notes.txt

Usage: python e2_experiment.py [--runs 20] [--windows 150] [--benign-frac 0.1] [--out .]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# 0. Import REAL detector primitives (via dnslib shim), like E1.               #
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
LAB_DIR = HERE.parents[3] / "labs" / "r2entropy"      # Code/labs/r2entropy
RESOLVER_DIR = LAB_DIR / "resolver"
SHIM_DIR = LAB_DIR / "localtest" / "shim"

OPERATING_POINT = {
    "R2_MIN_SAMPLES": "24",
    "R2_ENTROPY_THRESHOLD": "4.0",
    "R2_UNIQUE_RATIO_THRESHOLD": "0.70",
    "R2_VARIANT": "combined",
    "FRAG2_WINDOW_SECONDS": "2.0",
}
for _k, _v in OPERATING_POINT.items():
    os.environ.setdefault(_k, _v)
sys.path.insert(0, str(SHIM_DIR))
sys.path.insert(0, str(RESOLVER_DIR))
import resolver as R  # noqa: E402

WINDOW_SECONDS = float(OPERATING_POINT["FRAG2_WINDOW_SECONDS"])
MIN_SAMPLES = R.R2_MIN_SAMPLES
ENTROPY_THRESHOLD = R.R2_ENTROPY_THRESHOLD
UNIQUE_RATIO_THRESHOLD = R.R2_UNIQUE_RATIO_THRESHOLD
IPID_SPACE = 2048            # auth_server.py / attacker default
FIXED_IPID = 777            # attacker FIXED_IPID default

# E2: matched-volume levels (outline recommends around {24, 60, 120, 200}).
LEVELS = [24, 60, 120, 200]
VARIANTS = ["combined", "volume", "entropy", "unique"]
PRIMARY_VARIANT = "combined"
WARMUP_MULT = 3.0
EXPERIMENT_SEED = 20260805

# Conditions: one benign (negative class) + four attack models (positive class).
CONDITIONS = {
    "benign":        {"is_attack": False, "label": "Benign (auth model: random IPID 0..2047)"},
    "attack_sweep":  {"is_attack": True,  "label": "Attack sweep (continuous, IPID 0..2047) -- real default"},
    "attack_random": {"is_attack": True,  "label": "Attack random spoof (continuous, ~ giống benign)"},
    "attack_fixed":  {"is_attack": True,  "label": "Attack fixed IPID=777 (adaptive / low-entropy evasion)"},
    "attack_bursty": {"is_attack": True,  "label": "Attack sweep, bursty arrival"},
}
ATTACK_CONDITIONS = [c for c in CONDITIONS if CONDITIONS[c]["is_attack"]]


# --------------------------------------------------------------------------- #
# 1. IPID source models.                                                       #
# --------------------------------------------------------------------------- #
def benign_ipid(rng: random.Random) -> Callable[[], int]:
    return lambda: rng.randint(0, IPID_SPACE - 1)


def attacker_ipid(condition: str, rng: random.Random) -> Callable[[], int]:
    if condition == "attack_random":
        return lambda: rng.randint(0, IPID_SPACE - 1)
    if condition == "attack_fixed":
        return lambda: FIXED_IPID
    if condition in ("attack_sweep", "attack_bursty"):
        # spoof_r2entropy.py sends range(IPID_SPACE) each round -> cycling sweep.
        ctr = {"v": rng.randint(0, IPID_SPACE - 1)}

        def _sweep() -> int:
            val = ctr["v"] % IPID_SPACE
            ctr["v"] += 1
            return val
        return _sweep
    raise ValueError(condition)


# --------------------------------------------------------------------------- #
# 2. One run of a condition at a matched samples/window level.                 #
# --------------------------------------------------------------------------- #
def simulate_run(condition: str, level: int, seed: int, n_windows: int,
                 benign_frac: float) -> Dict[str, object]:
    """Return per-window arrays for one independent run.

    Arrivals are Poisson(lambda=level/WINDOW). For attack conditions each arrival
    is benign with prob benign_frac (commingled, since attacker spoofs src=auth),
    else attacker-generated. Total occupancy ~ level either way (volume matched).
    The window/prune/scoring is the REAL detector path.
    """
    rng = random.Random(seed)
    is_attack = CONDITIONS[condition]["is_attack"]
    b_ipid = benign_ipid(rng)
    a_ipid = attacker_ipid(condition, rng) if is_attack else None
    lam = level / WINDOW_SECONDS
    warmup_until = WARMUP_MULT * WINDOW_SECONDS

    # Bursty: alternate high/low intensity every ~1s but keep the mean rate = lam.
    bursty = condition == "attack_bursty"

    window: List[Tuple[float, int]] = []
    t = 0.0
    samples_arr, ent_arr, uniq_arr = [], [], []
    blocks = {v: 0 for v in VARIANTS}
    decisions = 0
    max_arrivals = int(warmup_until * lam) + n_windows * 4 + 2000

    for _ in range(max_arrivals):
        if decisions >= n_windows:
            break
        rate = lam
        if bursty:
            # square-wave burstiness: 2x rate for 1s, then 0.5x for 1s (mean ~ lam).
            phase = int(t) % 2
            rate = lam * (2.0 if phase == 0 else 0.5)
        gap = rng.expovariate(rate) if rate > 0 else 1.0
        t += gap

        if is_attack and rng.random() >= benign_frac:
            ipid = a_ipid()          # attacker fragment
        else:
            ipid = b_ipid()          # benign fragment (baseline or the benign-frac mix)
        window.append((t, ipid))
        cutoff = t - WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.pop(0)

        if t < warmup_until:
            continue

        ipids = [i for _, i in window]
        total = len(ipids)
        unique = len(set(ipids))
        entropy = R.shannon_entropy(ipids)
        unique_ratio = (unique / total) if total else 0.0
        decisions += 1
        samples_arr.append(total)
        ent_arr.append(entropy)
        uniq_arr.append(unique_ratio)
        for v in VARIANTS:
            if R.r2_should_block(v, True, total, entropy, unique_ratio):
                blocks[v] += 1

    return {
        "condition": condition, "level": level, "seed": seed,
        "decisions": decisions,
        "samples": samples_arr, "entropy": ent_arr, "unique_ratio": uniq_arr,
        "blocks": blocks,
        "block_rate": {v: (blocks[v] / decisions if decisions else 0.0) for v in VARIANTS},
    }


# --------------------------------------------------------------------------- #
# 3. Statistics.                                                               #
# --------------------------------------------------------------------------- #
def mean_ci_t(values: List[float]) -> Tuple[float, float, float]:
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    m = float(arr.mean()) if n else 0.0
    if n < 2:
        return (m, m, m)
    se = float(arr.std(ddof=1) / math.sqrt(n))
    h = float(stats.t.ppf(0.975, n - 1)) * se
    return (m, m - h, m + h)


def paired_diff_ci(a: List[float], b: List[float]) -> Tuple[float, float, float]:
    """Paired difference (a - b) mean and 95% t-interval (same seeds)."""
    d = np.asarray(a, dtype=float) - np.asarray(b, dtype=float)
    n = len(d)
    m = float(d.mean()) if n else 0.0
    if n < 2:
        return (m, m, m)
    se = float(d.std(ddof=1) / math.sqrt(n))
    h = float(stats.t.ppf(0.975, n - 1)) * se
    return (m, m - h, m + h)


def fpr_at_tpr(neg_scores: np.ndarray, pos_scores: np.ndarray,
               target_tpr: float = 0.95, higher_is_positive: bool = True
               ) -> float:
    """Smallest FPR achievable by a single-signal threshold at >= target_tpr.

    If the signal cannot separate the classes, this returns ~target_tpr (useless).
    """
    if len(pos_scores) == 0 or len(neg_scores) == 0:
        return float("nan")
    s = pos_scores if higher_is_positive else -pos_scores
    n = neg_scores if higher_is_positive else -neg_scores
    # threshold = the value achieving target TPR on positives (quantile).
    thr = np.quantile(s, 1.0 - target_tpr)
    tpr = float(np.mean(s >= thr))
    fpr = float(np.mean(n >= thr))
    # guard: ensure tpr>=target (quantile is inclusive enough); report fpr
    return fpr


# --------------------------------------------------------------------------- #
# 4. Orchestration.                                                            #
# --------------------------------------------------------------------------- #
def git_commit(path: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def cell_seed(condition: str, level: int, run_idx: int) -> int:
    cidx = list(CONDITIONS).index(condition)
    return EXPERIMENT_SEED + level * 100003 + cidx * 10007 + run_idx


def main() -> None:
    ap = argparse.ArgumentParser(description="E2 -- volume-matched benign vs attack")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--windows", type=int, default=150, help="decision windows / run")
    ap.add_argument("--benign-frac", type=float, default=0.1,
                    help="fraction of attack-window fragments that are benign (commingling)")
    ap.add_argument("--out", type=str, default=str(HERE))
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d_%H%M%S")

    print("=" * 80)
    print("E2 -- Volume-matched benign vs attack (RQ2: entropy có tách được khi cùng volume?)")
    print(f"operating point B5: samples>={MIN_SAMPLES}, entropy>={ENTROPY_THRESHOLD}, "
          f"unique>={UNIQUE_RATIO_THRESHOLD}; window={WINDOW_SECONDS}s")
    print(f"levels(samples/window)={LEVELS}; conditions={list(CONDITIONS)}")
    print(f"K={args.runs} runs, {args.windows} windows/run, benign_frac(attack)={args.benign_frac}")
    print("Ý nghĩa: benign block=FPR; attack block=TPR. Nếu B5 không hơn B2 -> entropy vô ích.")
    print("=" * 80)

    # Randomized execution order (E4/E2 protocol).
    cells = [(cond, lvl, r) for cond in CONDITIONS for lvl in LEVELS
             for r in range(args.runs)]
    random.Random(EXPERIMENT_SEED).shuffle(cells)

    runs: List[Dict[str, object]] = []
    t0 = time.time()
    for i, (cond, lvl, r) in enumerate(cells, 1):
        runs.append(simulate_run(cond, lvl, cell_seed(cond, lvl, r), args.windows,
                                 args.benign_frac))
        if i % 80 == 0 or i == len(cells):
            print(f"  [{i}/{len(cells)}] cells done ({time.time() - t0:.1f}s)")

    # index: runs by (condition, level)
    def cell_runs(cond, lvl):
        return [x for x in runs if x["condition"] == cond and x["level"] == lvl]

    # ---- per-window CSV -------------------------------------------------- #
    windows_csv = out_dir / "e2_windows.csv"
    with open(windows_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["condition", "level", "seed", "window_idx", "samples",
                    "entropy", "unique_ratio",
                    "block_combined", "block_volume", "block_entropy", "block_unique"])
        for x in runs:
            for j in range(len(x["samples"])):
                # per-window block indicators recomputed from stored signals
                s = x["samples"][j]; e = x["entropy"][j]; u = x["unique_ratio"][j]
                row = [x["condition"], x["level"], x["seed"], j,
                       s, f"{e:.4f}", f"{u:.4f}"]
                for v in VARIANTS:
                    row.append(int(R.r2_should_block(v, True, s, e, u)))
                w.writerow(row)
    print(f"[+] wrote {windows_csv}")

    # ---- aggregate + discrimination analysis ----------------------------- #
    meta = {
        "experiment": "E2 -- volume-matched benign vs attack",
        "run_id": run_id,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "code_git_commit": git_commit(LAB_DIR),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "detector_source": str((RESOLVER_DIR / "resolver.py").as_posix()),
        "operating_point": {"min_samples": MIN_SAMPLES,
                            "entropy_threshold": ENTROPY_THRESHOLD,
                            "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
                            "window_seconds": WINDOW_SECONDS},
        "levels": LEVELS, "conditions": {k: v["label"] for k, v in CONDITIONS.items()},
        "variants": VARIANTS, "primary_variant": PRIMARY_VARIANT,
        "runs_per_cell": args.runs, "windows_per_run": args.windows,
        "benign_frac_in_attack": args.benign_frac,
        "experiment_seed": EXPERIMENT_SEED,
        "note": ("Controlled-emulation testbed: real resolver.py detector primitives, "
                 "Poisson sliding window, attacker IPID models from spoof_r2entropy.py. "
                 "No Docker / real IP fragmentation (E5)."),
    }
    results = {"meta": meta, "block_rates": [], "discrimination": []}

    # (A) block rate per (condition, level, variant): FPR for benign, TPR for attack
    summary_rows = []
    for cond in CONDITIONS:
        for lvl in LEVELS:
            cr = cell_runs(cond, lvl)
            entry = {"condition": cond, "level": lvl, "is_attack": CONDITIONS[cond]["is_attack"],
                     "samples_mean": float(np.mean([np.mean(x["samples"]) for x in cr])),
                     "entropy_mean": float(np.mean([np.mean(x["entropy"]) for x in cr])),
                     "unique_ratio_mean": float(np.mean([np.mean(x["unique_ratio"]) for x in cr])),
                     "variants": {}}
            for v in VARIANTS:
                rates = [x["block_rate"][v] for x in cr]
                m, lo, hi = mean_ci_t(rates)
                entry["variants"][v] = {"block_rate_mean": m, "ci95": [lo, hi]}
                summary_rows.append([cond, lvl, v,
                                     "TPR" if CONDITIONS[cond]["is_attack"] else "FPR",
                                     f"{m:.4f}", f"{lo:.4f}", f"{hi:.4f}"])
            results["block_rates"].append(entry)

    # (B) discrimination attack-vs-benign at matched volume, per attack condition
    for atk in ATTACK_CONDITIONS:
        for lvl in LEVELS:
            benr = cell_runs("benign", lvl)
            atkr = cell_runs(atk, lvl)
            # pooled per-window signals for PR-AUC (positives=attack, negatives=benign)
            neg_ent = np.concatenate([np.array(x["entropy"]) for x in benr])
            pos_ent = np.concatenate([np.array(x["entropy"]) for x in atkr])
            neg_uni = np.concatenate([np.array(x["unique_ratio"]) for x in benr])
            pos_uni = np.concatenate([np.array(x["unique_ratio"]) for x in atkr])
            neg_vol = np.concatenate([np.array(x["samples"], dtype=float) for x in benr])
            pos_vol = np.concatenate([np.array(x["samples"], dtype=float) for x in atkr])

            def pr_auc(neg, pos, sign=1.0):
                y = np.concatenate([np.zeros(len(neg)), np.ones(len(pos))])
                s = np.concatenate([neg, pos]) * sign
                if len(np.unique(y)) < 2:
                    return float("nan")
                return float(average_precision_score(y, s))

            prevalence = len(pos_ent) / (len(pos_ent) + len(neg_ent))
            disc = {
                "attack": atk, "level": lvl,
                "prevalence": prevalence,
                "pr_auc_volume": pr_auc(neg_vol, pos_vol),
                # entropy/unique tried both directions; report the better (max)
                "pr_auc_entropy": max(pr_auc(neg_ent, pos_ent, 1.0),
                                      pr_auc(neg_ent, pos_ent, -1.0)),
                "pr_auc_unique": max(pr_auc(neg_uni, pos_uni, 1.0),
                                     pr_auc(neg_uni, pos_uni, -1.0)),
                "fpr_at_tpr95_entropy": fpr_at_tpr(neg_ent, pos_ent, 0.95, True),
                "fpr_at_tpr95_volume": fpr_at_tpr(neg_vol, pos_vol, 0.95, True),
            }
            # paired B5 vs B2 : per-seed (TPR_attack - FPR_benign) discrimination margin
            b5_margin, b2_margin = [], []
            for xb, xa in zip(sorted(benr, key=lambda z: z["seed"]),
                              sorted(atkr, key=lambda z: z["seed"])):
                b5_margin.append(xa["block_rate"]["combined"] - xb["block_rate"]["combined"])
                b2_margin.append(xa["block_rate"]["volume"] - xb["block_rate"]["volume"])
            pm, plo, phi = paired_diff_ci(b5_margin, b2_margin)
            disc["b5_margin_mean"] = float(np.mean(b5_margin))
            disc["b2_margin_mean"] = float(np.mean(b2_margin))
            disc["paired_b5_minus_b2_margin"] = {"mean": pm, "ci95": [plo, phi]}
            results["discrimination"].append(disc)

    # ---- write summary/JSON ---------------------------------------------- #
    with open(out_dir / "e2_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["condition", "level", "variant", "metric", "rate_mean", "ci_lo", "ci_hi"])
        w.writerows(summary_rows)
    print(f"[+] wrote {out_dir / 'e2_summary.csv'}")

    with open(out_dir / "e2_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] wrote {out_dir / 'e2_results.json'}")

    _print_verdict(results)
    _write_notes(out_dir, results)


def _print_verdict(results: dict) -> None:
    print("\n" + "=" * 80)
    print("KẾT QUẢ E2 -- ở CÙNG volume, entropy/unique có tách được benign vs attack?")
    print("=" * 80)
    print(f"\n{'attack':>14} {'lvl':>4} | {'TPR(B5)':>8} {'TPR(B2)':>8} | "
          f"{'PR-AUC ent':>10} {'PR-AUC vol':>10} | {'B5-B2 margin (paired 95% CI)':>30}")
    # quick lookups
    def tpr(cond, lvl, v):
        for e in results["block_rates"]:
            if e["condition"] == cond and e["level"] == lvl:
                return e["variants"][v]["block_rate_mean"]
        return float("nan")
    for d in results["discrimination"]:
        pm = d["paired_b5_minus_b2_margin"]
        ci = f"{pm['mean']:+.3f} [{pm['ci95'][0]:+.3f},{pm['ci95'][1]:+.3f}]"
        print(f"{d['attack']:>14} {d['level']:>4} | "
              f"{tpr(d['attack'], d['level'], 'combined'):>8.3f} "
              f"{tpr(d['attack'], d['level'], 'volume'):>8.3f} | "
              f"{d['pr_auc_entropy']:>10.3f} {d['pr_auc_volume']:>10.3f} | {ci:>30}")
    print("\nĐọc: prevalence=0.5 => PR-AUC~0.5 nghĩa là tín hiệu VÔ DỤNG (bằng ngẫu nhiên).")
    print("B5-B2 margin ~ 0 và CI chứa 0 => entropy/unique KHÔNG thêm sức phân biệt so với volume.")


def _write_notes(out_dir: Path, results: dict) -> None:
    L = ["E2 -- Volume-matched benign vs attack", "=" * 60, "",
         "MỤC TIÊU (RQ2): cô lập sức phân biệt của entropy/unique_ratio khỏi volume.",
         f"operating point: {results['meta']['operating_point']}",
         f"levels: {results['meta']['levels']} | conditions: {list(results['meta']['conditions'])}",
         f"K={results['meta']['runs_per_cell']} runs, {results['meta']['windows_per_run']} windows/run, "
         f"benign_frac(attack)={results['meta']['benign_frac_in_attack']}", "",
         "PR-AUC (attack=positive, benign=negative) tại cùng volume:"]
    for d in results["discrimination"]:
        L.append(f"  {d['attack']:>14} lvl={d['level']:>3}: "
                 f"PR-AUC entropy={d['pr_auc_entropy']:.3f} volume={d['pr_auc_volume']:.3f} "
                 f"| B5-B2 margin={d['paired_b5_minus_b2_margin']['mean']:+.3f}")
    L += ["", "Diễn giải: xem E2_report.md."]
    (out_dir / "notes.txt").write_text("\n".join(L), encoding="utf-8")
    print(f"[+] wrote {out_dir / 'notes.txt'}")


if __name__ == "__main__":
    main()
