"""B6 -- Detector đề xuất: đo IPID theo TỪNG truy vấn (per-query multiplicity).

Động cơ (từ E1 + E2)
--------------------
Luật cải tiến hiện tại (B5 combined) đo entropy/unique_ratio của IPID gộp trên
CẢ cửa sổ 2s theo (src_ip,dst_ip). Vì thế:
  * E1: benign bận (nhiều query, IPID ngẫu nhiên) cũng thoả cả 3 cổng -> FPR bùng nổ.
  * E2: ở cùng volume, B5 == B2 (entropy vô dụng), và attack fixed-IPID né được.

B6 đo ở ĐÚNG mức: mỗi truy vấn hợp lệ chỉ nên có ĐÚNG MỘT mảnh-thứ-hai. Đặc trưng:

    B6_ratio = (số FRAG2 quan sát trong cửa sổ) / max(1, số truy vấn hợp lệ trong cửa sổ)

  - benign: mỗi query 1 FRAG2 -> ratio ~ 1  (bất kể có bao nhiêu query -> KHÔNG confound volume)
  - attack (sweep/random/fixed): kẻ tấn công rải NHIỀU FRAG2 cho một khe -> ratio lớn
  - fixed-IPID vẫn bị bắt: cùng IPID nhưng vẫn NHIỀU gói -> ratio vẫn lớn

Giả định hiện thực: resolver biết chính xác số truy vấn upstream nó tự phát (mẫu số).
Đây là thông tin resolver luôn có -> đặc trưng cài được, không phải "gian lận".

entropy/unique_ratio (đóng góp gốc của nhóm) được HẠ xuống vai trò MÔ TẢ kiểu tấn
công (loạn = sweep, đều = fixed), không còn là trục phân biệt chính.

Ba phần
-------
  P1  Benign FPR theo tải (như E1): B2/B5/B6.
  P2  Matched-volume vs attack sweep/random/fixed/bursty (như E2): B2/B5/B6 + paired margin.
  P3  Đường đánh đổi phát hiện–né tránh: tăng cường độ attack (M/Q), đo TPR(B6) và
      proxy xác suất poison -> attacker muốn né (M nhỏ) thì success ~ 0.

Fidelity: B2/B5 dùng lại shannon_entropy + r2_should_block THẬT từ resolver.py.
B6 là logic ĐỀ XUẤT (chưa có trong resolver.py) nên hiện thực trong harness, ghi rõ.

Usage: python b6_experiment.py [--runs 20] [--out .]
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
from typing import Dict, List, Tuple

import numpy as np
from scipy import stats

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
LAB = HERE.parents[3] / "labs" / "r2entropy"
for k, v in {"R2_MIN_SAMPLES": "24", "R2_ENTROPY_THRESHOLD": "4.0",
             "R2_UNIQUE_RATIO_THRESHOLD": "0.70", "R2_VARIANT": "combined",
             "FRAG2_WINDOW_SECONDS": "2.0"}.items():
    os.environ.setdefault(k, v)
sys.path.insert(0, str(LAB / "localtest" / "shim"))
sys.path.insert(0, str(LAB / "resolver"))
import resolver as R  # real detector primitives

WIN = 2.0
IPID_SPACE = 2048
FIXED_IPID = 777
B6_TAU = 3.0            # per-query multiplicity threshold (block if ratio >= tau)
WARMUP_MULT = 3.0
SEED = 20260805

E1_LEVELS = [5, 12, 18, 24, 36, 60, 120, 300]
E2_LEVELS = [24, 60, 120, 200]
ATTACKS = ["attack_sweep", "attack_random", "attack_fixed", "attack_bursty"]


# --------------------------------------------------------------------------- #
# IPID samplers                                                                #
# --------------------------------------------------------------------------- #
def benign_sampler(rng):
    return lambda: rng.randint(0, IPID_SPACE - 1)


def attacker_sampler(kind, rng):
    if kind == "attack_random":
        return lambda: rng.randint(0, IPID_SPACE - 1)
    if kind == "attack_fixed":
        return lambda: FIXED_IPID
    ctr = {"v": rng.randint(0, IPID_SPACE - 1)}          # sweep / bursty

    def _sweep():
        v = ctr["v"] % IPID_SPACE
        ctr["v"] += 1
        return v
    return _sweep


def decide_all(ipids: List[int], q_count: int) -> Dict[str, bool]:
    """Block decisions for B2 (volume), B5 (combined), B6 (per-query ratio)."""
    total = len(ipids)
    unique = len(set(ipids))
    entropy = R.shannon_entropy(ipids)                    # REAL
    unique_ratio = (unique / total) if total else 0.0
    b6_ratio = total / max(1, q_count)
    return {
        "B2": R.r2_should_block("volume", True, total, entropy, unique_ratio),
        "B5": R.r2_should_block("combined", True, total, entropy, unique_ratio),
        "B6": b6_ratio >= B6_TAU,
        "_entropy": entropy, "_unique": unique_ratio, "_total": total,
        "_ratio": b6_ratio,
    }


# --------------------------------------------------------------------------- #
# One run: stream of arrivals; each arrival = decision event.                  #
# --------------------------------------------------------------------------- #
def simulate(level: int, attack: str, seed: int, n_dec: int,
             benign_frac: float) -> Dict[str, float]:
    rng = random.Random(seed)
    b_ipid = benign_sampler(rng)
    is_attack = attack is not None
    a_ipid = attacker_sampler(attack, rng) if is_attack else None
    lam = level / WIN
    warm = WARMUP_MULT * WIN
    bursty = attack == "attack_bursty"

    window: List[Tuple[float, int, bool]] = []            # (t, ipid, is_atk)
    t = 0.0
    blocks = {"B2": 0, "B5": 0, "B6": 0}
    dec = 0
    ent_sum = ratio_sum = 0.0
    guard = int(warm * lam) + n_dec * 4 + 3000
    for _ in range(guard):
        if dec >= n_dec:
            break
        rate = lam
        if bursty:
            rate = lam * (2.0 if int(t) % 2 == 0 else 0.5)
        t += rng.expovariate(rate) if rate > 0 else 1.0
        atk = is_attack and (rng.random() >= benign_frac)
        ipid = a_ipid() if atk else b_ipid()
        window.append((t, ipid, atk))
        cut = t - WIN
        while window and window[0][0] < cut:
            window.pop(0)
        if t < warm:
            continue
        ipids = [i for _, i, _ in window]
        q_count = sum(1 for _, _, a in window if not a)     # legit queries in window
        d = decide_all(ipids, q_count)
        dec += 1
        ent_sum += d["_entropy"]; ratio_sum += d["_ratio"]
        for k in ("B2", "B5", "B6"):
            if d[k]:
                blocks[k] += 1
    return {
        "decisions": dec,
        "rate_B2": blocks["B2"] / dec if dec else 0.0,
        "rate_B5": blocks["B5"] / dec if dec else 0.0,
        "rate_B6": blocks["B6"] / dec if dec else 0.0,
        "entropy_mean": ent_sum / dec if dec else 0.0,
        "b6_ratio_mean": ratio_sum / dec if dec else 0.0,
    }


def mean_ci(vals):
    a = np.asarray(vals, float)
    n = len(a); m = float(a.mean()) if n else 0.0
    if n < 2:
        return m, m, m
    h = float(stats.t.ppf(0.975, n - 1)) * float(a.std(ddof=1) / math.sqrt(n))
    return m, max(0.0, m - h), min(1.0, m + h)


def paired_ci(a, b):
    d = np.asarray(a, float) - np.asarray(b, float)
    n = len(d); m = float(d.mean()) if n else 0.0
    if n < 2:
        return m, m, m
    h = float(stats.t.ppf(0.975, n - 1)) * float(d.std(ddof=1) / math.sqrt(n))
    return m, m - h, m + h


def git_commit(p):
    try:
        return subprocess.run(["git", "-C", str(p), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--windows", type=int, default=200)
    ap.add_argument("--benign-frac", type=float, default=0.1)
    ap.add_argument("--out", type=str, default=str(HERE))
    args = ap.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d_%H%M%S")

    print("=" * 80)
    print(f"B6 -- per-query multiplicity detector (tau={B6_TAU}). So B2 / B5 / B6.")
    print(f"K={args.runs} runs, {args.windows} decisions/run, benign_frac(attack)={args.benign_frac}")
    print("=" * 80)

    results = {
        "meta": {
            "experiment": "B6 -- per-query multiplicity detector vs B2/B5",
            "run_id": run_id, "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "code_git_commit": git_commit(LAB), "python": platform.python_version(),
            "detector_real": str((LAB / "resolver" / "resolver.py").as_posix()),
            "b6_definition": "block if (frag2_in_window / max(1, legit_queries_in_window)) >= tau",
            "b6_tau": B6_TAU, "window_seconds": WIN, "ipid_space": IPID_SPACE,
            "runs_per_cell": args.runs, "decisions_per_run": args.windows,
            "benign_frac_in_attack": args.benign_frac, "seed": SEED,
            "note": "B2/B5 use REAL resolver.py primitives; B6 is the PROPOSED detector (in-harness).",
        },
        "P1_benign_fpr": [], "P2_matched": [], "P3_intensity": [],
    }

    # ---- P1: benign FPR vs rate (no attacker) --------------------------- #
    print("\n[P1] Benign FPR theo tải (attack off):")
    for lvl in E1_LEVELS:
        cells = [simulate(lvl, None, SEED + lvl * 1000 + r, args.windows, 0.0)
                 for r in range(args.runs)]
        row = {"level": lvl}
        for det in ("B2", "B5", "B6"):
            m, lo, hi = mean_ci([c[f"rate_{det}"] for c in cells])
            row[det] = {"fpr": m, "ci95": [lo, hi]}
        results["P1_benign_fpr"].append(row)
        print(f"  s/win={lvl:>3} | FPR  B2={row['B2']['fpr']:.3f}  "
              f"B5={row['B5']['fpr']:.3f}  B6={row['B6']['fpr']:.3f}")

    # ---- P2: matched volume vs attack ----------------------------------- #
    print("\n[P2] Matched-volume: TPR(attack) / FPR(benign) cho B2/B5/B6:")
    # benign reference per level
    benign = {}
    for lvl in E2_LEVELS:
        cells = [simulate(lvl, None, SEED + lvl * 7 + r, args.windows, 0.0)
                 for r in range(args.runs)]
        benign[lvl] = {det: [c[f"rate_{det}"] for c in cells] for det in ("B2", "B5", "B6")}
    for atk in ATTACKS:
        for lvl in E2_LEVELS:
            cells = [simulate(lvl, atk, SEED + lvl * 13 + r, args.windows, args.benign_frac)
                     for r in range(args.runs)]
            row = {"attack": atk, "level": lvl}
            for det in ("B2", "B5", "B6"):
                tpr = [c[f"rate_{det}"] for c in cells]
                m, lo, hi = mean_ci(tpr)
                row[f"TPR_{det}"] = {"mean": m, "ci95": [lo, hi]}
                row[f"FPR_{det}"] = mean_ci(benign[lvl][det])[0]
            # paired margins (attack TPR - benign FPR), B6 vs B5 and B6 vs B2
            b6m = np.array([c["rate_B6"] for c in cells]) - np.array(benign[lvl]["B6"])
            b5m = np.array([c["rate_B5"] for c in cells]) - np.array(benign[lvl]["B5"])
            b2m = np.array([c["rate_B2"] for c in cells]) - np.array(benign[lvl]["B2"])
            for name, x, y in (("B6_minus_B5", b6m, b5m), ("B6_minus_B2", b6m, b2m)):
                m, lo, hi = paired_ci(x, y)
                row[name] = {"mean": m, "ci95": [lo, hi]}
            results["P2_matched"].append(row)
            print(f"  {atk:>14} lvl={lvl:>3} | TPR B2={row['TPR_B2']['mean']:.2f} "
                  f"B5={row['TPR_B5']['mean']:.2f} B6={row['TPR_B6']['mean']:.2f} | "
                  f"FPR(benign) B6={row['FPR_B6']:.2f}")

    # ---- P3: detection/evasion tradeoff --------------------------------- #
    print("\n[P3] Đánh đổi phát hiện–né: cố định Q~12/window, tăng M (forgeries/window):")
    Q_LEVEL = 12
    M_LIST = [0, 3, 6, 12, 24, 60, 120, 300, 600]
    for M in M_LIST:
        total_level = Q_LEVEL + M
        bf = Q_LEVEL / total_level if total_level else 1.0
        # sweep attack (distinct IPIDs) -> success proxy = coverage of target IPID
        cells = [simulate(total_level, "attack_sweep" if M > 0 else None,
                          SEED + M * 101 + r, args.windows, bf if M > 0 else 0.0)
                 for r in range(args.runs)]
        tpr_b6 = mean_ci([c["rate_B6"] for c in cells])[0]
        tpr_b5 = mean_ci([c["rate_B5"] for c in cells])[0]
        tpr_b2 = mean_ci([c["rate_B2"] for c in cells])[0]
        # poison success proxy: prob a swept forgery matches the one target IPID in window
        success = min(1.0, M / IPID_SPACE)
        results["P3_intensity"].append({
            "M_forgeries": M, "Q_queries": Q_LEVEL, "intensity_M_over_Q": M / Q_LEVEL,
            "TPR_B2": tpr_b2, "TPR_B5": tpr_b5, "TPR_B6": tpr_b6,
            "poison_success_proxy": success,
        })
        print(f"  M={M:>3} (M/Q={M/Q_LEVEL:4.1f}) | TPR B2={tpr_b2:.2f} B5={tpr_b5:.2f} "
              f"B6={tpr_b6:.2f} | success~{success:.3f}")

    # ---- write ----------------------------------------------------------- #
    (out / "b6_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] wrote {out / 'b6_results.json'}")
    _summary_csv(out, results)


def _summary_csv(out, results):
    with open(out / "b6_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["part", "key1", "key2", "B2", "B5", "B6", "extra"])
        for r in results["P1_benign_fpr"]:
            w.writerow(["P1_benign_FPR", r["level"], "", f"{r['B2']['fpr']:.4f}",
                        f"{r['B5']['fpr']:.4f}", f"{r['B6']['fpr']:.4f}", ""])
        for r in results["P2_matched"]:
            w.writerow(["P2_TPR", r["attack"], r["level"], f"{r['TPR_B2']['mean']:.4f}",
                        f"{r['TPR_B5']['mean']:.4f}", f"{r['TPR_B6']['mean']:.4f}",
                        f"FPRb6={r['FPR_B6']:.4f}"])
        for r in results["P3_intensity"]:
            w.writerow(["P3_intensity", f"M={r['M_forgeries']}", f"M/Q={r['intensity_M_over_Q']:.1f}",
                        f"{r['TPR_B2']:.4f}", f"{r['TPR_B5']:.4f}", f"{r['TPR_B6']:.4f}",
                        f"success={r['poison_success_proxy']:.4f}"])
    print(f"[+] wrote {out / 'b6_summary.csv'}")


if __name__ == "__main__":
    main()
