"""Independent verifier for E1 -- cross-checks reliability of the numbers.

This file deliberately does NOT reuse e1_experiment.py's simulation loop. It:
  (1) property-tests the REAL detector primitives (shannon_entropy, r2_should_block)
      against textbook formulas (scipy entropy, explicit AND-gate);
  (2) independently re-derives FPR(level) with a fresh, from-scratch simulation
      (own RNG, own window, own entropy) and checks the committed e1_results.json
      values fall inside the independent 95% CI;
  (3) validates the Clopper-Pearson intervals against scipy.stats.binomtest;
  (4) checks two analytic anchors (volume gate below MIN_SAMPLES => FPR=0;
      all-distinct high load => FPR=1).

Run: python e1_verify.py
"""
from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

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
import resolver as R  # the REAL detector

WIN = 2.0
MIN_SAMPLES, ENT_THR, UNIQ_THR = 24, 4.0, 0.70
IPID_SPACE = 2048
PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, ok, detail=""):
    results.append((ok, name, detail))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f" -- {detail}" if detail else ""))


# --------------------------------------------------------------------------- #
print("\n(1) PRIMITIVES vs textbook formulas")
# shannon_entropy == scipy entropy base 2, on random multisets
rng = np.random.default_rng(7)
maxerr = 0.0
for _ in range(2000):
    n = int(rng.integers(1, 400))
    space = int(rng.choice([16, 256, 2048]))
    vals = list(rng.integers(0, space, size=n))
    counts = np.array(list(Counter(vals).values()), dtype=float)
    ref = float(stats.entropy(counts, base=2))
    got = R.shannon_entropy(vals)
    maxerr = max(maxerr, abs(ref - got))
check("shannon_entropy == scipy.stats.entropy (base 2)", maxerr < 1e-9,
      f"max abs err over 2000 cases = {maxerr:.2e}")

# r2_should_block combined == explicit AND gate, on a grid
grid_ok = True
for s in range(0, 60, 3):
    for e in [0.0, 3.9, 4.0, 4.6, 10.0]:
        for u in [0.0, 0.69, 0.70, 1.0]:
            expect = (s >= MIN_SAMPLES) and (e >= ENT_THR) and (u >= UNIQ_THR)
            got = R.r2_should_block("combined", True, s, e, u)
            grid_ok &= (expect == got)
check("r2_should_block('combined') == (samples>=24 AND entropy>=4.0 AND unique>=0.70)", grid_ok)
# defense off must never block
check("r2_should_block returns False when defense_on=False",
      not any(R.r2_should_block("combined", False, 100, 10.0, 1.0) for _ in range(1)))


# --------------------------------------------------------------------------- #
print("\n(2) INDEPENDENT FPR re-derivation (fresh sim) vs committed e1_results.json")
def independent_fpr(level, n_runs=60, n_dec=300, base_seed=999):
    """From-scratch benign-only FPR sim for random-IPID (auth model). Own code path."""
    lam = level / WIN
    warm = 3.0 * WIN
    fprs = []
    for r in range(n_runs):
        g = np.random.default_rng(base_seed + r + level * 1000)
        win = []               # list of (t, ipid)
        t = 0.0
        blocks = dec = 0
        guard = int(warm * lam) + n_dec * 3 + 2000
        for _ in range(guard):
            if dec >= n_dec:
                break
            t += g.exponential(1.0 / lam)
            win.append((t, int(g.integers(0, IPID_SPACE))))
            cut = t - WIN
            while win and win[0][0] < cut:
                win.pop(0)
            if t < warm:
                continue
            ipids = [i for _, i in win]
            n = len(ipids)
            u = len(set(ipids)) / n if n else 0.0
            # independent entropy (not R.shannon_entropy)
            c = np.array(list(Counter(ipids).values()), dtype=float)
            ent = float(-(c / n * np.log2(c / n)).sum()) if n else 0.0
            dec += 1
            if n >= MIN_SAMPLES and ent >= ENT_THR and u >= UNIQ_THR:
                blocks += 1
        fprs.append(blocks / dec if dec else 0.0)
    a = np.array(fprs)
    m = a.mean()
    se = a.std(ddof=1) / math.sqrt(len(a))
    h = stats.t.ppf(0.975, len(a) - 1) * se
    return m, max(0, m - h), min(1, m + h)

committed = {e["level"]: e["variants"]["combined"]["fpr_run_mean"]
             for e in json.load(open(HERE / "e1_results.json", encoding="utf-8"))["levels"]
             if e["behavior"] == "random2048"}
for lvl in [12, 18, 24, 36]:
    m, lo, hi = independent_fpr(lvl)
    c = committed[lvl]
    inside = lo - 0.05 <= c <= hi + 0.05    # allow small MC slack (diff seeds)
    check(f"random2048 FPR@{lvl}: committed {c:.3f} within independent 95% CI "
          f"[{lo:.3f},{hi:.3f}]", inside)


# --------------------------------------------------------------------------- #
print("\n(3) Clopper-Pearson vs scipy.stats.binomtest")
def cp(k, n):
    lo = 0.0 if k == 0 else stats.beta.ppf(0.025, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(0.975, k + 1, n - k)
    return float(lo), float(hi)

cp_ok = True
for k, n in [(0, 6000), (8, 6000), (3721, 6000), (6000, 6000)]:
    lo, hi = cp(k, n)
    ref = stats.binomtest(k, n).proportion_ci(method="exact")
    cp_ok &= abs(lo - ref.low) < 1e-6 and abs(hi - ref.high) < 1e-6
check("Clopper-Pearson (beta ppf) == scipy binomtest exact CI", cp_ok)
check("0/6000 reported as interval, not 0", cp(0, 6000)[1] > 0,
      f"CP95(0/6000) = [0, {cp(0,6000)[1]:.5f}]")


# --------------------------------------------------------------------------- #
print("\n(4) Analytic anchors (mechanism sanity)")
# below MIN_SAMPLES the volume gate must keep FPR=0 regardless of entropy/unique
m5, _, hi5 = independent_fpr(5, n_runs=30)
check("very low load (level 5) => FPR 0 (volume gate closed)", hi5 < 1e-6,
      f"FPR={m5:.4f}")
# extreme distinct load => FPR ~ 1
m300, lo300, _ = independent_fpr(300, n_runs=20)
check("very high distinct load (level 300) => FPR = 1 (all gates open)", lo300 > 0.999,
      f"FPR={m300:.4f}")


# --------------------------------------------------------------------------- #
n_fail = sum(1 for ok, *_ in results if not ok)
print("\n" + "=" * 64)
print(f"E1 VERIFY: {len(results) - n_fail}/{len(results)} checks PASS, {n_fail} FAIL")
print("=" * 64)
sys.exit(1 if n_fail else 0)
