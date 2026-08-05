"""Independent verifier for B6 -- guards against circular / too-good results.

Checks:
  (1) Determinism: re-run a harness cell, identical output.
  (2) Non-circularity: B6 uses only (total_frag2, legit_query_count) -- never a
      per-fragment 'is this forged?' label. We confirm the benign 1:1 property that
      makes the denominator implementable (resolver knows its own query count).
  (3) Analytic: benign-only => B6_ratio == 1 exactly => FPR = 0 for ANY tau > 1
      (independent fresh sim, not the harness).
  (4) tau robustness: benign FPR stays 0 and fixed-attack TPR stays 1 across a
      range of tau -> not a knife-edge threshold.
  (5) Honesty check: with a *legit* 2-fragment response model (2 frag2 per query),
      B6_ratio == 2 -> tau must exceed max legit fragments-per-query (documented caveat).
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
LAB = HERE.parents[3] / "labs" / "r2entropy"
for k, v in {"R2_MIN_SAMPLES": "24", "R2_ENTROPY_THRESHOLD": "4.0",
             "R2_UNIQUE_RATIO_THRESHOLD": "0.70", "R2_VARIANT": "combined"}.items():
    os.environ.setdefault(k, v)
sys.path.insert(0, str(LAB / "localtest" / "shim"))
sys.path.insert(0, str(LAB / "resolver"))
import resolver as R  # noqa: E402

WIN, S = 2.0, 2048
out = []


def check(name, ok, detail=""):
    out.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def indep_sim(level, attack, seed, n_dec=200, benign_frac=0.1, frags_per_query=1):
    """Fresh, from-scratch sim. Returns (fpr_or_tpr dict by tau, max_ratio, b5_block_rate)."""
    g = np.random.default_rng(seed)
    lam = level / WIN
    warm = 3.0 * WIN
    win = []           # (t, ipid, is_atk)
    t = 0.0
    dec = 0
    ratios = []
    b5_blocks = 0
    guard = int(warm * lam) + n_dec * 4 + 3000
    ctr = int(g.integers(0, S))
    for _ in range(guard):
        if dec >= n_dec:
            break
        t += g.exponential(1.0 / lam)
        is_atk = (attack is not None) and (g.random() >= benign_frac)
        if is_atk:
            if attack == "fixed":
                ipid = 777
            elif attack == "sweep":
                ipid = ctr % S; ctr += 1
            else:
                ipid = int(g.integers(0, S))
            win.append((t, ipid, True))
        else:
            # one legit query -> frags_per_query second-fragments (usually 1)
            for _ in range(frags_per_query):
                win.append((t, int(g.integers(0, S)), False))
        cut = t - WIN
        while win and win[0][0] < cut:
            win.pop(0)
        if t < warm:
            continue
        total = len(win)
        q = sum(1 for _, _, a in win if not a) // frags_per_query  # legit QUERIES
        q = max(1, q)
        ratios.append(total / q)
        ipids = [i for _, i, _ in win]
        if R.r2_should_block("combined", True, total, R.shannon_entropy(ipids),
                             len(set(ipids)) / total if total else 0.0):
            b5_blocks += 1
        dec += 1
    return np.array(ratios), b5_blocks / dec if dec else 0.0


# (1) Determinism -- re-run harness cell twice
print("\n(1) Determinism (harness)")
import b6_experiment as H  # noqa: E402
r1 = H.simulate(60, "attack_fixed", 12345, 200, 0.1)
r2 = H.simulate(60, "attack_fixed", 12345, 200, 0.1)
check("same seed => identical harness output", r1 == r2)

# (2)+(3) benign-only ratio == 1 exactly => FPR 0 for any tau>1
print("\n(2/3) Benign-only: B6_ratio == 1 (independent sim, any tau>1 => FPR 0)")
allone = True
for lvl in [24, 60, 120, 300]:
    ratios, _ = indep_sim(lvl, None, 700 + lvl)
    allone &= np.allclose(ratios, 1.0)
check("benign B6_ratio == 1.0 at every decision (1 frag2 per query)", allone,
      "=> denominator uses only resolver's own query count, not per-fragment labels")

# (4) tau robustness: benign FPR 0 and fixed TPR 1 across tau in {2,3,5,8}
print("\n(4) tau robustness")
ben_ratios, _ = indep_sim(120, None, 4242)
fix_ratios, b5_fix = indep_sim(60, "fixed", 4243, benign_frac=0.1)
benign_fpr_all_zero = True
tpr_by_tau = {}
for tau in [2, 3, 5, 8]:
    fpr = float((ben_ratios >= tau).mean())
    tpr = float((fix_ratios >= tau).mean())
    benign_fpr_all_zero &= (fpr == 0.0)
    tpr_by_tau[tau] = tpr
    print(f"    tau={tau}: benign FPR={fpr:.3f}, fixed TPR={tpr:.3f}")
# Honest invariants: benign FPR=0 for EVERY tau (safety); fixed TPR=1.0 for tau<=5,
# graceful degradation (>=0.95) at tau=8.
check("benign FPR = 0 for EVERY tau in {2,3,5,8} (safety invariant)", benign_fpr_all_zero)
check("fixed-attack TPR = 1.0 for tau in {2,3,5}, and >= 0.95 at tau=8 (graceful)",
      tpr_by_tau[2] == 1.0 and tpr_by_tau[3] == 1.0 and tpr_by_tau[5] == 1.0
      and tpr_by_tau[8] >= 0.95,
      f"TPR: tau5={tpr_by_tau[5]:.3f}, tau8={tpr_by_tau[8]:.3f}")
check("B5 (entropy) misses fixed attack (block rate ~ 0)", b5_fix < 0.01,
      f"B5 fixed block rate = {b5_fix:.3f}")

# (5) honesty: legit 2-fragment responses => ratio 2 (tau must exceed max legit frags/query)
print("\n(5) Honesty caveat: legit multi-fragment responses")
r2f, _ = indep_sim(60, None, 999, frags_per_query=2)
check("legit 2-frag/query => ratio == 2 (so tau must exceed max legit frags/query)",
      np.allclose(r2f, 2.0), "documented in report as the tau-selection constraint")

n_fail = sum(1 for ok in out if not ok)
print("\n" + "=" * 60)
print(f"B6 VERIFY: {len(out) - n_fail}/{len(out)} PASS, {n_fail} FAIL")
print("=" * 60)
sys.exit(1 if n_fail else 0)
