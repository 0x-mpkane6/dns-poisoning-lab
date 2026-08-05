"""E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary of Rℓ₂).

Thí nghiệm E1 trong outline "POPS-Rℓ₂": chạy detector trên *chỉ* lưu lượng
fragment HỢP LỆ (không bật attacker) ở nhiều mức tải khác nhau và đo False
Positive Rate (FPR). Vì không có attacker, mọi quyết định ``tc_block`` đều là
báo động nhầm (false positive) -> FPR = blocks / decisions.

Tính trung thực (fidelity)
--------------------------
Script KHÔNG cài lại thuật toán detector. Nó import trực tiếp hai hàm chấm điểm
gốc từ ``labs/r2entropy/resolver/resolver.py``:

* ``shannon_entropy(values)``  -- entropy Shannon (log2) của tập IPID.
* ``r2_should_block(variant, defense_on, samples, entropy, unique_ratio)``
  -- luật B1..B5 tại operating point 24 / 4.0 / 0.70.

Cửa sổ trượt (sliding window) được mô phỏng đúng như ``R2EntropyTable._prune``:
cutoff = now - FRAG2_WINDOW_SECONDS, loại mọi sự kiện cũ hơn cutoff. Mô hình IPID
hợp lệ lấy đúng từ ``auth/auth_server.py`` (mỗi truy vấn frag phát một FRAG2 với
IPID = randint(0, IPID_SPACE-1)).

Vì sao là testbed mô phỏng chứ không phải Docker
------------------------------------------------
Docker daemon không chạy trong môi trường này, client ``dig`` không có trên
Windows, và quan trọng hơn: auth server hiện tại tuần tự hoá mỗi truy vấn bằng
AUTH_DELAY=0.25s -> tối đa ~4 query/s -> ~8 mẫu/cửa sổ, không thể đạt các mức
{24, 36, 60, 120, 300} mà E1 yêu cầu. Đây đúng là điều README framework đã ghi:
"throughput cần được bổ sung trước khi chạy ma trận E1-E4 chính". Do đó E1 được
chạy trên testbed mô phỏng đã kiểm chứng (cùng mã detector), và mọi kết luận chỉ
áp dụng trong controlled emulation (đúng với Phạm vi kết luận của outline).

Đầu ra
------
* e1_runs.csv    -- một dòng / run (K x levels x behaviors x variants).
* e1_levels.csv  -- tổng hợp / (level, behavior, variant) kèm 95% CI.
* e1_results.json -- toàn bộ kết quả + config + provenance (P0 logging).
* notes.txt      -- mô tả và tóm tắt kết quả.

Usage: python e1_experiment.py [--runs 20] [--decisions 300] [--out .]
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
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from scipy import stats

# Windows consoles default to cp1252; force UTF-8 so Vietnamese/Rℓ₂ prints.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# 0. Import the REAL detector primitives from resolver.py (via dnslib shim).   #
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
# HERE = Code/research/Report/experiments/E1 -> parents[3] = Code
LAB_DIR = HERE.parents[3] / "labs" / "r2entropy"          # Code/labs/r2entropy
RESOLVER_DIR = LAB_DIR / "resolver"
SHIM_DIR = LAB_DIR / "localtest" / "shim"

# Operating point 4.0 / 24 / 0.70 (paper's proposed B5 thresholds) -- resolver.py
# reads these at import time from the environment, so set them BEFORE importing.
OPERATING_POINT = {
    "R2_MIN_SAMPLES": "24",
    "R2_ENTROPY_THRESHOLD": "4.0",
    "R2_UNIQUE_RATIO_THRESHOLD": "0.70",
    "R2_VARIANT": "combined",
    "FRAG2_WINDOW_SECONDS": "2.0",
}
for _k, _v in OPERATING_POINT.items():
    os.environ.setdefault(_k, _v)

sys.path.insert(0, str(SHIM_DIR))       # dependency-free dnslib stand-in
sys.path.insert(0, str(RESOLVER_DIR))   # resolver.py
import resolver as R  # noqa: E402  (import after sys.path / env setup, by design)

# --------------------------------------------------------------------------- #
# 1. Experiment configuration (E1 spec).                                       #
# --------------------------------------------------------------------------- #
WINDOW_SECONDS = float(OPERATING_POINT["FRAG2_WINDOW_SECONDS"])
MIN_SAMPLES = R.R2_MIN_SAMPLES
ENTROPY_THRESHOLD = R.R2_ENTROPY_THRESHOLD
UNIQUE_RATIO_THRESHOLD = R.R2_UNIQUE_RATIO_THRESHOLD

# E1: target samples/window.
SAMPLES_PER_WINDOW_LEVELS = [5, 12, 18, 24, 36, 60, 120, 300]

# Detector variants scored per decision event. "combined" (B5) is the primary
# operating point under test; the others (B2/B3/B4) are reference lines that
# explain *why* B5 behaves as it does at high rate.
VARIANTS = ["combined", "volume", "entropy", "unique"]
PRIMARY_VARIANT = "combined"

# E1: "tối thiểu ba kiểu IPID/source behavior". Each models a legitimate way a
# real host/middlebox assigns the 16-bit IP identification field.
IPID_BEHAVIORS = {
    # Exactly auth_server.py: uniform random over IPID_SPACE=2048. High diversity.
    "random2048": {"kind": "uniform", "space": 2048,
                   "label": "Random IPID (uniform 0..2047) -- auth_server model"},
    # Classic monotonic global counter (older Linux/Windows stacks). All-distinct.
    "sequential": {"kind": "sequential", "space": 2048,
                   "label": "Sequential IPID (global +1 counter)"},
    # Constrained device / NAT / middlebox reusing a tiny IPID pool. Low diversity.
    "smallpool16": {"kind": "uniform", "space": 16,
                    "label": "Small IPID pool (uniform 0..15) -- NAT / constrained host"},
}

EXPERIMENT_SEED = 20260805  # fixed -> reproducible cell ordering & per-cell seeds
WARMUP_MULT = 3.0           # discard first WARMUP_MULT * window seconds (ramp-up)


# --------------------------------------------------------------------------- #
# 2. IPID source model (faithful to auth_server.py benign FRAG2).             #
# --------------------------------------------------------------------------- #
def make_ipid_sampler(behavior: str, rng: random.Random):
    """Return a zero-arg callable producing one benign FRAG2 IPID."""
    cfg = IPID_BEHAVIORS[behavior]
    space = cfg["space"]
    if cfg["kind"] == "uniform":
        # auth_server.py: random.randint(0, IPID_SPACE - 1)
        return lambda: rng.randint(0, space - 1)
    if cfg["kind"] == "sequential":
        start = rng.randint(0, space - 1)
        counter = {"v": start}

        def _seq() -> int:
            val = counter["v"] % space
            counter["v"] += 1
            return val
        return _seq
    raise ValueError(f"unknown behavior kind: {cfg['kind']}")


# --------------------------------------------------------------------------- #
# 3. One run: steady-state benign traffic at a target samples/window.          #
# --------------------------------------------------------------------------- #
@dataclass
class RunResult:
    level: int
    behavior: str
    run_idx: int
    seed: int
    decisions: int
    # blocks per variant (numerator of FPR); decisions is the shared denominator
    blocks: Dict[str, int]
    fpr: Dict[str, float]
    entropy_mean: float
    entropy_p95: float
    samples_mean: float
    unique_ratio_mean: float


def simulate_run(level: int, behavior: str, run_idx: int, seed: int,
                 n_decisions: int) -> RunResult:
    """Simulate one independent run of benign-only traffic.

    Arrivals follow a Poisson process with rate lambda = level / WINDOW so the
    expected occupancy of any WINDOW-second sliding window equals ``level``. Each
    arrival is (a) a benign FRAG2 observed by the detector and (b) a FRAG1 that
    triggers a scoring decision -- exactly the benign-on pairing in auth_server.py.
    The window is pruned with resolver.py's rule (cutoff = t - WINDOW) and scored
    with the real shannon_entropy + r2_should_block.
    """
    rng = random.Random(seed)
    next_ipid = make_ipid_sampler(behavior, rng)
    lam = level / WINDOW_SECONDS          # arrivals per second
    warmup_until = WARMUP_MULT * WINDOW_SECONDS

    window: List[Tuple[float, int]] = []  # (timestamp, ipid), mirrors the deque
    t = 0.0
    blocks = {v: 0 for v in VARIANTS}
    decisions = 0
    entropies: List[float] = []
    samples_seen: List[int] = []
    unique_ratios: List[float] = []

    # Cap total arrivals so a pathological rate can't loop forever.
    max_arrivals = int(warmup_until * lam) + n_decisions * 3 + 1000
    for _ in range(max_arrivals):
        if decisions >= n_decisions:
            break
        # Poisson process -> exponential inter-arrival gaps.
        gap = rng.expovariate(lam) if lam > 0 else 1.0
        t += gap
        window.append((t, next_ipid()))
        # resolver.py R2EntropyTable._prune: drop events older than the window.
        cutoff = t - WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.pop(0)

        if t < warmup_until:
            continue  # ramp-up: window not yet representative of steady state

        ipids = [ipid for _, ipid in window]
        total = len(ipids)
        unique = len(set(ipids))
        entropy = R.shannon_entropy(ipids)                 # REAL detector math
        unique_ratio = (unique / total) if total else 0.0

        decisions += 1
        entropies.append(entropy)
        samples_seen.append(total)
        unique_ratios.append(unique_ratio)
        for variant in VARIANTS:
            if R.r2_should_block(variant, True, total, entropy, unique_ratio):
                blocks[variant] += 1                       # benign block == FP

    fpr = {v: (blocks[v] / decisions if decisions else 0.0) for v in VARIANTS}
    return RunResult(
        level=level, behavior=behavior, run_idx=run_idx, seed=seed,
        decisions=decisions, blocks=blocks, fpr=fpr,
        entropy_mean=float(np.mean(entropies)) if entropies else 0.0,
        entropy_p95=float(np.percentile(entropies, 95)) if entropies else 0.0,
        samples_mean=float(np.mean(samples_seen)) if samples_seen else 0.0,
        unique_ratio_mean=float(np.mean(unique_ratios)) if unique_ratios else 0.0,
    )


# --------------------------------------------------------------------------- #
# 4. Statistics: exact-binomial (Clopper-Pearson) + run-level cluster bootstrap.
# --------------------------------------------------------------------------- #
def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Exact binomial (Clopper-Pearson) 95% CI. Handles k=0 and k=n cleanly.

    This is the interval the outline demands for FPR=0: 0/n is reported as
    [0, upper] -- never as 'FPR is exactly 0'.
    """
    if n == 0:
        return (0.0, 1.0)
    lower = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    upper = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (float(lower), float(upper))


def cluster_bootstrap_fpr(per_run_blocks: List[int], per_run_dec: List[int],
                          n_boot: int = 5000, seed: int = 12345
                          ) -> Tuple[float, float, float]:
    """Hierarchical/cluster bootstrap over RUNS (the independent unit).

    Windows inside a run are dependent, so we resample whole runs with
    replacement and recompute the pooled FPR. Returns (point, lo95, hi95).
    """
    blocks = np.asarray(per_run_blocks, dtype=float)
    dec = np.asarray(per_run_dec, dtype=float)
    point = blocks.sum() / dec.sum() if dec.sum() else 0.0
    if len(blocks) == 0 or dec.sum() == 0:
        return (point, 0.0, 0.0)
    rng = np.random.default_rng(seed)
    n = len(blocks)
    stats_boot = np.empty(n_boot)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        d = dec[idx].sum()
        stats_boot[b] = blocks[idx].sum() / d if d else 0.0
    lo, hi = np.percentile(stats_boot, [2.5, 97.5])
    return (float(point), float(lo), float(hi))


def mean_ci_t(values: List[float]) -> Tuple[float, float, float]:
    """Mean and 95% t-interval across runs (run-level independence)."""
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    m = float(arr.mean()) if n else 0.0
    if n < 2:
        return (m, m, m)
    se = float(arr.std(ddof=1) / math.sqrt(n))
    h = stats.t.ppf(0.975, n - 1) * se
    return (m, m - h, m + h)


# --------------------------------------------------------------------------- #
# 5. Orchestration.                                                            #
# --------------------------------------------------------------------------- #
def git_commit(path: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def cell_seed(level: int, behavior: str, run_idx: int) -> int:
    """Deterministic per-cell seed so results are independent of run order."""
    beh_idx = list(IPID_BEHAVIORS).index(behavior)
    return EXPERIMENT_SEED + level * 100003 + beh_idx * 10007 + run_idx


def main() -> None:
    ap = argparse.ArgumentParser(description="E1 -- FPR vs benign fragment rate")
    ap.add_argument("--runs", type=int, default=20, help="K independent runs / cell")
    ap.add_argument("--decisions", type=int, default=300, help="decision events / run")
    ap.add_argument("--out", type=str, default=str(HERE), help="output directory")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d_%H%M%S")

    print("=" * 78)
    print("E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary của Rℓ₂)")
    print("Ý nghĩa: chạy detector trên lưu lượng CHỈ hợp lệ (no attacker). Mọi lần")
    print("'tc_block' là một false positive. Ta quét samples/window và đo FPR để tìm")
    print("vùng an toàn và điểm detector bắt đầu chặn nhầm người dùng thật.")
    print(f"Operating point B5: samples>={MIN_SAMPLES}, entropy>={ENTROPY_THRESHOLD}, "
          f"unique_ratio>={UNIQUE_RATIO_THRESHOLD}; window={WINDOW_SECONDS}s")
    print(f"K={args.runs} runs/cell, {args.decisions} decisions/run, "
          f"levels={SAMPLES_PER_WINDOW_LEVELS}, behaviors={list(IPID_BEHAVIORS)}")
    print("=" * 78)

    # Build all cells, then randomize execution order (E1: randomize load order).
    cells = [(lvl, beh, r)
             for lvl in SAMPLES_PER_WINDOW_LEVELS
             for beh in IPID_BEHAVIORS
             for r in range(args.runs)]
    order_rng = random.Random(EXPERIMENT_SEED)
    order_rng.shuffle(cells)

    runs: List[RunResult] = []
    t0 = time.time()
    for i, (lvl, beh, r) in enumerate(cells, 1):
        seed = cell_seed(lvl, beh, r)
        runs.append(simulate_run(lvl, beh, r, seed, args.decisions))
        if i % 60 == 0 or i == len(cells):
            print(f"  [{i}/{len(cells)}] cells done ({time.time() - t0:.1f}s)")

    # ---- Per-run CSV (raw, with numerator/denominator per E1/P0) ---------- #
    runs_csv = out_dir / "e1_runs.csv"
    with open(runs_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["level_samples_per_window", "behavior", "run_idx", "seed",
                    "decisions",
                    "blocks_combined", "blocks_volume", "blocks_entropy", "blocks_unique",
                    "fpr_combined", "fpr_volume", "fpr_entropy", "fpr_unique",
                    "entropy_mean", "entropy_p95", "samples_mean", "unique_ratio_mean"])
        for x in sorted(runs, key=lambda z: (z.level, z.behavior, z.run_idx)):
            w.writerow([x.level, x.behavior, x.run_idx, x.seed, x.decisions,
                        x.blocks["combined"], x.blocks["volume"],
                        x.blocks["entropy"], x.blocks["unique"],
                        f"{x.fpr['combined']:.6f}", f"{x.fpr['volume']:.6f}",
                        f"{x.fpr['entropy']:.6f}", f"{x.fpr['unique']:.6f}",
                        f"{x.entropy_mean:.4f}", f"{x.entropy_p95:.4f}",
                        f"{x.samples_mean:.3f}", f"{x.unique_ratio_mean:.4f}"])
    print(f"[+] wrote {runs_csv}")

    # ---- Aggregate per (level, behavior) --------------------------------- #
    levels_rows = []
    results = {
        "meta": {
            "experiment": "E1 -- FPR vs benign fragment rate (operating boundary)",
            "run_id": run_id,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "code_git_commit": git_commit(LAB_DIR),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "detector_source": str((RESOLVER_DIR / "resolver.py").as_posix()),
            "fidelity_note": ("Imports the real shannon_entropy + r2_should_block from "
                              "resolver.py; sliding window mirrors R2EntropyTable._prune; "
                              "IPID model from auth_server.py. Controlled-emulation testbed "
                              "(no Docker / real IP fragmentation)."),
            "operating_point": {
                "min_samples": MIN_SAMPLES,
                "entropy_threshold": ENTROPY_THRESHOLD,
                "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
                "window_seconds": WINDOW_SECONDS,
            },
            "levels_samples_per_window": SAMPLES_PER_WINDOW_LEVELS,
            "behaviors": {k: v["label"] for k, v in IPID_BEHAVIORS.items()},
            "variants": VARIANTS,
            "primary_variant": PRIMARY_VARIANT,
            "runs_per_cell": args.runs,
            "decisions_per_run": args.decisions,
            "experiment_seed": EXPERIMENT_SEED,
            "fpr_definition": "false positives = benign tc_block; FPR = blocks / decisions",
        },
        "levels": [],
    }

    for beh in IPID_BEHAVIORS:
        for lvl in SAMPLES_PER_WINDOW_LEVELS:
            cell_runs = [x for x in runs if x.level == lvl and x.behavior == beh]
            dec = [x.decisions for x in cell_runs]
            total_dec = int(sum(dec))
            entry: Dict[str, object] = {
                "behavior": beh, "level": lvl,
                "n_runs": len(cell_runs), "total_decisions": total_dec,
                "samples_mean": float(np.mean([x.samples_mean for x in cell_runs])),
                "variants": {},
            }
            ent_m, ent_lo, ent_hi = mean_ci_t([x.entropy_mean for x in cell_runs])
            uni_m, uni_lo, uni_hi = mean_ci_t([x.unique_ratio_mean for x in cell_runs])
            entry["entropy_mean"] = ent_m
            entry["entropy_ci95"] = [ent_lo, ent_hi]
            entry["unique_ratio_mean"] = uni_m
            entry["unique_ratio_ci95"] = [uni_lo, uni_hi]

            for variant in VARIANTS:
                blk = [x.blocks[variant] for x in cell_runs]
                total_blk = int(sum(blk))
                # Run-level mean FPR + t-interval (primary; respects independence)
                run_fprs = [x.fpr[variant] for x in cell_runs]
                m, lo, hi = mean_ci_t(run_fprs)
                # Cluster bootstrap over runs (pooled point + CI)
                bp, blo, bhi = cluster_bootstrap_fpr(blk, dec)
                # Exact binomial on pooled counts (for the FPR=0 upper-bound claim)
                cp_lo, cp_hi = clopper_pearson(total_blk, total_dec)
                entry["variants"][variant] = {
                    "blocks_total": total_blk,
                    "decisions_total": total_dec,
                    "fpr_pooled": (total_blk / total_dec) if total_dec else 0.0,
                    "fpr_run_mean": m,
                    "fpr_run_ci95_t": [lo, hi],
                    "fpr_cluster_bootstrap_ci95": [blo, bhi],
                    "fpr_clopper_pearson_ci95": [cp_lo, cp_hi],
                }
                levels_rows.append([
                    beh, lvl, variant, len(cell_runs), total_blk, total_dec,
                    f"{(total_blk / total_dec) if total_dec else 0.0:.6f}",
                    f"{m:.6f}", f"{lo:.6f}", f"{hi:.6f}",
                    f"{cp_lo:.6f}", f"{cp_hi:.6f}",
                ])
            results["levels"].append(entry)

    levels_csv = out_dir / "e1_levels.csv"
    with open(levels_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["behavior", "level_samples_per_window", "variant", "n_runs",
                    "blocks_total", "decisions_total", "fpr_pooled",
                    "fpr_run_mean", "fpr_run_ci_lo", "fpr_run_ci_hi",
                    "fpr_cp_ci_lo", "fpr_cp_ci_hi"])
        w.writerows(levels_rows)
    print(f"[+] wrote {levels_csv}")

    results_json = out_dir / "e1_results.json"
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] wrote {results_json}")

    # ---- Console summary: the failure boundary (primary variant) ---------- #
    print("\n" + "=" * 78)
    print(f"KẾT QUẢ E1 -- FPR của detector B5 (combined) trên benign, theo samples/window")
    print("Nhắc lại: đây là báo động NHẦM. FPR càng cao = càng chặn nhầm người dùng thật.")
    print("=" * 78)
    for beh in IPID_BEHAVIORS:
        print(f"\n[{beh}] {IPID_BEHAVIORS[beh]['label']}")
        print(f"  {'s/win':>6} {'FPR(run-mean)':>14} {'95% CI':>20} "
              f"{'entropy':>9} {'uniq':>6}")
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            cv = entry["variants"][PRIMARY_VARIANT]
            lo, hi = cv["fpr_run_ci95_t"]
            ci = f"[{lo:.3f}, {hi:.3f}]"
            print(f"  {entry['level']:>6} {cv['fpr_run_mean']:>14.3f} {ci:>20} "
                  f"{entry['entropy_mean']:>9.3f} {entry['unique_ratio_mean']:>6.3f}")

        # failure boundary = first level whose FPR run-CI lower bound > 0
        boundary = None
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            lo, _ = entry["variants"][PRIMARY_VARIANT]["fpr_run_ci95_t"]
            if lo > 0:
                boundary = entry["level"]
                break
        if boundary is not None:
            print(f"  -> failure boundary (FPR CI lower bound > 0) tại "
                  f"samples/window = {boundary}")
        else:
            print("  -> không quan sát false positive ở mọi mức đã thử (safe).")

    print("\n[✓] E1 hoàn tất. Xem e1_levels.csv / e1_results.json và figures/.")
    _write_notes(out_dir, results, args)


def _write_notes(out_dir: Path, results: dict, args) -> None:
    lines = []
    lines.append("E1 -- FPR theo tốc độ fragment hợp lệ (operating boundary của Rℓ₂)")
    lines.append("=" * 70)
    lines.append("")
    lines.append("MỤC TIÊU (outline E1): xác định operating boundary của detector trên")
    lines.append("benign traffic và đo FPR ở/ngoài vùng samples < MIN_SAMPLES.")
    lines.append("")
    lines.append("THIẾT LẬP:")
    m = results["meta"]
    lines.append(f"  - detector: {m['detector_source']} (import trực tiếp, không cài lại)")
    lines.append(f"  - operating point B5: {m['operating_point']}")
    lines.append(f"  - levels samples/window: {m['levels_samples_per_window']}")
    lines.append(f"  - behaviors: {list(m['behaviors'])}")
    lines.append(f"  - K = {m['runs_per_cell']} runs/cell, {m['decisions_per_run']} decisions/run")
    lines.append(f"  - FPR = {m['fpr_definition']}")
    lines.append("")
    lines.append("KẾT QUẢ CHÍNH (variant combined = B5):")
    for beh in results["meta"]["behaviors"]:
        lines.append(f"  [{beh}]")
        for entry in results["levels"]:
            if entry["behavior"] != beh:
                continue
            cv = entry["variants"]["combined"]
            lo, hi = cv["fpr_run_ci95_t"]
            lines.append(f"    s/win={entry['level']:>3}: FPR={cv['fpr_run_mean']:.3f} "
                         f"CI=[{lo:.3f},{hi:.3f}] entropy={entry['entropy_mean']:.3f} "
                         f"uniq={entry['unique_ratio_mean']:.3f}")
    lines.append("")
    lines.append("DIỄN GIẢI: xem E1_report.md.")
    (out_dir / "notes.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] wrote {out_dir / 'notes.txt'}")


if __name__ == "__main__":
    main()
