"""Publication figures for E1 from e1_results.json.

Figure_1.png -- FPR vs samples/window (primary detector B5=combined), 95% CI
               bands per IPID behavior, MIN_SAMPLES marked. THE headline figure.
Figure_2.png -- entropy(rate) and unique_ratio(rate) with the two B5 gate
               thresholds, explaining *why* FPR behaves as it does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
FIG_DIR = HERE / "figures"
FIG_DIR.mkdir(exist_ok=True)

# Theme-neutral, colorblind-safe palette (Okabe-Ito subset).
COLORS = {"random2048": "#0072B2", "sequential": "#D55E00", "smallpool16": "#009E73"}
MARKERS = {"random2048": "o", "sequential": "s", "smallpool16": "^"}

with open(HERE / "e1_results.json", encoding="utf-8") as f:
    RESULTS = json.load(f)

META = RESULTS["meta"]
BEHAVIORS = list(META["behaviors"])
LABEL = META["behaviors"]
LEVELS = META["levels_samples_per_window"]
MIN_SAMPLES = META["operating_point"]["min_samples"]
ENT_THR = META["operating_point"]["entropy_threshold"]
UNIQ_THR = META["operating_point"]["unique_ratio_threshold"]


def series(behavior: str, key_path):
    """Extract a per-level series for one behavior. key_path is a callable(entry)."""
    xs, ys = [], []
    for entry in RESULTS["levels"]:
        if entry["behavior"] != behavior:
            continue
        xs.append(entry["level"])
        ys.append(key_path(entry))
    order = np.argsort(xs)
    return np.array(xs)[order], np.array(ys, dtype=object)[order]


def fpr_series(behavior: str):
    xs, mean, lo, hi = [], [], [], []
    for entry in sorted((e for e in RESULTS["levels"] if e["behavior"] == behavior),
                        key=lambda e: e["level"]):
        cv = entry["variants"]["combined"]
        xs.append(entry["level"])
        mean.append(cv["fpr_run_mean"])
        l, h = cv["fpr_run_ci95_t"]
        lo.append(max(0.0, l))
        hi.append(min(1.0, h))
    return np.array(xs), np.array(mean), np.array(lo), np.array(hi)


def ci_series(behavior: str, mean_key: str, ci_key: str):
    xs, mean, lo, hi = [], [], [], []
    for entry in sorted((e for e in RESULTS["levels"] if e["behavior"] == behavior),
                        key=lambda e: e["level"]):
        xs.append(entry["level"])
        mean.append(entry[mean_key])
        l, h = entry[ci_key]
        lo.append(l)
        hi.append(h)
    return np.array(xs), np.array(mean), np.array(lo), np.array(hi)


# --------------------------------------------------------------------------- #
# Figure 1 -- FPR(rate) : the operating boundary.                             #
# --------------------------------------------------------------------------- #
def figure_1() -> None:
    fig, ax = plt.subplots(figsize=(8.2, 5.4))
    for beh in BEHAVIORS:
        xs, mean, lo, hi = fpr_series(beh)
        ax.plot(xs, mean, marker=MARKERS[beh], color=COLORS[beh], lw=2.0,
                ms=6, label=LABEL[beh], zorder=3)
        ax.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18, zorder=2)

    ax.axvline(MIN_SAMPLES, color="#444444", ls="--", lw=1.3, zorder=1)
    ax.text(MIN_SAMPLES * 1.03, 0.06, f"MIN_SAMPLES = {MIN_SAMPLES}",
            rotation=90, va="bottom", ha="left", fontsize=9, color="#444444")

    # Shade the empirically-safe region (below the first false positive).
    ax.axvspan(min(LEVELS) * 0.8, 15, color="#009E73", alpha=0.06, zorder=0)
    ax.text(6.2, 0.9, "vùng an toàn\n(safe region)", fontsize=9,
            color="#00694d", ha="center", va="center")

    ax.set_xscale("log")
    ax.set_xticks(LEVELS)
    ax.set_xticklabels([str(v) for v in LEVELS])
    ax.set_xlim(min(LEVELS) * 0.85, max(LEVELS) * 1.15)
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("Benign fragment load — samples / window (2.0 s)")
    ax.set_ylabel("False Positive Rate  (benign tc_block / decisions)")
    ax.set_title("E1 — FPR của detector B5 (combined) theo tốc độ fragment hợp lệ\n"
                 "Chỉ có lưu lượng HỢP LỆ: mọi block là báo động nhầm. Bóng = 95% CI (run-level)",
                 fontsize=11)
    ax.grid(True, which="both", ls=":", alpha=0.4)
    ax.legend(loc="center right", fontsize=9, framealpha=0.95)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "Figure_1.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_1.png'}")


# --------------------------------------------------------------------------- #
# Figure 2 -- why: entropy & unique_ratio vs the two B5 gates.                #
# --------------------------------------------------------------------------- #
def figure_2() -> None:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 5.2))

    for beh in BEHAVIORS:
        xs, m, lo, hi = ci_series(beh, "entropy_mean", "entropy_ci95")
        ax1.plot(xs, m, marker=MARKERS[beh], color=COLORS[beh], lw=2, ms=6,
                 label=LABEL[beh])
        ax1.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18)
    ax1.axhline(ENT_THR, color="#444", ls="--", lw=1.3)
    ax1.text(min(xs), ENT_THR + 0.08, f"entropy gate = {ENT_THR}", fontsize=9, color="#444")
    ax1.axvline(MIN_SAMPLES, color="#888", ls=":", lw=1.1)
    ax1.set_xscale("log")
    ax1.set_xticks(LEVELS); ax1.set_xticklabels([str(v) for v in LEVELS])
    ax1.set_xlabel("samples / window")
    ax1.set_ylabel("Mean IPID entropy (bits, log2)")
    ax1.set_title("(a) Entropy(rate) vs entropy gate")
    ax1.grid(True, which="both", ls=":", alpha=0.4)
    ax1.legend(fontsize=8, loc="lower right")

    for beh in BEHAVIORS:
        xs, m, lo, hi = ci_series(beh, "unique_ratio_mean", "unique_ratio_ci95")
        ax2.plot(xs, m, marker=MARKERS[beh], color=COLORS[beh], lw=2, ms=6,
                 label=LABEL[beh])
        ax2.fill_between(xs, lo, hi, color=COLORS[beh], alpha=0.18)
    ax2.axhline(UNIQ_THR, color="#444", ls="--", lw=1.3)
    ax2.text(min(xs), UNIQ_THR - 0.06, f"unique_ratio gate = {UNIQ_THR}", fontsize=9, color="#444")
    ax2.axvline(MIN_SAMPLES, color="#888", ls=":", lw=1.1)
    ax2.set_xscale("log")
    ax2.set_xticks(LEVELS); ax2.set_xticklabels([str(v) for v in LEVELS])
    ax2.set_xlabel("samples / window")
    ax2.set_ylabel("Mean unique_ratio")
    ax2.set_ylim(0, 1.05)
    ax2.set_title("(b) unique_ratio(rate) vs unique gate")
    ax2.grid(True, which="both", ls=":", alpha=0.4)
    ax2.legend(fontsize=8, loc="lower left")

    fig.suptitle("E1 — Vì sao B5 báo nhầm: nguồn IPID đa dạng (random/sequential) vượt CẢ hai gate "
                 "khi tải tăng;\nnguồn IPID nghèo (small pool) bị unique_ratio gate chặn lại → không FP",
                 fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIG_DIR / "Figure_2.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_2.png'}")


if __name__ == "__main__":
    print("Rendering E1 figures — this is what the results are meant to show:")
    print("  Fig 1: the FPR failure boundary on benign traffic.")
    print("  Fig 2: the entropy/unique_ratio mechanism behind it.")
    figure_1()
    figure_2()
    print("[✓] figures done.")
