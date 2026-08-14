"""Publication figures for E2 from e2_results.json + e2_windows.csv.

Figure_1.png -- at matched volume, TPR(attack) vs FPR(benign) for B5: high-entropy
               attacks fall ON the diagonal (no discrimination); the fixed-IPID
               attack falls to TPR=0 (B5 evaded).
Figure_2.png -- (a) PR-AUC entropy vs volume per condition (near chance);
               (b) per-window entropy distributions: benign vs sweep overlap,
               fixed sits at ~0 -> the deployed high-entropy rule points the wrong way.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
FIG_DIR = HERE / "figures"
FIG_DIR.mkdir(exist_ok=True)

with open(HERE / "e2_results.json", encoding="utf-8") as f:
    RESULTS = json.load(f)
META = RESULTS["meta"]
LEVELS = META["levels"]

COND_COLOR = {"attack_sweep": "#0072B2", "attack_random": "#D55E00",
              "attack_fixed": "#CC0000", "attack_bursty": "#009E73",
              "attack_dup_sweep": "#7B3FBF"}
COND_MARK = {"attack_sweep": "o", "attack_random": "s", "attack_fixed": "X",
             "attack_bursty": "^", "attack_dup_sweep": "P"}
LEVEL_SIZE = {lvl: 60 + 22 * i for i, lvl in enumerate(LEVELS)}


def block_rate(cond, lvl, variant):
    for e in RESULTS["block_rates"]:
        if e["condition"] == cond and e["level"] == lvl:
            return e["variants"][variant]["block_rate_mean"]
    return float("nan")


# --------------------------------------------------------------------------- #
# Figure 1 -- TPR vs FPR at matched volume (detector B5).                      #
# --------------------------------------------------------------------------- #
def figure_1() -> None:
    fig, ax = plt.subplots(figsize=(7.6, 6.8))
    ax.plot([0, 1], [0, 1], ls="--", color="#888", lw=1.4, zorder=1,
            label="đường không phân biệt (TPR=FPR)")
    for cond in COND_COLOR:
        xs, ys = [], []
        for lvl in LEVELS:
            fpr = block_rate("benign", lvl, "combined")   # benign block = FPR
            tpr = block_rate(cond, lvl, "combined")        # attack block = TPR
            xs.append(fpr); ys.append(tpr)
            ax.scatter(fpr, tpr, s=LEVEL_SIZE[lvl], color=COND_COLOR[cond],
                       marker=COND_MARK[cond], edgecolor="white", lw=0.8, zorder=3)
        ax.plot(xs, ys, color=COND_COLOR[cond], lw=1.0, alpha=0.5, zorder=2,
                label=cond)
    # Label only the lowest level: the higher levels all collapse onto (1,1) and
    # their labels would overprint each other.
    lvl0 = min(LEVELS)
    ax.annotate(f"mức {lvl0}",
                (block_rate("benign", lvl0, "combined"),
                 block_rate("attack_sweep", lvl0, "combined")),
                textcoords="offset points", xytext=(8, -4), fontsize=8, color="#333")
    ax.annotate(f"mức ≥{sorted(LEVELS)[1]}", (1.0, 1.0), textcoords="offset points",
                xytext=(-64, 4), fontsize=8, color="#333")
    # Rℓ2 gốc (legacy): chặn mọi fragment -> mọi attack TPR=1 nhưng benign FPR=1 -> góc (1,1)
    ax.scatter(1.0, 1.0, s=300, marker="D", color="#111111", edgecolor="white", lw=1.2,
               zorder=5, label="Rℓ2 gốc")
    ax.set_xlim(-0.03, 1.06); ax.set_ylim(-0.06, 1.08)
    ax.set_xlabel("FPR (benign bị chặn)")
    ax.set_ylabel("TPR (attack bị chặn)")
    ax.grid(True, ls=":", alpha=0.4)
    # upper-left is the empty half of the plane -> legend never covers the data
    # (attack_fixed sits at TPR = 0, which a lower-right legend would hide).
    ax.legend(loc="upper left", fontsize=8.5, framealpha=0.95)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "Figure_1.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_1.png'}")


# --------------------------------------------------------------------------- #
# Figure 2 -- PR-AUC (entropy vs volume) + entropy distribution overlap.       #
# --------------------------------------------------------------------------- #
def _load_entropy_by_cond(level: int):
    data = defaultdict(list)
    with open(HERE / "e2_windows.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if int(row["level"]) == level:
                data[row["condition"]].append(float(row["entropy"]))
    return {k: np.array(v) for k, v in data.items()}


def figure_2() -> None:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.2, 5.4))

    # (a) PR-AUC entropy vs volume, grouped by attack condition (avg over levels)
    attacks = list(COND_COLOR)
    ent_auc = {a: [] for a in attacks}
    vol_auc = {a: [] for a in attacks}
    uni_auc = {a: [] for a in attacks}
    for d in RESULTS["discrimination"]:
        ent_auc[d["attack"]].append(d["pr_auc_entropy"])
        vol_auc[d["attack"]].append(d["pr_auc_volume"])
        uni_auc[d["attack"]].append(d["pr_auc_unique"])
    x = np.arange(len(attacks))
    w = 0.27
    ax1.bar(x - w, [np.mean(ent_auc[a]) for a in attacks], w,
            label="PR-AUC entropy", color="#0072B2")
    ax1.bar(x, [np.mean(uni_auc[a]) for a in attacks], w,
            label="PR-AUC unique_ratio", color="#009E73")
    ax1.bar(x + w, [np.mean(vol_auc[a]) for a in attacks], w,
            label="PR-AUC volume", color="#E69F00")
    ax1.axhline(0.5, color="#888", ls="--", lw=1.2, label="mức ngẫu nhiên = 0.5")
    ax1.set_xticks(x); ax1.set_xticklabels([a.replace("attack_", "").replace("dup_sweep","dup-sweep") for a in attacks], fontsize=8.5)
    ax1.set_ylabel("PR-AUC (trung bình theo level)")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("(a)", fontsize=10)
    ax1.legend(fontsize=8.5); ax1.grid(True, axis="y", ls=":", alpha=0.4)

    # (b) entropy distributions at a representative matched volume
    lvl = 120 if 120 in LEVELS else LEVELS[-1]
    ent = _load_entropy_by_cond(lvl)
    order = ["benign", "attack_sweep", "attack_random", "attack_fixed", "attack_bursty",
             "attack_dup_sweep"]
    order = [c for c in order if c in ent]
    colors = {"benign": "#444444", "attack_sweep": "#0072B2", "attack_random": "#D55E00",
              "attack_fixed": "#CC0000", "attack_bursty": "#009E73",
              "attack_dup_sweep": "#7B3FBF"}
    parts = ax2.violinplot([ent[c] for c in order], showmeans=True, showextrema=False)
    for pc, c in zip(parts["bodies"], order):
        pc.set_facecolor(colors[c]); pc.set_alpha(0.55)
    ax2.axhline(META["operating_point"]["entropy_threshold"], color="#444", ls="--", lw=1.2,
                label=f"ngưỡng entropy = {META['operating_point']['entropy_threshold']}")
    ax2.set_xticks(range(1, len(order) + 1))
    ax2.set_xticklabels([c.replace("attack_", "") for c in order], fontsize=8, rotation=20)
    ax2.set_ylabel("entropy mỗi cửa sổ (bit)")
    ax2.set_title(f"(b)  samples/window = {lvl}", fontsize=10)
    ax2.legend(fontsize=8.5)
    ax2.grid(True, axis="y", ls=":", alpha=0.4)

    fig.tight_layout()
    fig.savefig(FIG_DIR / "Figure_2.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_2.png'}")


if __name__ == "__main__":
    print("Rendering E2 figures:")
    figure_1()
    figure_2()
    print("done.")
