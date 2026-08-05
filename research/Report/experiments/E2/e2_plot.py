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
              "attack_fixed": "#CC0000", "attack_bursty": "#009E73"}
COND_MARK = {"attack_sweep": "o", "attack_random": "s", "attack_fixed": "X",
             "attack_bursty": "^"}
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
    # annotate levels on the sweep line
    for lvl in LEVELS:
        fpr = block_rate("benign", lvl, "combined")
        tpr = block_rate("attack_sweep", lvl, "combined")
        ax.annotate(f"{lvl}", (fpr, tpr), textcoords="offset points",
                    xytext=(6, -10), fontsize=8, color="#333")
    ax.set_xlim(-0.03, 1.03); ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("FPR  = benign bị chặn  (cùng volume)")
    ax.set_ylabel("TPR  = attack bị chặn")
    ax.set_title("E2 — Detector B5 ở CÙNG volume: TPR vs FPR\n"
                 "High-entropy attack nằm TRÊN đường chéo (không phân biệt);\n"
                 "attack_fixed rơi xuống TPR=0 (B5 bị né). Kích thước điểm = samples/window",
                 fontsize=10.5)
    ax.grid(True, ls=":", alpha=0.4)
    ax.legend(loc="lower right", fontsize=8.5, framealpha=0.95)
    # region labels
    ax.text(0.5, 0.96, "vùng phân biệt tốt (TPR≫FPR)", fontsize=8.5,
            color="#00694d", ha="center")
    ax.text(0.62, 0.30, "attack_fixed: B5 miss hoàn toàn\n(entropy=0 < 4.0)",
            fontsize=8.5, color="#CC0000", ha="center")
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
    for d in RESULTS["discrimination"]:
        ent_auc[d["attack"]].append(d["pr_auc_entropy"])
        vol_auc[d["attack"]].append(d["pr_auc_volume"])
    x = np.arange(len(attacks))
    w = 0.36
    ax1.bar(x - w / 2, [np.mean(ent_auc[a]) for a in attacks], w,
            label="PR-AUC entropy", color="#0072B2")
    ax1.bar(x + w / 2, [np.mean(vol_auc[a]) for a in attacks], w,
            label="PR-AUC volume", color="#E69F00")
    ax1.axhline(0.5, color="#888", ls="--", lw=1.2)
    ax1.text(len(attacks) - 0.5, 0.52, "chance = 0.5", fontsize=8.5, color="#555", ha="right")
    ax1.set_xticks(x); ax1.set_xticklabels([a.replace("attack_", "") for a in attacks], fontsize=9)
    ax1.set_ylabel("PR-AUC (attack=positive), trung bình theo level")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("(a) Sức phân biệt ở cùng volume: entropy vs volume\n"
                  "(fixed: entropy tách hoàn toàn nhưng NGƯỢC chiều — xem panel b)", fontsize=9.5)
    ax1.legend(fontsize=8.5); ax1.grid(True, axis="y", ls=":", alpha=0.4)

    # (b) entropy distributions at a representative matched volume
    lvl = 120 if 120 in LEVELS else LEVELS[-1]
    ent = _load_entropy_by_cond(lvl)
    order = ["benign", "attack_sweep", "attack_random", "attack_fixed", "attack_bursty"]
    order = [c for c in order if c in ent]
    colors = {"benign": "#444444", "attack_sweep": "#0072B2", "attack_random": "#D55E00",
              "attack_fixed": "#CC0000", "attack_bursty": "#009E73"}
    parts = ax2.violinplot([ent[c] for c in order], showmeans=True, showextrema=False)
    for pc, c in zip(parts["bodies"], order):
        pc.set_facecolor(colors[c]); pc.set_alpha(0.55)
    ax2.axhline(META["operating_point"]["entropy_threshold"], color="#444", ls="--", lw=1.3)
    ax2.text(0.6, META["operating_point"]["entropy_threshold"] + 0.15,
             f"entropy gate = {META['operating_point']['entropy_threshold']}",
             fontsize=8.5, color="#444")
    ax2.set_xticks(range(1, len(order) + 1))
    ax2.set_xticklabels([c.replace("attack_", "") for c in order], fontsize=8.5, rotation=15)
    ax2.set_ylabel("Per-window IPID entropy (bits)")
    ax2.set_title(f"(b) Phân phối entropy tại samples/window = {lvl}\n"
                  "benign ≈ sweep/random/bursty (chồng lấn) — fixed ~0 (dưới gate)", fontsize=9.5)
    ax2.grid(True, axis="y", ls=":", alpha=0.4)

    fig.suptitle("E2 — Ở cùng volume, entropy KHÔNG tách benign khỏi high-entropy attack; "
                 "và bị attack_fixed né (entropy=0)", fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIG_DIR / "Figure_2.png", dpi=160)
    plt.close(fig)
    print(f"[+] wrote {FIG_DIR / 'Figure_2.png'}")


if __name__ == "__main__":
    print("Rendering E2 figures:")
    print("  Fig 1: TPR-vs-FPR at matched volume (B5 on the no-discrimination diagonal).")
    print("  Fig 2: PR-AUC entropy~volume + entropy-distribution overlap.")
    figure_1()
    figure_2()
    print("done.")
