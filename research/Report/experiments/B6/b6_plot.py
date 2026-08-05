"""Figures for B6 (per-query multiplicity detector) vs B2 / B5."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = Path(__file__).resolve().parent
FIG = HERE / "figures"; FIG.mkdir(exist_ok=True)
R = json.load(open(HERE / "b6_results.json", encoding="utf-8"))
COL = {"B2": "#E69F00", "B5": "#0072B2", "B6": "#009E73"}


def fig1_benign_fpr():
    fig, ax = plt.subplots(figsize=(8.0, 5.2))
    levels = [r["level"] for r in R["P1_benign_fpr"]]
    for det in ("B2", "B5", "B6"):
        y = [r[det]["fpr"] for r in R["P1_benign_fpr"]]
        lab = {"B2": "B2 volume-only", "B5": "B5 combined (đề xuất cũ)",
               "B6": "B6 per-query (đề xuất mới)"}[det]
        ax.plot(levels, y, marker="o", color=COL[det], lw=2.2, ms=6, label=lab)
    ax.axvline(24, color="#666", ls="--", lw=1.1)
    ax.text(24 * 1.03, 0.55, "MIN_SAMPLES=24", rotation=90, fontsize=8.5, color="#666")
    ax.set_xscale("log"); ax.set_xticks(levels); ax.set_xticklabels([str(v) for v in levels])
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("Tải benign — samples/window (không có attacker)")
    ax.set_ylabel("False Positive Rate")
    ax.set_title("B6 xoá false positive trên benign\n"
                 "B2/B5 chặn nhầm khi tải tăng; B6 giữ FPR = 0 ở mọi mức", fontsize=11)
    ax.grid(True, which="both", ls=":", alpha=0.4); ax.legend(fontsize=9)
    fig.tight_layout(); fig.savefig(FIG / "Figure_1.png", dpi=160); plt.close(fig)
    print(f"[+] {FIG/'Figure_1.png'}")


def fig2_tpr_fpr():
    # grouped bars at a representative level: TPR(avg over attacks) and benign FPR
    lvl = 60
    dets = ["B2", "B5", "B6"]
    tpr = {d: [] for d in dets}
    fpr = {d: None for d in dets}
    for row in R["P2_matched"]:
        if row["level"] != lvl:
            continue
        for d in dets:
            tpr[d].append(row[f"TPR_{d}"]["mean"])
            fpr[d] = row[f"FPR_{d}"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.6, 5.2))

    x = np.arange(len(dets)); w = 0.38
    ax1.bar(x - w / 2, [np.mean(tpr[d]) for d in dets], w, label="TPR (trung bình 4 attack)",
            color="#009E73")
    ax1.bar(x + w / 2, [fpr[d] for d in dets], w, label="FPR (benign, cùng volume)",
            color="#CC5555")
    ax1.set_xticks(x); ax1.set_xticklabels(["B2\nvolume", "B5\ncombined", "B6\nper-query"])
    ax1.set_ylim(0, 1.08); ax1.set_ylabel("tỉ lệ")
    ax1.set_title(f"(a) Ở samples/window={lvl}: chỉ B6 đạt TPR cao VÀ FPR=0", fontsize=10)
    for i, d in enumerate(dets):
        ax1.text(i - w / 2, np.mean(tpr[d]) + 0.02, f"{np.mean(tpr[d]):.2f}", ha="center", fontsize=8)
        ax1.text(i + w / 2, fpr[d] + 0.02, f"{fpr[d]:.2f}", ha="center", fontsize=8)
    ax1.legend(fontsize=8.5); ax1.grid(True, axis="y", ls=":", alpha=0.4)

    # panel b: TPR on the fixed (adaptive) attack across levels
    levels = sorted({r["level"] for r in R["P2_matched"]})
    for d in dets:
        y = [next(r[f"TPR_{d}"]["mean"] for r in R["P2_matched"]
                  if r["attack"] == "attack_fixed" and r["level"] == lv) for lv in levels]
        ax2.plot(levels, y, marker="o", color=COL[d], lw=2.2, ms=6,
                 label={"B2": "B2", "B5": "B5", "B6": "B6"}[d])
    ax2.set_xscale("log"); ax2.set_xticks(levels); ax2.set_xticklabels([str(v) for v in levels])
    ax2.set_ylim(-0.03, 1.05); ax2.set_xlabel("samples/window")
    ax2.set_ylabel("TPR trên attack_fixed (IPID=777)")
    ax2.set_title("(b) Attack adaptive fixed-IPID: B5 miss hẳn (TPR=0),\nB6 vẫn bắt (TPR=1)", fontsize=10)
    ax2.grid(True, which="both", ls=":", alpha=0.4); ax2.legend(fontsize=9)

    fig.suptitle("B6 vượt B2 và B5 ở cùng volume: bắt được mọi attack (kể cả fixed) mà không báo nhầm benign",
                 fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.94)); fig.savefig(FIG / "Figure_2.png", dpi=160); plt.close(fig)
    print(f"[+] {FIG/'Figure_2.png'}")


def fig3_tradeoff():
    P3 = R["P3_intensity"]
    mq = [r["intensity_M_over_Q"] for r in P3]
    fig, ax = plt.subplots(figsize=(8.4, 5.4))
    ax.plot(mq, [r["TPR_B6"] for r in P3], marker="o", color=COL["B6"], lw=2.4, ms=7,
            label="TPR của B6 (bị phát hiện)")
    ax.plot(mq, [r["poison_success_proxy"] for r in P3], marker="s", color="#CC0000",
            lw=2.2, ms=6, label="Xác suất poison (proxy)")
    ax.axhline(0.5, color="#999", ls=":", lw=1)
    ax.set_xscale("symlog", linthresh=0.2)
    ax.set_xlabel("Cường độ tấn công  M/Q  (forgeries trên mỗi truy vấn hợp lệ)")
    ax.set_ylabel("tỉ lệ")
    ax.set_ylim(-0.03, 1.05)
    ax.set_title("Đánh đổi phát hiện–né tránh của B6\n"
                 "Muốn poison hiệu quả (success↑) thì M/Q phải lớn → B6 phát hiện (TPR→1).\n"
                 "Muốn né B6 (TPR thấp) thì M/Q nhỏ → success ~ 0.", fontsize=10.5)
    # shade the "attacker loses" zones
    ax.axvspan(5, mq[-1], color="#009E73", alpha=0.07)
    ax.text(15, 0.15, "loud → bị bắt", color="#00694d", fontsize=9, ha="center")
    ax.text(0.35, 0.9, "quiet → vô hại", color="#555", fontsize=9, ha="center")
    ax.grid(True, ls=":", alpha=0.4); ax.legend(fontsize=9, loc="center right")
    fig.tight_layout(); fig.savefig(FIG / "Figure_3.png", dpi=160); plt.close(fig)
    print(f"[+] {FIG/'Figure_3.png'}")


if __name__ == "__main__":
    fig1_benign_fpr()
    fig2_tpr_fpr()
    fig3_tradeoff()
    print("done.")
