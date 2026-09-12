#!/usr/bin/env python3
"""Render the compact RQ2 figure from frozen E3 JSON artifacts with Matplotlib.

The native canvas is 7.0 x 3.6 inches at 300 dpi. All standard text is at
least 8 pt at that print size. This script never opens a decision-level CSV.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.lines import Line2D
from matplotlib.patches import Patch


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
E3_ROOT = ROOT.parent / "E3"
DPI = 300
TEAL, SAGE, CORAL = "#31AEA9", "#82A096", "#FF5E4A"
PURPLE, GOLD, INK = "#7E47A6", "#FAC42C", "#191E28"
BLUE, GREY, ORANGE = "#1976AE", "#69707C", "#E59F00"


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(protocol: dict[str, Any], grid: dict[str, Any], lock: dict[str, Any], test: dict[str, Any], protocol_path: Path,
           grid_path: Path) -> None:
    if grid.get("status") != "validation_sweep_complete_no_selection":
        raise ValueError("E3 validation grid is not the frozen no-selection artifact")
    if grid.get("protocol", {}).get("sha256") != sha256_file(protocol_path):
        raise ValueError("Validation-grid protocol provenance mismatch")
    if lock.get("validation_grid", {}).get("sha256") != sha256_file(grid_path):
        raise ValueError("Lock validation-grid provenance mismatch")
    if test.get("held_out_evaluation", {}).get("candidate") != lock.get("selected_candidate"):
        raise ValueError("Held-out result is not from the locked candidate")


def build_heatmap_matrix(grid: dict[str, Any]) -> tuple[np.ndarray, list[int], list[int], list[float]]:
    ns, hs, us = [8, 16, 24, 48], [2, 3, 4, 5, 6], [0.5, 0.7, 0.9]
    by_key = {(item["candidate"]["min_samples"], item["candidate"]["entropy_threshold"], item["candidate"]["unique_ratio_threshold"]): item for item in grid["candidates"]}
    matrix = np.array([[float(by_key[(n, h, u)]["primary"]["macro"]["delta_J_new_vs_B2"]) for n in ns for u in us] for h in hs])
    return matrix, ns, hs, us


def draw_panel_a(ax: plt.Axes, key_ax: plt.Axes, grid: dict[str, Any], lock: dict[str, Any]) -> None:
    matrix, ns, hs, us = build_heatmap_matrix(grid)
    cmap = LinearSegmentedColormap.from_list("rq2_teal_sage_coral", [TEAL, SAGE, CORAL])
    image = ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=float(matrix.min()), vmax=float(matrix.max()))
    ax.set_xticks(range(12), [f"{u:.1f}" for _ in ns for u in us], fontsize=8)
    ax.set_yticks(range(5), hs, fontsize=8)
    ax.set_xlabel("Unique-ratio threshold U₀ (grouped by N)", fontsize=8, labelpad=3)
    ax.set_ylabel("Entropy threshold H₀", fontsize=8, labelpad=5)
    ax.tick_params(length=0, pad=4)
    ax.set_xticks(np.arange(-.5, 12, 1), minor=True)
    ax.set_yticks(np.arange(-.5, 5, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.25)
    ax.tick_params(which="minor", bottom=False, left=False)
    for boundary in (2.5, 5.5, 8.5):
        ax.axvline(boundary, color=INK, linewidth=.9)
    for center, n in zip((1, 4, 7, 10), ns):
        ax.text(center, 1.055, f"N = {n}", transform=ax.get_xaxis_transform(), ha="center", va="bottom", fontsize=8, fontweight="bold")
    # Square: initial B5 (N=24, H=4, U=.7); star: locked B5 (N=8, H=6, U=.9).
    ax.scatter(7, 2, s=88, marker="s", facecolors="white", edgecolors=PURPLE, linewidths=1.5, zorder=4)
    ax.scatter(2, 4, s=105, marker="*", facecolors=GOLD, edgecolors=INK, linewidths=.8, zorder=5)
    ax.text(.5, 1.245, "Validation macro ΔJ (new B5 − B2)", transform=ax.transAxes, ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.text(.5, 1.145, "60 pre-specified candidates", transform=ax.transAxes, ha="center", va="bottom", fontsize=8)

    # One coherent key strip: color scale and operating-point symbols share the same row.
    key_ax.set_axis_off()
    cax = key_ax.inset_axes([.02, .43, .42, .20])
    cbar = plt.colorbar(image, cax=cax, orientation="horizontal", ticks=[float(matrix.min()), float(matrix.max())])
    cbar.ax.tick_params(labelsize=8, length=2, pad=2)
    cbar.outline.set_linewidth(.5)
    cbar.set_label("Validation ΔJ", fontsize=8, labelpad=1)
    # Compact vertical marker legend at the right of the colorbar.
    key_ax.scatter(.60, .70, marker="s", s=55, facecolors="white", edgecolors=PURPLE, linewidths=1.3, transform=key_ax.transAxes)
    key_ax.text(.64, .70, "Initial B5", fontsize=8, va="center", transform=key_ax.transAxes)
    key_ax.scatter(.60, .28, marker="*", s=68, facecolors=GOLD, edgecolors=INK, linewidths=.7, transform=key_ax.transAxes)
    key_ax.text(.64, .28, "Locked B5", fontsize=8, va="center", transform=key_ax.transAxes)


def draw_panel_b(ax: plt.Axes, key_ax: plt.Axes, test: dict[str, Any]) -> None:
    macro = test["primary"]["macro"]["variants"]
    groups = [("Attack alert", "attack_alert_rate"), ("Benign trigger", "benign_trigger_rate"), ("FNR", "FNR")]
    variants = [("new_B5", "Locked B5", BLUE), ("B2", "B2", GREY), ("old_B5", "Initial B5", ORANGE)]
    x = np.arange(len(groups))
    width = .16
    for index, (key, _, color) in enumerate(variants):
        means = [float(macro[key][metric]["mean"]) for _, metric in groups]
        errors = np.array([[mean - float(macro[key][metric]["ci95"][0]) for mean, (_, metric) in zip(means, groups)],
                           [float(macro[key][metric]["ci95"][1]) - mean for mean, (_, metric) in zip(means, groups)]])
        ax.bar(x + (index - 1) * width, means, width, color=color, yerr=errors, capsize=2.5, error_kw={"elinewidth": .8, "capthick": .8, "ecolor": INK}, zorder=3)
    ax.set_xticks(x, [name for name, _ in groups], fontsize=8)
    ax.set_ylim(0, 1)
    ax.set_yticks(np.arange(0, 1.01, .2))
    ax.tick_params(axis="y", labelsize=8)
    ax.yaxis.grid(True, color="#DCE1E8", linewidth=.7, zorder=0)
    ax.set_axisbelow(True)
    ax.text(.5, 1.285, "Held-out primary performance", transform=ax.transAxes, ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.text(.5, 1.12, "Macro across eight primary cells\n95% paired-trace bootstrap CI", transform=ax.transAxes, ha="center", va="bottom", fontsize=8, linespacing=1.25)
    key_ax.set_axis_off()
    handles = [Patch(facecolor=color, edgecolor="none", label=name) for _, name, color in variants]
    key_ax.legend(handles=handles, loc="center", ncol=3, frameon=False, fontsize=8, handlelength=1.2, columnspacing=1.6, handletextpad=.4)


def render(protocol: dict[str, Any], grid: dict[str, Any], lock: dict[str, Any], test: dict[str, Any], output: Path) -> None:
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.linewidth": .75})
    figure = plt.figure(figsize=(7.0, 3.6), dpi=DPI)
    spec = figure.add_gridspec(2, 2, height_ratios=[1, .18], width_ratios=[1.10, 1.0], left=.085, right=.985, bottom=.105, top=.755, wspace=.18, hspace=.48)
    ax_a, ax_b = figure.add_subplot(spec[0, 0]), figure.add_subplot(spec[0, 1])
    key_a, key_b = figure.add_subplot(spec[1, 0]), figure.add_subplot(spec[1, 1])
    draw_panel_a(ax_a, key_a, grid, lock)
    draw_panel_b(ax_b, key_b, test)
    figure.text(.015, .91, "A", fontsize=10, fontweight="bold", color=INK)
    figure.text(.518, .91, "B", fontsize=10, fontweight="bold", color=INK)
    figure.savefig(output, dpi=DPI, bbox_inches=None, facecolor="white")
    plt.close(figure)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=E3_ROOT / "e3_protocol.json")
    parser.add_argument("--grid", type=Path, default=E3_ROOT / "e3_validation_grid.json")
    parser.add_argument("--lock", type=Path, default=E3_ROOT / "e3_locked_threshold.json")
    parser.add_argument("--test", type=Path, default=E3_ROOT / "e3_test_results.json")
    parser.add_argument("--output", type=Path, default=ROOT / "figures" / "RQ2-threshold-calibration-compact.png")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    protocol, grid, lock, test = (load_json(path) for path in (args.protocol, args.grid, args.lock, args.test))
    verify(protocol, grid, lock, test, args.protocol, args.grid)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    render(protocol, grid, lock, test, args.output)
    print(f"Wrote publication-ready RQ2 figure from frozen artifacts: {args.output}")
    return 0


if __name__ == "__main__":
    main()
