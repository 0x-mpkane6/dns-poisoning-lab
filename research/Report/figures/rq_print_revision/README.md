# Print revision and existing-log additions

Upload the four `RQ*.pdf` figures (or the matching PNGs) to the cloud project's
`figure/` folder. They use the current cloud filenames. Replace figure blocks
using `figure_blocks.tex`; use `text_replacements.tex` for changed references.
No cloud manuscript has been modified. Original figures and raw artifacts remain available.

All figures have a fixed **122 mm** width, measured from the available manuscript,
with **8.5 pt or larger** text. Include at `width=\linewidth` in the same 122 mm
text block; do not reduce below 114.83 mm (which would lower 8.5 pt below 8 pt).
PNG export is 600 dpi; PDF/SVG are vector. LaTeX tables use 9 pt explicitly and no
`resizebox`. The PNG/PDF table companions are previews; prefer real `.tex` tables.

| Former item | Replacement |
|---|---|
| Figure 2 | `RQ1_benign_boundary`: initial and locked B5, same recorded benign traces |
| Figure 3 | `RQ1_volume_matched_discrimination`: PR-AUC only; remove the A/B wording |
| Figure 4 | `RQ2_threshold_calibration`: one heatmap with all 60 candidates, plus held-out panel B |
| Figure 5 | `RQ3_failure_modes`: shared three-color traffic key and only two metric entries for B |
| Figure 6 | `RQ4_runtime_outcomes.tex`; mechanism rates move to prose (`RQ4_runtime_mechanism.tex` is an optional extra) |
| New benign cost | `runtime_benign_cost_original.tex` and `runtime_benign_cost_factorial.tex` |
| Completed 2x2 follow-up | `runtime_factorial_results.tex` (16 cells, 320 runs, 16,000 trials) |

The zero-delta-J sentence and the entropy/volume explanation already exist in the
latest available RQ text: replace/retain them, do not duplicate them. Table 1 is
currently the **B0--B5 definition table**, not the earlier experimental-settings
table. Its removal is optional; the supplied paragraph preserves all six variants.
Final page count depends on the cloud manuscript and has not been certified.

## Data and inference

Locked benign boundary is a **post-hoc re-score**, not fresh held-out evidence.
480 original runs / 144,000 decisions are checked against recorded hashes and
initial-B5 predictions; 5,000 bootstrap resamples use runs, not decisions.
Runtime campaign summaries are kept separate. The original campaign does not
provide validated cache-insertion evidence. The factorial campaign does.

Benign latency is the query subprocess interval reconstructed from monotonic
query start/end logs, excluding cache-before/cache-after. Reported median/p95
pool 1,000 query attempts per cell, **including timeouts**, as descriptive
quantiles. Companion CSVs also give the mean of per-run medians/p95s; these are
different statistics. Trial counts are not treated as independent sample sizes.
Native-drop has concurrent queries; the other policies have sequential queries,
so differences in latency cannot be attributed to policy alone.

The factorial factors are forged-tail injection on/off and background rate under
the same sweep pattern. Background includes non-DNS occupancy; forged tails add
traffic beyond the registered background rate. The lab notifies the fragment
sender of metadata; this does not establish a natural off-path attack.

The high-threshold validation-only post-hoc analysis already exists in
`../../experiments/E3-Extend/`; it must not replace the locked operating point.
The additional `controlled_ipid_sensitivity/` directory contains a separate
post-hoc benign replay for a 65,536-value space; see its protocol and verification.
No attack-discrimination or orphan-fragment baseline is implied by that replay.
GitHub publication requires the user's resolution of the
earlier no-commit/no-push constraint.

Reproduce from Code: `python research/Report/figures/revise_paper_figures.py`.
`source_manifest.json` pins all inputs; `verification.json` records checks.
