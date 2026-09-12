# E3-Extend — Post-hoc sensitivity analysis

E3-Extend evaluates the requested high-threshold grid `H ∈ {7, 8}` and `U ∈ {0.95, 0.99}` on **E3 validation only**. It is an explicitly post-hoc, descriptive addendum to E3 — not a new registered selection experiment.

## Non-negotiable boundaries

- Do not edit anything in `../E3/`.
- The only decision-level input permitted to the script is `../E3/datasets/splits_60_20_20/validation.csv.gz`.
- Do not open, hash, parse, aggregate, or otherwise access `held_out_test.csv.gz` for this extension.
- Do not rank candidates, lock a threshold, select a replacement candidate, or run a new held-out evaluation.
- Report attack-alert and FNR alongside $\Delta J$; a larger $\Delta J$ alone is not evidence that a detector is safer or better.
- ASR remains unmeasured and unsupported by the E2 decision-level dataset.

The governing record is [`e3_extend_protocol.json`](e3_extend_protocol.json). It preserves hashes and the identity of the frozen parent E3 artifacts, but does not read or modify them.

## Run order

From the repository root:

```bash
python3 research/Report/experiments/E3-Extend/scripts/e3_extend_sensitivity.py
python3 research/Report/experiments/E3-Extend/scripts/e3_extend_validate.py
python3 -m pip install -r research/Report/experiments/E3-Extend/requirements-plot.txt
python3 research/Report/experiments/E3-Extend/scripts/e3_extend_plot_rq2.py
```

Expected outputs are `e3_extend_sensitivity_grid.csv`, `e3_extend_sensitivity_grid.json`, and `e3_extend_validation.json`. A PASS validation means the descriptive grid has been reproduced correctly; it does **not** authorize any threshold change or a second held-out run.

`figures/RQ2-threshold-calibration-compact.png` is a two-panel replacement for the former four-heatmap RQ2 layout. It is rendered with Matplotlib only from frozen E3 JSON artifacts at 7.0 × 3.6 inches and 300 dpi; general figure text is 8 pt at that native size. [`RQ2_posthoc_sensitivity_table.tex`](RQ2_posthoc_sensitivity_table.tex) is the separate LaTex table for the post-hoc result.
