# English RQ figure set

This directory contains the five English, publication-ready summary figures
for the research questions. The figures were regenerated from the canonical
E1--E5 artifacts by
[`generate_rq_figures_en.py`](../generate_rq_figures_en.py). Existing frozen
figures inside the experiment run directories were not overwritten.

| Figure | Research question | Caption |
| --- | --- | --- |
| `RQ1_benign_boundary` | RQ1 — Benign operating boundary | False-positive rate (benign trigger rate) of the combined B5 rule as target fragment volume increases under random, sequential and small-pool IPID behavior. Shaded regions are 95% run-level confidence intervals; (n=20) independent runs per cell. |
| `RQ2_volume_matched_discrimination` | RQ1 — Controlled discrimination block (legacy filename) | Panel A shows the paired (Delta J) of the initial B5 configuration relative to the volume-only baseline for continuous and bursty sweeps. Panel B shows score-level PR-AUC for entropy and the unique-IPID ratio. Shaded regions are 95% paired-trace confidence intervals; (n=20) paired traces per cell. |
| `RQ3_threshold_calibration` | RQ2 — Threshold calibration (legacy filename) | Validation (Delta J) over the registered 60-point threshold grid and held-out macro performance of the locked B5 operating point, B2, and the initial B5 configuration. Heatmap values and bars use the registered validation/held-out estimates; Panel E reports a macro mean over eight primary cells with stratified paired-trace bootstrap confidence intervals. |
| `RQ3_failure_modes` | RQ3 — Stability and failure modes | Panel A shows the paired (Delta J) of the locked B5 rule relative to B2 for the registered fixed-IPID and duplicate-sweep failure probes, with the random-IPID negative control. Panel B shows attack-alert and benign-trigger rates for the same conditions. Error bars are 95% paired-trace confidence intervals; (n=6) paired traces per cell. Failure probes and the negative control were not used for threshold selection. |
| `RQ4_runtime_root_cause` | RQ4 — Resolver-level runtime validation | Panel A reports any-poison run rates for the routed-IPS policies. Panel B decomposes the locked B5 mechanism chain into trigger, forged-tail drop, TC injection and TCP retry for the fixed-IPID and sweep-flood workloads. Error bars are exact Clopper--Pearson intervals in Panel A and run-level bootstrap intervals in Panel B; (n=20) runs per cell. |

PNG files are exported at 600 dpi. PDF and SVG companions are provided for
submission workflows that prefer vector graphics.
