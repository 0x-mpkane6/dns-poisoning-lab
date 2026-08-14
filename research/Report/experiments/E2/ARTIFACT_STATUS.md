# E2 artifact status

Updated: 2026-08-14

## Canonical result

The authoritative E2 result for its stated scope is:

`runs/E2_confirmatory_20260814_complete_b0_ablation/`

Its raw-to-result validator passed **18/18** checks. The root report to use is
[`E2_report.md`](E2_report.md).

The canonical run contains, without overwriting old data:

- `e2_protocol.json`: protocol registered before data collection.
- `raw_runs/` and `e2_decisions.csv.gz`: event-level raw evidence.
- `e2_runs.csv`, `e2_summary.csv`, `e2_results.json`: run and aggregate results.
- `source_snapshot/` and `artifact_manifest.json`: exact source/hash provenance.
- `validation.json`: independent replay validation (PASS).

## What this result supports

It supports a **query-timed, paired controlled-emulation** conclusion about detector decisions: B5 does not improve over B1–B4 in the registered sweep conditions, and it is worse than B2 in the fixed/duplicate-IPID failure probes. It includes B0–B5 baseline/ablation, paired 95% CI, PR-AUC, and held-out FPR after validation-locked TPR targeting.

## What it does not support

Do not cite E2 as evidence of real IP fragmentation, poisoning prevention, ASR, BFrag coverage, latency, CPU, deployment performance, or a generally safer replacement for POPS Rℓ2. Those need E5 / a real resolver experiment.

## Historical material

`runs/E2_confirmatory_20260813_165220_seed20260813/` is the prior confirmatory artifact. It remains reproducible, but the newer canonical artifact supersedes it because it completes the requested B1–B5 and matched-TPR analysis.

`runs/provisional/E2_20260806_220159/` is retained only for traceability. It is a methodologically provisional exploratory snapshot and must not be used as confirmatory evidence.
