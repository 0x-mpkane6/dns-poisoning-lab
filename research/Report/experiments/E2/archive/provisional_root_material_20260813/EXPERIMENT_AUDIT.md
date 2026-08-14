# E2 experiment-integrity audit

Audit date: 2026-08-10  
Review independence: fresh same-family reviewer  
Acceptance status: provisional audit  
Verdict: **PROVISIONAL — no result promoted**

## Checks completed

- 72,000 window rows = 6 conditions × 4 levels × 20 runs × 150 windows.
- 480 unique seeds/runs and no duplicate primary keys.
- 120 summary rows, 24 JSON block-rate cells, and 20 discrimination cells.
- All stored rule flags and aggregate block rates recomputed from the CSV.
- Summary rounding differed by at most `4.75e-5`.
- PR-AUC recomputation from rounded rows differed by at most `0.000301`.
- For the benign/sweep/random/bursty conditions, B5 equaled volume-only in `48,000/48,000` rows.

## Blocking findings

1. **Decision-epoch mismatch:** the harness scores at FRAG2 arrivals rather than the resolver's later query/FRAG1 decision point.
2. **In-sample calibration:** the exact reporting seeds tune attack arrival rates, and only cell means are matched.
3. **Invalid inferential treatment:** adjacent-window lag-1 correlation is approximately `0.959`; pooled PR-AUC has no cluster CI, and four t-intervals leave the probability range.
4. **Unsupported security claims:** no retained IPID sequence, poisoning outcome, or ASR can establish full-space coverage or unchanged poisoning probability.
5. **Missing evidence:** the report's `benign_frac={0,0.25,0.5}` sensitivity results are not retained.
6. **Incomplete provenance:** no full commit, dirty state, exact command, source snapshot, dependency versions, or full-precision calibration manifest.

The report also understates the maximum volume PR-AUC as `0.622` instead of `0.638644`, and says `12,000/12,000` collectively where the four named conditions contain 48,000 rows.

## Disposition

The coherent six-item output set was moved together to `runs/provisional/E2_20260806_220159/`. No E2 result was promoted. The working scripts remain at the root for correction and rerunning.

The machine-readable verdict is in `EXPERIMENT_AUDIT.json`.
