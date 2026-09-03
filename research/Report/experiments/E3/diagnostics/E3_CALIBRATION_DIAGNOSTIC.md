# E3 Calibration Diagnostic

> Read-only diagnostic over the frozen E3 artifacts. No threshold was selected,
> changed, or re-evaluated for reporting as a new confirmatory result.

## 1. Entropy implementation

Both the controlled detector and E5 runtime detector use raw Shannon entropy in
bits:

```python
return -sum((count / n) * math.log2(count / n) for count in counts.values())
```

They do not divide by `log2(n)`. Therefore,

$$
H \leq \log_2 n, \qquad H \geq 6 \Longrightarrow n \geq 64.
$$

For the locked point `(N,H,U)=(8,6.0,0.90)`, the gate `n>=8` is
mathematically redundant. The implementation matches the raw-entropy formula in
the paper; the issue is the parameterization and its interpretation, not a
formula/code mismatch.

## 2. Registered grid and decision equivalence

- Registered grid: `N={8,16,24,48}`, `H={2,3,4,5,6}`,
  `U={0.5,0.7,0.9}` = **60 candidates**.
- Exact prediction vectors on the validation primary rows: **14 distinct classes**.
- Exact prediction vectors on all validation rows: **24 distinct classes**.
- The selected point belongs to a four-member primary equivalence class:
  `[(8, 6.0, 0.9), (16, 6.0, 0.9), (24, 6.0, 0.9), (48, 6.0, 0.9)]`.

The tie-break selected `N=8`, but the validation predictions do not identify it
separately from `N=16`, `N=24`, or `N=48` at `H=6.0,U=0.90`.

See [`e3_candidate_equivalence.csv`](e3_candidate_equivalence.csv) for all 60
candidates and their exact equivalence classes.

## 3. Actual sample-count distributions in primary cells

Target volume is an expected workload level, not a fixed sample count in every
two-second window. The tables below report `min / median / mean / p95 / max`.
The column `Pr(n>=64)` shows how often raw entropy can possibly reach 6 bits.

### Validation partition (used for threshold selection)

| Profile | Level | Role | Condition | Traces | Decisions | n min / median / mean / p95 / max | Pr(n>=64) | Locked trigger |
| --- | ---: | --- | --- | ---: | ---: | --- | ---: | ---: |
| bursty | 120 | attack | `attack_sweep_bursty` | 6 | 900 | 54 / 122.0 / 120.99 / 174.0 / 192 | 0.9911 | 0.9878 |
| bursty | 120 | benign | `benign_bursty` | 6 | 900 | 54 / 122.0 / 120.99 / 174.0 / 192 | 0.9911 | 0.9822 |
| bursty | 200 | attack | `attack_sweep_bursty` | 6 | 900 | 86 / 198.5 / 198.50 / 287.0 / 306 | 1.0000 | 1.0000 |
| bursty | 200 | benign | `benign_bursty` | 6 | 900 | 86 / 198.5 / 198.50 / 287.0 / 306 | 1.0000 | 0.9989 |
| bursty | 24 | attack | `attack_sweep_bursty` | 6 | 900 | 2 / 23.0 / 23.87 / 38.0 / 52 | 0.0000 | 0.0000 |
| bursty | 24 | benign | `benign_bursty` | 6 | 900 | 2 / 23.0 / 23.87 / 38.0 / 52 | 0.0000 | 0.0000 |
| bursty | 60 | attack | `attack_sweep_bursty` | 6 | 900 | 24 / 59.0 / 59.88 / 88.0 / 109 | 0.4444 | 0.4367 |
| bursty | 60 | benign | `benign_bursty` | 6 | 900 | 24 / 59.0 / 59.88 / 88.0 / 109 | 0.4444 | 0.4156 |
| continuous | 120 | attack | `attack_sweep_continuous` | 6 | 900 | 92 / 119.0 / 118.97 / 135.0 / 147 | 1.0000 | 1.0000 |
| continuous | 120 | benign | `benign_continuous` | 6 | 900 | 92 / 119.0 / 118.97 / 135.0 / 147 | 1.0000 | 1.0000 |
| continuous | 200 | attack | `attack_sweep_continuous` | 6 | 900 | 163 / 202.0 / 202.35 / 226.0 / 244 | 1.0000 | 1.0000 |
| continuous | 200 | benign | `benign_continuous` | 6 | 900 | 163 / 202.0 / 202.35 / 226.0 / 244 | 1.0000 | 1.0000 |
| continuous | 24 | attack | `attack_sweep_continuous` | 6 | 900 | 11 / 24.0 / 23.90 / 32.0 / 40 | 0.0000 | 0.0000 |
| continuous | 24 | benign | `benign_continuous` | 6 | 900 | 11 / 24.0 / 23.90 / 32.0 / 40 | 0.0000 | 0.0000 |
| continuous | 60 | attack | `attack_sweep_continuous` | 6 | 900 | 41 / 60.0 / 60.09 / 73.0 / 84 | 0.3189 | 0.3044 |
| continuous | 60 | benign | `benign_continuous` | 6 | 900 | 41 / 60.0 / 60.09 / 73.0 / 84 | 0.3189 | 0.2544 |

### Held-out partition (integrity audit only; not for selecting a replacement)

| Profile | Level | Role | Condition | Traces | Decisions | n min / median / mean / p95 / max | Pr(n>=64) | Locked trigger |
| --- | ---: | --- | --- | ---: | ---: | --- | ---: | ---: |
| bursty | 120 | attack | `attack_sweep_bursty` | 6 | 900 | 56 / 123.0 / 121.96 / 176.0 / 196 | 0.9822 | 0.9811 |
| bursty | 120 | benign | `benign_bursty` | 6 | 900 | 56 / 123.0 / 121.96 / 176.0 / 196 | 0.9822 | 0.9744 |
| bursty | 200 | attack | `attack_sweep_bursty` | 6 | 900 | 96 / 198.0 / 199.75 / 285.0 / 318 | 1.0000 | 1.0000 |
| bursty | 200 | benign | `benign_bursty` | 6 | 900 | 96 / 198.0 / 199.75 / 285.0 / 318 | 1.0000 | 0.9944 |
| bursty | 24 | attack | `attack_sweep_bursty` | 6 | 900 | 7 / 23.0 / 23.50 / 38.0 / 51 | 0.0000 | 0.0000 |
| bursty | 24 | benign | `benign_bursty` | 6 | 900 | 7 / 23.0 / 23.50 / 38.0 / 51 | 0.0000 | 0.0000 |
| bursty | 60 | attack | `attack_sweep_bursty` | 6 | 900 | 21 / 59.0 / 59.77 / 88.0 / 104 | 0.4333 | 0.4322 |
| bursty | 60 | benign | `benign_bursty` | 6 | 900 | 21 / 59.0 / 59.77 / 88.0 / 104 | 0.4333 | 0.4067 |
| continuous | 120 | attack | `attack_sweep_continuous` | 6 | 900 | 81 / 119.0 / 119.22 / 136.0 / 148 | 1.0000 | 1.0000 |
| continuous | 120 | benign | `benign_continuous` | 6 | 900 | 81 / 119.0 / 119.22 / 136.0 / 148 | 1.0000 | 1.0000 |
| continuous | 200 | attack | `attack_sweep_continuous` | 6 | 900 | 165 / 201.0 / 201.26 / 226.0 / 244 | 1.0000 | 1.0000 |
| continuous | 200 | benign | `benign_continuous` | 6 | 900 | 165 / 201.0 / 201.26 / 226.0 / 244 | 1.0000 | 0.9989 |
| continuous | 24 | attack | `attack_sweep_continuous` | 6 | 900 | 9 / 23.0 / 23.82 / 33.0 / 42 | 0.0000 | 0.0000 |
| continuous | 24 | benign | `benign_continuous` | 6 | 900 | 9 / 23.0 / 23.82 / 33.0 / 42 | 0.0000 | 0.0000 |
| continuous | 60 | attack | `attack_sweep_continuous` | 6 | 900 | 38 / 60.0 / 60.25 / 73.0 / 81 | 0.3300 | 0.3167 |
| continuous | 60 | benign | `benign_continuous` | 6 | 900 | 38 / 60.0 / 60.25 / 73.0 / 81 | 0.3300 | 0.2689 |

At target volume 60, validation windows do exceed 64 samples. Thus, activation
near level 60 is possible even though a window with exactly `n=60` cannot reach
six bits of entropy.

## 4. Data accounting

- Validation file: **27,600 rows**; primary matched analysis: **14,400 rows**.
- Held-out file: **27,600 rows**; primary matched analysis: **14,400 rows**.
- The primary macro uses 8 cells x 6 matched pairs x 2 runs x 150 decisions = **14,400 primary decisions**.
- The remainder of the 27,600-row held-out file comprises random-IPID control,
  fixed/duplicate failure probes, and calibration-derived benign-only rows.

The phrase “27,600 held-out decisions across eight primary cells” is therefore
incorrect. `27,600` is the full held-out file size, not the primary-analysis
denominator.

## 5. Does E3 need to be rerun?

The existing held-out numbers remain valid for the exact locked rule that was
evaluated. They do not establish that `N=8` is a meaningful calibrated volume
threshold, because that gate is redundant and four values of `N` are prediction-
equivalent at the selected `H,U` pair.

- **No rerun is strictly required** if the paper is reframed as a diagnostic or
  negative result, explicitly reports the redundancy/equivalence classes, and
  does not call the point a refined three-parameter defense.
- **A new calibration and fresh confirmatory set are required** if the paper
  claims to identify a meaningful improved threshold or operational defense.
- Replacing raw entropy with normalized entropy changes the detector and cannot
  be handled as a wording correction.
- A future search should report a Pareto frontier over attack-alert/FNR and
  benign-trigger rather than selecting solely by `J` without a coverage gate.
