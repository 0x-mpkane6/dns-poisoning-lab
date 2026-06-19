# P2 Docker Batch 150 - Weak vs Bruteforce

Generated on 2026-06-19.

Scope:

- Labs: OoB, SFrag, and BFrag.
- Rounds: 150 DNS queries per case.
- Runs: 1 per case.
- Cases: baseline, attack-off, attack-on.
- Docker data; charts generated with Windows Python because WSL Python lacked `matplotlib`.

## Weak Entropy

Output directory: `Report/data/docker_weak_150/`

| Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
|-----|------|------------------|-----|-------------|-------------|
| oob | baseline | 0 / 150 | 0.00% | 274.846 ms | 274.278 ms |
| oob | attack-off | 148 / 150 | 98.67% | 260.647 ms | 376.623 ms |
| oob | attack-on | 0 / 150 | 0.00% | 254.951 ms | 382.839 ms |
| sfrag | baseline | 0 / 150 | 0.00% | 271.194 ms | 271.535 ms |
| sfrag | attack-off | 147 / 150 | 98.00% | 271.229 ms | 272.730 ms |
| sfrag | attack-on | 0 / 150 | 0.00% | 275.347 ms | 274.763 ms |
| bfrag | baseline | 0 / 150 | 0.00% | 281.764 ms | 277.001 ms |
| bfrag | attack-off | 150 / 150 | 100.00% | 280.248 ms | 273.955 ms |
| bfrag | attack-on | 0 / 150 | 0.00% | 283.898 ms | 275.370 ms |

## Bruteforce Entropy

Output directory: `Report/data/docker_bruteforce_150/`

| Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
|-----|------|------------------|-----|-------------|-------------|
| oob | baseline | 0 / 150 | 0.00% | 277.595 ms | 273.263 ms |
| oob | attack-off | 0 / 150 | 0.00% | 277.588 ms | 274.090 ms |
| oob | attack-on | 0 / 150 | 0.00% | 277.655 ms | 274.598 ms |
| sfrag | baseline | 0 / 150 | 0.00% | 277.537 ms | 273.299 ms |
| sfrag | attack-off | 0 / 150 | 0.00% | 280.277 ms | 273.036 ms |
| sfrag | attack-on | 0 / 150 | 0.00% | 277.769 ms | 275.585 ms |
| bfrag | baseline | 0 / 150 | 0.00% | 277.931 ms | 274.367 ms |
| bfrag | attack-off | 0 / 150 | 0.00% | 284.564 ms | 273.394 ms |
| bfrag | attack-on | 0 / 150 | 0.00% | 283.307 ms | 275.458 ms |

## Brute-force Model Note

The model file `Report/data/docker_bruteforce_150/p2_bruteforce_model.csv`
uses source-port candidates `1024..65535`, giving:

- OoB entropy space: `64512 * 65536 = 4,227,858,432` source-port/TXID pairs.
- SFrag entropy space: `64512 * 65535 = 4,227,793,920` source-port/IPID pairs.
- BFrag uses a bullseye IPID in this lab, so the brute-force burden is mainly
  the `64512` source-port candidates rather than a source-port/IPID product.
- With a budget of roughly one full TXID/IPID sweep per query window, expected
  ASR is about `0.00155010%`, or `0.002325` poisoned queries per 150-query run.

So the Docker brute-force result of `0 / 150` is consistent with the expected
probability under full source-port entropy.
