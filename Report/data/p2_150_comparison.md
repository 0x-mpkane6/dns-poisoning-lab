# P2 Docker Batch 150 - Weak vs Bruteforce

Generated on 2026-06-19.

Scope:

- Labs: OoB and SFrag.
- Rounds: 150 DNS queries per case.
- Runs: 1 per case.
- Cases: baseline, attack-off, attack-on.
- Docker data; charts generated with Windows Python because WSL Python lacked `matplotlib`.

## Weak Entropy

Output directory: `Report/data/docker_weak_150/`

| Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
|-----|------|------------------|-----|-------------|-------------|
| oob | baseline | 0 / 150 | 0.00% | 271.523 ms | 274.132 ms |
| oob | attack-off | 146 / 150 | 97.33% | 262.146 ms | 283.546 ms |
| oob | attack-on | 0 / 150 | 0.00% | 255.686 ms | 395.384 ms |
| sfrag | baseline | 0 / 150 | 0.00% | 271.144 ms | 274.342 ms |
| sfrag | attack-off | 135 / 150 | 90.00% | 267.480 ms | 274.463 ms |
| sfrag | attack-on | 0 / 150 | 0.00% | 267.804 ms | 273.524 ms |

## Bruteforce Entropy

Output directory: `Report/data/docker_bruteforce_150/`

| Lab | Case | Poisoned / Total | ASR | Avg latency | P95 latency |
|-----|------|------------------|-----|-------------|-------------|
| oob | baseline | 0 / 150 | 0.00% | 270.417 ms | 274.964 ms |
| oob | attack-off | 0 / 150 | 0.00% | 269.187 ms | 274.040 ms |
| oob | attack-on | 0 / 150 | 0.00% | 270.793 ms | 274.251 ms |
| sfrag | baseline | 0 / 150 | 0.00% | 271.035 ms | 273.737 ms |
| sfrag | attack-off | 0 / 150 | 0.00% | 271.575 ms | 280.749 ms |
| sfrag | attack-on | 0 / 150 | 0.00% | 271.143 ms | 276.799 ms |

## Brute-force Model Note

The model file `Report/data/docker_bruteforce_150/p2_bruteforce_model.csv`
uses source-port candidates `1024..65535`, giving:

- OoB entropy space: `64512 * 65536 = 4,227,858,432` source-port/TXID pairs.
- SFrag entropy space: `64512 * 65535 = 4,227,793,920` source-port/IPID pairs.
- With a budget of roughly one full TXID/IPID sweep per query window, expected
  ASR is about `0.00155010%`, or `0.002325` poisoned queries per 150-query run.

So the Docker brute-force result of `0 / 150` is consistent with the expected
probability under full source-port entropy.
