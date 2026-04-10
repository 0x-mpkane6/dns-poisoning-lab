# DNS Poisoning Labs (Nguoi 2 scope)

This directory adds isolated labs for the "Nguoi 2" scope while leaving the original root lab untouched.

## Lab folders

- `oob/`: SOoB (Out-of-Bailiwick) + R3 toggle.
- `sfrag/`: SFrag (IPID guessing) + R2 toggle.
- `bfrag/`: BFrag (bullseye IPID) + R2 toggle.
- `base/`: shared scripts and conventions.

## Unified runner interface

Each lab supports:

```bash
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Output metrics:

- ASR from `/app/result.txt`
- Latency avg/p95 from `/app/latency_ms.txt` (RTT of target query only)

## Recommended workflow per lab

```bash
cd <lab-folder>
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Repeat and average:

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Notes

- The original root lab files are not modified by this structure.
- Each lab has its own subnet to avoid docker network overlap:
  - `oob`: `10.20.0.0/24`
  - `sfrag`: `10.30.0.0/24`
  - `bfrag`: `10.40.0.0/24`
- If Docker daemon is down, `run_case.sh` exits early with a preflight error message.
