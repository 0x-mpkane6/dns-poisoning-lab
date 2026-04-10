# labs/base conventions

`labs/base` contains shared scripts and interface conventions used by all lab variants.

## Shared scripts

- `scripts/run_case_common.sh`: helper functions used by each lab runner.
- `scripts/measure_asr.sh`: computes poisoning ASR from `/app/result.txt`.
- `scripts/measure_latency.sh`: computes latency avg/p95 from `/app/latency_ms.txt` (RTT of the target query only).
- `scripts/benchmark_case.sh`: runs a case multiple times and prints averaged metrics.

## Standard lab contract

Each lab folder should provide:

- `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- `./scripts/reset.sh`
- client output files:
  - `/app/result.txt` for ASR
  - `/app/latency_ms.txt` for latency samples

`run_case.sh` performs Docker preflight and uses `docker compose up -d` (no forced rebuild).
Use `./scripts/reset.sh` when you need a clean rebuild.

## Common environment knobs

- `DEFENSE_MODE` (`on|off`)
- `TXID_SPACE`
- `IPID_SPACE`
- `ATTACK_RATE`
- `ROUNDS`
- `POISON_IP`
