# OoB Lab (SOoB / R3)

This folder is an isolated copy of the original OoB lab, with the same attack logic and a standardized runner/output format used by all labs under `labs/`.

## What it covers

- Attack family: `SOoB` (Out-of-Bailiwick poisoning).
- Defense switch: `R3`-style bailiwick filter via `toggle_defense.sh on|off`.
- Metrics:
  - ASR from `result.txt`
  - latency samples from `latency_ms.txt` (RTT of the target query only)

## Quick start

From this folder:

```bash
docker info
```

Run scenarios:

```bash
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

Optional benchmark (3 repeated runs):

```bash
bash ../base/scripts/benchmark_case.sh ./scripts/run_case.sh attack-off 50 3
```

## Standard interface

- Runner: `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- Result file in client container: `/app/result.txt`
- Latency file in client container: `/app/latency_ms.txt`

## Environment knobs

- `DEFENSE_MODE` (`on|off`) initial mode for resolver.
- `TXID_SPACE` size of TXID guess space.
- `ATTACK_RATE` attack loop sleep interval.
- `ROUNDS` default rounds for client probes.
- `POISON_IP` poisoned address tracked in ASR metrics.

## Troubleshooting

- If ASR is unexpectedly low in `attack-off`, run with more rounds and ensure attacker is alive (`docker compose logs attacker`).
- If you need a clean rebuild, run `bash ./scripts/reset.sh`.
