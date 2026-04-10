# SFrag Lab (Fragment Guessing / R2)

This lab models the `SFrag` family where the attacker guesses IPID for forged second-fragment data.

## What it covers

- Attack family: `SFrag`.
- Defense switch: `R2`-style fragmentation handling via `toggle_defense.sh on|off`.
- Metrics:
  - ASR from `/app/result.txt`
  - latency from `/app/latency_ms.txt` (RTT of the target query only)

## Quick start

```bash
docker info
bash ./scripts/run_case.sh baseline 50
bash ./scripts/run_case.sh attack-off 50
bash ./scripts/run_case.sh attack-on 50
```

## Standard interface

- Runner: `./scripts/run_case.sh <baseline|attack-off|attack-on> [rounds]`
- Common variables: `DEFENSE_MODE`, `TXID_SPACE`, `IPID_SPACE`, `ATTACK_RATE`, `ROUNDS`, `POISON_IP`

## Notes

- Fragment marker (`FRAG1`) is attached only for attack-profile query names (prefix `frag*`).
- Baseline profile uses non-trigger names, so normal benign behavior is separated from attack-trigger flow.
- `attack-off`: resolver merges forged frag2 payload when IPID matches.
- `attack-on`: resolver detects frag flow and returns truncated response (`TC=1`) instead of caching forged data.
- If poisoning is too low, increase `ROUNDS` and reduce `ATTACK_RATE`.
