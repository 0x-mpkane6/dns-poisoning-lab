# BFrag Lab (Bullseye Fragment / R2)

This lab models `BFrag`, where attacker already knows the target IPID (bullseye mode) and injects one forged frag2 pattern repeatedly.

## What it covers

- Attack family: `BFrag`.
- Defense switch: `R2` via `toggle_defense.sh on|off`.
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
- Baseline profile uses non-trigger names, so benign behavior is isolated from attack-trigger flow.
- Auth server runs in `FRAG_MODE=bfrag` and emits `BULLSEYE_IPID`.
- Attacker sends forged frag2 with that exact `BULLSEYE_IPID`.
- Defense `on` should keep poisoning near zero by truncating suspicious fragmented flow.
