# E5-v2 Routed IPS Runbook

E5-v2 is a separate resolver-level campaign.  It does not overwrite the
canonical E5 output and its results must not be pooled with E1--E5 legacy
artifacts.

The registered protocol is
[`e5_v2_protocol.json`](D:/ATM/Project/Code/research/Report/experiments/E5/e5_v2_protocol.json).
The implementation is under
[`tools/routed_lab`](D:/ATM/Project/Code/research/Report/experiments/E5/tools/routed_lab).

## Execution order

From the repository root:

```powershell
python research/Report/experiments/E5/run_e5_v2.py --stage preflight
python research/Report/experiments/E5/run_e5_v2.py --stage pilot
python research/Report/experiments/E5/run_e5_v2.py --stage sanity
python research/Report/experiments/E5/run_e5_v2.py --stage confirmatory
```

The confirmatory stage is refused unless the pilot has passed its engineering
checks, the NFQUEUE/routing preflight is `PASS`, and all 16 sanity cells have
passed integrity validation.  All cells are run sequentially and the stack is
recreated after every cell.

If code, configuration, protocol, or the Unbound source changes after
registration, the runner refuses to continue.  Use a new run identifier only
after registering a new protocol snapshot and rerunning the complete pilot.

## Data products

Each run is written below `output/<run-id>/raw/<stage>/`.  The raw directory
contains the client, auth, attacker, IPS, resolver/cache, firewall, and
PCAPNG evidence.  `metrics.json` is derived from those raw files and
`validation.json` records integrity checks.  Confirmatory aggregation is
written only after all 320 recreated-stack runs pass validation.

Docker Desktop/Linux containers must be running before `--stage preflight`.
The preflight deliberately aborts when the kernel cannot bind NFQUEUE; it does
not silently fall back to resolver-local filtering or a non-NFQUEUE path.
