# E5 supplement — outline scope only

Four E5 cells: benign low, near the earlier E1 boundary, volume-matched fixed-IPID
attack, and the final flood operating point. Retain the existing B0 positive
control. K=20 recreated-stack runs/cell, 50 rounds/run, one excluded sanity
run/cell. Locked E3 threshold 8/6.0/0.90; 2-second window; randomized order.

No new baseline, C5, boundary sweep, PCAP campaign, or defense redesign.
Existing Unbound images, network, attack paths, and resource settings remain.
Essential measurement corrections: one rate sender, monotonic detector window,
accurate rule-installation status, and measurement-only event summaries.
No old result is overwritten or pooled with this campaign.

From the Code directory:

```
python -X utf8 research/Report/experiments/E5/unbound_lab/supplement/campaign.py --stage all
```

Retain raw outcomes, latency p50/p95/p99 (existing 10-ms client clock), CPU/memory,
occupancy, detector decisions and run-level confidence intervals. False triggers
and poisoning are outcomes, not reasons to discard a run. The validator accounts
for event/tick logging instead of expecting one detector row per client round.
