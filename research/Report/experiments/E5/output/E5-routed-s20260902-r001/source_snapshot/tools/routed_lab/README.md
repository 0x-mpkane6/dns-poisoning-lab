# E5-v2 routed laboratory

This directory contains the isolated two-network Docker lab for the E5-v2
campaign.  The resolver and attacker are on different sides of the two-
interface IPS.  The attacker process is the only forged-tail sender; there is
no resolver-local poisoner in this lab.

The lab is normally driven by the parent runner
`research/Report/experiments/E5/run_e5_v2.py`, which supplies read-only replay
schedules and per-cell artifact mounts.  Starting the compose file manually
without those mounts is useful only for image/configuration debugging, not for
data collection.
