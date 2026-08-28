#!/bin/bash
set -euo pipefail
: > /app/frag2_events.jsonl
: > /app/r2_entropy_decisions.jsonl
: > /app/unbound_queries.jsonl
echo "${DEFENSE_MODE:-off}" > /app/defense_mode
echo "off" > /app/poison_mode
unbound -V > /app/unbound_version.txt 2>&1 || true
python3 /app/detector.py &
python3 /app/poisoner.py &
exec unbound -d -c /etc/unbound/unbound.conf
