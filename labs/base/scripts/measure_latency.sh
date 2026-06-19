#!/bin/bash

set -euo pipefail

CLIENT_SERVICE="${1:-client}"
LATENCY_PATH="${2:-/app/latency_ms.txt}"

# Stream via docker exec to avoid Docker-on-Windows /tmp path mangling.
TMP_FILE="$(mktemp -p "${TMPDIR:-/tmp}" measure_lat.XXXXXX 2>/dev/null || mktemp)"
SORTED_FILE="$(mktemp -p "${TMPDIR:-/tmp}" measure_lat_s.XXXXXX 2>/dev/null || mktemp)"
trap 'rm -f "$TMP_FILE" "$SORTED_FILE"' EXIT

if ! docker compose exec -T "$CLIENT_SERVICE" cat "$LATENCY_PATH" > "$TMP_FILE" 2>/dev/null; then
    echo "Latency samples: 0"
    echo "Latency avg = 0.000 ms"
    echo "Latency p95 = 0.000 ms"
    exit 0
fi

TOTAL="$(wc -l < "$TMP_FILE" | tr -d ' ')"

if [ "${TOTAL}" -eq 0 ]; then
    echo "Latency samples: 0"
    echo "Latency avg = 0.000 ms"
    echo "Latency p95 = 0.000 ms"
    exit 0
fi

AVG="$(awk '{ sum += $1 } END { printf "%.3f", sum / NR }' "$TMP_FILE")"

sort -n "$TMP_FILE" > "$SORTED_FILE"
P95_INDEX=$(( (95 * TOTAL + 99) / 100 ))
P95="$(awk -v idx="$P95_INDEX" 'NR == idx { printf "%.3f", $1; exit }' "$SORTED_FILE")"

echo "Latency samples: ${TOTAL}"
echo "Latency avg = ${AVG} ms"
echo "Latency p95 = ${P95} ms"
