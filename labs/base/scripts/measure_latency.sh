#!/bin/bash

set -euo pipefail

CLIENT_SERVICE="${1:-client}"
LATENCY_PATH="${2:-/app/latency_ms.txt}"
COMPOSE_CMD=(docker compose)

if ! docker compose version >/dev/null 2>&1; then
    if command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
    else
        echo "[!] docker compose plugin or docker-compose command is unavailable."
        exit 1
    fi
fi

TMP_FILE="$(mktemp)"
SORTED_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE" "$SORTED_FILE"' EXIT

CLIENT_CID="$("${COMPOSE_CMD[@]}" ps -q "$CLIENT_SERVICE" 2>/dev/null || true)"

if [ -z "${CLIENT_CID}" ]; then
    echo "Latency samples: 0"
    echo "Latency avg = 0.000 ms"
    echo "Latency p95 = 0.000 ms"
    exit 0
fi

if ! docker cp "${CLIENT_CID}:${LATENCY_PATH}" "$TMP_FILE" >/dev/null 2>&1; then
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
