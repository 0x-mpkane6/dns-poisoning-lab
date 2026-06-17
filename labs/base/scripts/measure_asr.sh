#!/bin/bash

set -euo pipefail

CLIENT_SERVICE="${1:-client}"
POISON_IP="${2:-6.6.6.6}"
RESULT_PATH="${3:-/app/result.txt}"
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
trap 'rm -f "$TMP_FILE"' EXIT

CLIENT_CID="$("${COMPOSE_CMD[@]}" ps -q "$CLIENT_SERVICE" 2>/dev/null || true)"

if [ -z "${CLIENT_CID}" ]; then
    echo "Total: 0"
    echo "Poisoned: 0"
    echo "Success rate = 0.00%"
    exit 0
fi

if ! docker cp "${CLIENT_CID}:${RESULT_PATH}" "$TMP_FILE" >/dev/null 2>&1; then
    echo "Total: 0"
    echo "Poisoned: 0"
    echo "Success rate = 0.00%"
    exit 0
fi

TOTAL="$(wc -l < "$TMP_FILE" | tr -d ' ')"
POISONED="$(grep -F -x -c -- "${POISON_IP}" "$TMP_FILE" || true)"

echo "Total: ${TOTAL}"
echo "Poisoned: ${POISONED}"

if [ "${TOTAL}" -eq 0 ]; then
    RATE="0.00"
else
    RATE="$(awk -v p="$POISONED" -v t="$TOTAL" 'BEGIN { printf "%.2f", (p * 100.0) / t }')"
fi

echo "Success rate = ${RATE}%"
