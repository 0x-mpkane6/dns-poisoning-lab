#!/bin/bash

set -euo pipefail

CLIENT_SERVICE="${1:-client}"
POISON_IP="${2:-6.6.6.6}"
RESULT_PATH="${3:-/app/result.txt}"

# Avoid `docker cp` here: on Docker Desktop for Windows it mangles
# /tmp/... destinations into D:\tmp\... and silently fails.
# Stream the file via `docker compose exec ... cat` instead.
TMP_FILE="$(mktemp -p "${TMPDIR:-/tmp}" measure_asr.XXXXXX 2>/dev/null || mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

if ! docker compose exec -T "$CLIENT_SERVICE" cat "$RESULT_PATH" > "$TMP_FILE" 2>/dev/null; then
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
