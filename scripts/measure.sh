#!/bin/bash

set -e

TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT

docker cp client:/app/result.txt "$TMP_FILE"

TOTAL=$(wc -l < "$TMP_FILE")
POISON=$(grep -c "^6.6.6.6$" "$TMP_FILE" || true)

echo "Total: $TOTAL"
echo "Poisoned: $POISON"

if [ "$TOTAL" -eq 0 ]; then
    RATE="0.00"
else
    RATE=$(awk -v p="$POISON" -v t="$TOTAL" 'BEGIN { printf "%.2f", (p * 100.0) / t }')
fi

echo "Success rate = ${RATE}%"
