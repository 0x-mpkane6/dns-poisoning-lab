#!/bin/bash

# pipefail without -e: dig failures (defense-ON TC=1, no TCP) must not abort.
set -uo pipefail

RESOLVER="${RESOLVER_IP:-10.30.0.53}"
TARGET_ZONE="${1:-example.net}"
ROUNDS="${2:-${ROUNDS:-50}}"
PROFILE="${3:-attack}"

RESULT_FILE="/app/result.txt"
LATENCY_FILE="/app/latency_ms.txt"

rm -f "$RESULT_FILE" "$LATENCY_FILE"

echo "[+] Triggering fragmentation attempts: zone=${TARGET_ZONE}, rounds=${ROUNDS}, resolver=${RESOLVER}, profile=${PROFILE}"

for i in $(seq 1 "$ROUNDS"); do
    if [ "$PROFILE" = "baseline" ]; then
        PREFIX="base"
    else
        PREFIX="frag"
    fi
    QNAME="${PREFIX}${i}.$(date +%s%N).${TARGET_ZONE}"

    START_NS="$(date +%s%N)"
    dig @"$RESOLVER" "$QNAME" +tries=1 +time=1 +short >/dev/null 2>&1 || true
    END_NS="$(date +%s%N)"
    LATENCY_MS="$(awk -v s="$START_NS" -v e="$END_NS" 'BEGIN { printf "%.3f", (e - s) / 1000000.0 }')"

    sleep 0.05

    BANK_IP="$(dig @"$RESOLVER" bank.com +tries=1 +time=1 +short 2>/dev/null | head -n1 | tr -d '\r' || true)"
    if [ -z "$BANK_IP" ]; then
        BANK_IP="NOANSWER"
    fi

    echo "$BANK_IP" >> "$RESULT_FILE"
    echo "$LATENCY_MS" >> "$LATENCY_FILE"
    echo "[$i/$ROUNDS] bank.com -> $BANK_IP | latency=${LATENCY_MS}ms"
done

echo "[+] Done. Results saved to $RESULT_FILE"
echo "[+] Latency saved to $LATENCY_FILE"
