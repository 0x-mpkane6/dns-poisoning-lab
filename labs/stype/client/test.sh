#!/bin/bash

set -euo pipefail

RESOLVER="${RESOLVER_IP:-10.50.0.53}"
TARGET_ZONE="${1:-example.net}"
ROUNDS="${2:-${ROUNDS:-150}}"
PROFILE="${3:-attack}"
ATTACK_VARIANT="${4:-${ATTACK_VARIANT:-txid}}"
FLUSH_QNAME="${FLUSH_QNAME:-_flush.stype-control}"
RESULT_FILE="/app/result.txt"
LATENCY_FILE="/app/latency_ms.txt"

rm -f "$RESULT_FILE"
rm -f "$LATENCY_FILE"

echo "[+] Triggering S-type attempts: variant=${ATTACK_VARIANT}, zone=${TARGET_ZONE}, rounds=${ROUNDS}, resolver=${RESOLVER}, profile=${PROFILE}"

for i in $(seq 1 "$ROUNDS")
do
    # Keep each measurement independent from the previous round's cache state.
    dig @"$RESOLVER" "$FLUSH_QNAME" +tries=1 +time=1 +short > /dev/null || true

    if [ "$PROFILE" = "baseline" ]; then
        QNAME="safe${i}.$(date +%s%N).${TARGET_ZONE}"
    elif [ "$ATTACK_VARIANT" = "kaminsky" ]; then
        QNAME="victim.bank.com"
    else
        QNAME="bank.com"
    fi

    START_NS="$(date +%s%N)"
    dig @"$RESOLVER" "$QNAME" +tries=1 +time=1 +short > /dev/null
    END_NS="$(date +%s%N)"

    LATENCY_MS="$(awk -v s="$START_NS" -v e="$END_NS" 'BEGIN { printf "%.3f", (e - s) / 1000000.0 }')"
    sleep 0.05

    BANK_IP=$(dig @"$RESOLVER" bank.com +tries=1 +time=1 +short | head -n1 | tr -d '\r')
    if [ -z "$BANK_IP" ]; then
        BANK_IP="NOANSWER"
    fi

    echo "$BANK_IP" >> "$RESULT_FILE"
    echo "$LATENCY_MS" >> "$LATENCY_FILE"
    echo "[$i/$ROUNDS] trigger=${QNAME} bank.com -> $BANK_IP | latency=${LATENCY_MS}ms"
done

echo "[+] Done. Results saved to $RESULT_FILE"
echo "[+] Latency saved to $LATENCY_FILE"
