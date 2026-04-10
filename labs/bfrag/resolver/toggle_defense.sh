#!/bin/bash

set -euo pipefail

MODE="${1:-off}"
STATE_FILE="/app/defense_mode"

if [ "$MODE" = "on" ]; then
    echo "on" > "$STATE_FILE"
    echo "[+] R2 defense is ON"
else
    echo "off" > "$STATE_FILE"
    echo "[+] R2 defense is OFF"
fi
