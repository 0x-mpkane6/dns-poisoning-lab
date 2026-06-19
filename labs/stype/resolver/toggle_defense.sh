#!/bin/bash

MODE="$1"
STATE_FILE="/app/defense_mode"

if [ "$MODE" == "on" ]; then
    echo "on" > "$STATE_FILE"
    echo "[+] Rl1 defense is ON"
else
    echo "off" > "$STATE_FILE"
    echo "[+] Rl1 defense is OFF"
fi
