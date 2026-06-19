#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_SCRIPT_DIR="$(cd "$LAB_DIR/../base/scripts" && pwd)"

source "$BASE_SCRIPT_DIR/run_case_common.sh"

CASE_NAME="${1:-}"
ROUNDS="${2:-${ROUNDS:-50}}"
TARGET_ZONE="${TARGET_ZONE:-example.net}"
POISON_IP="${POISON_IP:-6.6.6.6}"

if [ -z "$CASE_NAME" ]; then
    echo "Usage: $0 <baseline|attack-off|attack-on>[-weak|-full|-bruteforce|-paper] [rounds]"
    exit 1
fi

cd "$LAB_DIR"

CASE_BASE="$CASE_NAME"
case "$CASE_NAME" in
    *-weak)
        ENTROPY_MODE="weak"
        CASE_BASE="${CASE_NAME%-weak}"
        ;;
    *-full|*-realistic)
        ENTROPY_MODE="full"
        CASE_BASE="${CASE_NAME%-full}"
        CASE_BASE="${CASE_BASE%-realistic}"
        ;;
    *-bruteforce|*-paper)
        ENTROPY_MODE="bruteforce"
        CASE_BASE="${CASE_NAME%-bruteforce}"
        CASE_BASE="${CASE_BASE%-paper}"
        ;;
esac

configure_entropy_profile "${ENTROPY_MODE:-full}"
ensure_stack_up
stop_attack_worker "python3 /app/spoof_sfrag.py"

case "$CASE_BASE" in
    baseline)
        toggle_defense off
        docker compose stop attacker >/dev/null 2>&1 || true
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "baseline"
        ;;
    attack-off)
        toggle_defense off
        start_attack_worker "nohup python3 /app/spoof_sfrag.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "attack"
        ;;
    attack-on)
        toggle_defense on
        start_attack_worker "nohup python3 /app/spoof_sfrag.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "attack"
        ;;
    *)
        echo "Unknown case: $CASE_NAME"
        echo "Usage: $0 <baseline|attack-off|attack-on>[-weak|-full|-bruteforce|-paper] [rounds]"
        exit 1
        ;;
esac

collect_metrics "$POISON_IP"
