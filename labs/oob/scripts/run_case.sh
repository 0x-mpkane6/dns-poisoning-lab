#!/bin/bash
#
# OoB lab runner.
# Cases:
#   baseline                  - không attack, defense off
#   attack-off                - attack default profile (1 vector), defense off
#   attack-on                 - attack default profile, defense on
#   attack-off-multi          - attack multi-vector profile, defense off
#   attack-on-multi           - attack multi-vector profile, defense on
# Add suffix -weak, -full, or -bruteforce/-paper to force one entropy profile.
#
# Usage: bash run_case.sh <case> [rounds]

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
    echo "Usage: $0 <baseline|attack-off|attack-on|attack-off-multi|attack-on-multi>[-weak|-full|-bruteforce|-paper] [rounds]"
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
stop_attack_worker "python3 /app/spoof.py"

PROFILE="default"
DEFENSE="off"
NEED_ATTACKER="0"

case "$CASE_BASE" in
    baseline)
        DEFENSE="off"
        NEED_ATTACKER="0"
        ;;
    attack-off)
        DEFENSE="off"
        NEED_ATTACKER="1"
        PROFILE="default"
        ;;
    attack-on)
        DEFENSE="on"
        NEED_ATTACKER="1"
        PROFILE="default"
        ;;
    attack-off-multi)
        DEFENSE="off"
        NEED_ATTACKER="1"
        PROFILE="multi"
        ;;
    attack-on-multi)
        DEFENSE="on"
        NEED_ATTACKER="1"
        PROFILE="multi"
        ;;
    *)
        echo "Unknown case: $CASE_NAME"
        echo "Usage: $0 <baseline|attack-off|attack-on|attack-off-multi|attack-on-multi>[-weak|-full|-bruteforce|-paper] [rounds]"
        exit 1
        ;;
esac

toggle_defense "$DEFENSE"

if [ "$NEED_ATTACKER" = "1" ]; then
    start_attack_worker "ATTACK_PROFILE=${PROFILE} nohup python3 /app/spoof.py >/tmp/attack.log 2>&1 &"
    sleep 1
else
    docker compose stop attacker >/dev/null 2>&1 || true
fi

PROBE_PROFILE="attack"
if [ "$CASE_BASE" = "baseline" ]; then
    PROBE_PROFILE="baseline"
fi
run_client_probe "$TARGET_ZONE" "$ROUNDS" "$PROBE_PROFILE"

collect_metrics "$POISON_IP"
