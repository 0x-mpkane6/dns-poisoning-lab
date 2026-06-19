#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_SCRIPT_DIR="$(cd "$LAB_DIR/../base/scripts" && pwd)"

source "$BASE_SCRIPT_DIR/run_case_common.sh"

CASE_NAME="${1:-}"
ROUNDS="${2:-${ROUNDS:-150}}"
TARGET_ZONE="${TARGET_ZONE:-example.net}"
POISON_IP="${POISON_IP:-6.6.6.6}"
ATTACK_VARIANT="${ATTACK_VARIANT:-txid}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
export ATTACK_VARIANT
export RUN_ID

if [ -z "$CASE_NAME" ]; then
    echo "Usage: $0 <baseline|attack-off|attack-on> [rounds]"
    exit 1
fi

cd "$LAB_DIR"

ensure_stack_up
stop_attack_worker "python3 /app/spoof_stype.py"

snapshot_case_artifacts() {
    local metrics="$1"
    local out_dir="$LAB_DIR/artifacts/$RUN_ID/$ATTACK_VARIANT/$CASE_NAME"
    local client_cid

    mkdir -p "$out_dir"
    printf "%s\n" "$metrics" > "$out_dir/metrics.txt"

    client_cid="$(compose ps -q client 2>/dev/null || true)"
    if [ -n "$client_cid" ]; then
        docker cp "${client_cid}:/app/result.txt" "$out_dir/result.txt" >/dev/null 2>&1 || true
        docker cp "${client_cid}:/app/latency_ms.txt" "$out_dir/latency_ms.txt" >/dev/null 2>&1 || true
    fi

    echo "[+] Artifacts saved to $out_dir"
}

run_stype_probe() {
    local profile="$1"
    compose exec -T client bash /app/test.sh "$TARGET_ZONE" "$ROUNDS" "$profile" "$ATTACK_VARIANT"
}

case "$CASE_NAME" in
    baseline)
        toggle_defense off
        compose stop attacker >/dev/null 2>&1 || true
        run_stype_probe "baseline"
        ;;
    attack-off)
        toggle_defense off
        start_attack_worker "ATTACK_VARIANT=$ATTACK_VARIANT nohup python3 /app/spoof_stype.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_stype_probe "attack"
        ;;
    attack-on)
        toggle_defense on
        start_attack_worker "ATTACK_VARIANT=$ATTACK_VARIANT nohup python3 /app/spoof_stype.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_stype_probe "attack"
        ;;
    *)
        echo "Unknown case: $CASE_NAME"
        echo "Usage: $0 <baseline|attack-off|attack-on> [rounds]"
        exit 1
        ;;
esac

METRICS="$(collect_metrics "$POISON_IP")"
echo "$METRICS"
snapshot_case_artifacts "$METRICS"
