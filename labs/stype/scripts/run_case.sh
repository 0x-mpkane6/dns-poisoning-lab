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

    mkdir -p "$out_dir"
    printf "%s\n" "$metrics" > "$out_dir/metrics.txt"

    # Stream via `docker compose exec ... cat` instead of `docker cp`: on
    # Docker Desktop for Windows, `docker cp <cid>:<path> <out_dir>` mangles
    # MSYS-style absolute destination paths (e.g. /d/foo/bar) into invalid
    # ones (e.g. D:\d\foo\bar) and fails silently under `|| true` (see
    # measure_asr.sh / measure_latency.sh, which use the same workaround).
    docker compose exec -T client cat /app/result.txt > "$out_dir/result.txt" 2>/dev/null || true
    docker compose exec -T client cat /app/latency_ms.txt > "$out_dir/latency_ms.txt" 2>/dev/null || true

    echo "[+] Artifacts saved to $out_dir"
}

run_stype_probe() {
    local profile="$1"
    docker compose exec -T client bash /app/test.sh "$TARGET_ZONE" "$ROUNDS" "$profile" "$ATTACK_VARIANT"
}

case "$CASE_NAME" in
    baseline)
        toggle_defense off
        docker compose stop attacker >/dev/null 2>&1 || true
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
