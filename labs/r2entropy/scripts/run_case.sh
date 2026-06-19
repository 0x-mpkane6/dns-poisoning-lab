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
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
export RUN_ID

if [ -z "$CASE_NAME" ]; then
    echo "Usage: $0 <baseline|benign-on|attack-on> [rounds]"
    exit 1
fi

cd "$LAB_DIR"

ensure_stack_up
stop_attack_worker "python3 /app/spoof_r2entropy.py"

snapshot_case_artifacts() {
    local metrics="$1"
    local out_dir="$LAB_DIR/artifacts/$RUN_ID/$CASE_NAME"
    local client_cid
    local resolver_cid
    local attacker_cid

    mkdir -p "$out_dir"
    printf "%s\n" "$metrics" > "$out_dir/metrics.txt"

    client_cid="$(compose ps -q client 2>/dev/null || true)"
    resolver_cid="$(compose ps -q resolver 2>/dev/null || true)"
    attacker_cid="$(compose ps -q attacker 2>/dev/null || true)"

    if [ -n "$client_cid" ]; then
        docker cp "${client_cid}:/app/result.txt" "$out_dir/result.txt" >/dev/null 2>&1 || true
        docker cp "${client_cid}:/app/latency_ms.txt" "$out_dir/latency_ms.txt" >/dev/null 2>&1 || true
    fi

    if [ -n "$resolver_cid" ]; then
        docker cp "${resolver_cid}:/app/frag2_events.jsonl" "$out_dir/frag2_events.jsonl" >/dev/null 2>&1 || true
        docker cp "${resolver_cid}:/app/r2_entropy_decisions.jsonl" "$out_dir/r2_entropy_decisions.jsonl" >/dev/null 2>&1 || true
        docker cp "${resolver_cid}:/app/r2_entropy_summary.json" "$out_dir/r2_entropy_summary.json" >/dev/null 2>&1 || true
    fi

    if [ -n "$attacker_cid" ]; then
        docker cp "${attacker_cid}:/tmp/attack.log" "$out_dir/attack.log" >/dev/null 2>&1 || true
    fi

    compose logs resolver > "$out_dir/resolver.log" 2>&1 || true
    compose logs attacker > "$out_dir/attacker.log" 2>&1 || true

    echo "[+] Artifacts saved to $out_dir"
}

case "$CASE_NAME" in
    baseline)
        toggle_defense on
        compose stop attacker >/dev/null 2>&1 || true
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "baseline"
        ;;
    benign-on)
        toggle_defense on
        compose stop attacker >/dev/null 2>&1 || true
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "benign-frag"
        ;;
    attack-on)
        toggle_defense on
        start_attack_worker "nohup python3 /app/spoof_r2entropy.py >/tmp/attack.log 2>&1 &"
        sleep 1
        run_client_probe "$TARGET_ZONE" "$ROUNDS" "attack"
        ;;
    *)
        echo "Unknown case: $CASE_NAME"
        echo "Usage: $0 <baseline|benign-on|attack-on> [rounds]"
        exit 1
        ;;
esac

METRICS="$(collect_metrics "$POISON_IP")"
echo "$METRICS"
snapshot_case_artifacts "$METRICS"
