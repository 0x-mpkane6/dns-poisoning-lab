#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    cat <<'EOF'
Usage:
  bash scripts/run_pipeline.sh [--build] [--skip-up] [zone] [baseline_rounds] [attack_rounds]

Examples:
  bash scripts/run_pipeline.sh
  bash scripts/run_pipeline.sh example.net 10 50
  bash scripts/run_pipeline.sh --build example.net 10 50
EOF
}

DO_BUILD=0
SKIP_UP=0

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            DO_BUILD=1
            shift
            ;;
        --skip-up)
            SKIP_UP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL[@]}"

ZONE="${1:-example.net}"
BASELINE_ROUNDS="${2:-10}"
ATTACK_ROUNDS="${3:-50}"

if ! [[ "$BASELINE_ROUNDS" =~ ^[0-9]+$ ]] || ! [[ "$ATTACK_ROUNDS" =~ ^[0-9]+$ ]]; then
    echo "[-] baseline_rounds and attack_rounds must be integer values"
    exit 1
fi

RUN_TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$ROOT_DIR/artifacts/pipeline_$RUN_TS"
mkdir -p "$OUT_DIR"

declare -A PHASE_TOTAL
declare -A PHASE_POISON
declare -A PHASE_RATE

stop_attacker() {
    docker exec attacker sh -lc "pkill -f '/app/spoof.py' 2>/dev/null || true" >/dev/null 2>&1 || true
}

start_attacker() {
    stop_attacker
    docker exec -d attacker sh -lc "python3 /app/spoof.py >/tmp/spoof.log 2>&1" >/dev/null
    sleep 1
}

capture_phase_metrics() {
    local phase_key="$1"
    local metrics="$2"

    PHASE_TOTAL["$phase_key"]="$(echo "$metrics" | awk -F': ' '/^Total:/ {print $2}')"
    PHASE_POISON["$phase_key"]="$(echo "$metrics" | awk -F': ' '/^Poisoned:/ {print $2}')"
    PHASE_RATE["$phase_key"]="$(echo "$metrics" | awk -F'= ' '/^Success rate/ {print $2}')"
}

run_phase() {
    local phase_key="$1"
    local phase_title="$2"
    local defense_mode="$3"
    local rounds="$4"

    echo
    echo "=== $phase_title ==="
    docker exec resolver bash /app/toggle_defense.sh "$defense_mode" >/dev/null
    docker exec client bash /app/test.sh "$ZONE" "$rounds"

    local metrics
    metrics="$(bash scripts/measure.sh)"
    echo "$metrics"

    echo "$metrics" > "$OUT_DIR/${phase_key}_metrics.txt"
    docker cp client:/app/result.txt "$OUT_DIR/${phase_key}_result.txt" >/dev/null
    capture_phase_metrics "$phase_key" "$metrics"
}

trap stop_attacker EXIT

echo "[1/4] Preparing containers..."
if [[ "$SKIP_UP" -eq 0 ]]; then
    if [[ "$DO_BUILD" -eq 1 ]]; then
        docker compose up -d --build
    else
        docker compose up -d
    fi
fi

echo "[2/4] Running baseline without attacker..."
run_phase "baseline" "Baseline (Defense OFF, No Attacker)" "off" "$BASELINE_ROUNDS"

echo "[3/4] Running OoB attack with defense OFF..."
start_attacker
run_phase "attack_off" "Attack (Defense OFF)" "off" "$ATTACK_ROUNDS"

echo "[4/4] Running OoB attack with defense ON..."
run_phase "attack_on" "Attack (Defense ON / Rl3 Enabled)" "on" "$ATTACK_ROUNDS"

{
    echo "zone=$ZONE"
    echo "baseline_rounds=$BASELINE_ROUNDS"
    echo "attack_rounds=$ATTACK_ROUNDS"
    echo
    echo "phase,total,poisoned,success_rate"
    echo "baseline,${PHASE_TOTAL[baseline]},${PHASE_POISON[baseline]},${PHASE_RATE[baseline]}"
    echo "attack_off,${PHASE_TOTAL[attack_off]},${PHASE_POISON[attack_off]},${PHASE_RATE[attack_off]}"
    echo "attack_on,${PHASE_TOTAL[attack_on]},${PHASE_POISON[attack_on]},${PHASE_RATE[attack_on]}"
} > "$OUT_DIR/summary.csv"

echo
echo "=== Summary ==="
echo "Baseline    : poisoned=${PHASE_POISON[baseline]}/${PHASE_TOTAL[baseline]} | rate=${PHASE_RATE[baseline]}"
echo "Attack OFF  : poisoned=${PHASE_POISON[attack_off]}/${PHASE_TOTAL[attack_off]} | rate=${PHASE_RATE[attack_off]}"
echo "Attack ON   : poisoned=${PHASE_POISON[attack_on]}/${PHASE_TOTAL[attack_on]} | rate=${PHASE_RATE[attack_on]}"
echo "Artifacts   : $OUT_DIR"

