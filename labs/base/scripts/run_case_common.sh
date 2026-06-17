#!/bin/bash

set -euo pipefail

BASE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_CMD=()

compose() {
    "${COMPOSE_CMD[@]}" "$@"
}

ensure_docker_ready() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "[!] docker command not found. Install Docker Desktop / Docker Engine first."
        return 1
    fi

    if ! docker info >/dev/null 2>&1; then
        echo "[!] Docker daemon is not reachable."
        echo "    Start Docker Desktop (or Docker service) and retry."
        return 1
    fi

    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
    else
        echo "[!] docker compose plugin or docker-compose command is unavailable."
        return 1
    fi
}

ensure_stack_up() {
    ensure_docker_ready
    compose up -d
}

toggle_defense() {
    local mode="${1:-off}"
    compose exec -T resolver bash /app/toggle_defense.sh "$mode"
}

run_client_probe() {
    local target_zone="$1"
    local rounds="$2"
    local profile="${3:-attack}"
    compose exec -T client bash /app/test.sh "$target_zone" "$rounds" "$profile"
}

start_attack_worker() {
    local cmd="$1"
    compose start attacker >/dev/null 2>&1 || true
    compose exec -T attacker sh -lc "$cmd"
}

stop_attack_worker() {
    local match_pattern="${1:-python3 /app/}"
    compose exec -T attacker sh -lc "pkill -f \"$match_pattern\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
}

collect_metrics() {
    local poison_ip="${1:-6.6.6.6}"
    bash "$BASE_SCRIPT_DIR/measure_asr.sh" client "$poison_ip" "/app/result.txt"
    bash "$BASE_SCRIPT_DIR/measure_latency.sh" client "/app/latency_ms.txt"
}
