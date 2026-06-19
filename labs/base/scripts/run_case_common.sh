#!/bin/bash

set -euo pipefail

# Prevent Git Bash on Windows from mangling absolute container paths
# like /app/... into C:/Program Files/Git/app/...
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

BASE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

    if ! docker compose version >/dev/null 2>&1; then
        echo "[!] docker compose plugin is unavailable."
        return 1
    fi
}

ensure_stack_up() {
    ensure_docker_ready
    local build_args=()
    if [ "${BUILD_IMAGES:-0}" = "1" ]; then
        build_args+=(--build)
    fi
    if [ "${FORCE_RECREATE:-0}" = "1" ]; then
        docker compose up -d "${build_args[@]}" --force-recreate
    else
        docker compose up -d "${build_args[@]}"
    fi
}

configure_entropy_profile() {
    local mode="${1:-full}"
    case "$mode" in
        full|realistic)
            export ENTROPY_MODE="full"
            export UPSTREAM_FIXED_SRC_PORT="${UPSTREAM_FIXED_SRC_PORT:-0}"
            export RESOLVER_UPSTREAM_PORT="${RESOLVER_UPSTREAM_PORT:-33333}"
            export TXID_SPACE="${TXID_SPACE:-65536}"
            export TXID_SCAN_LIMIT="${TXID_SCAN_LIMIT:-4096}"
            export IPID_SPACE="${IPID_SPACE:-65535}"
            export IPID_SCAN_LIMIT="${IPID_SCAN_LIMIT:-8192}"
            unset SRC_PORT_START SRC_PORT_END SRC_PORT_SCAN_LIMIT
            export PACKET_CHUNK_SIZE="${PACKET_CHUNK_SIZE:-512}"
            ;;
        bruteforce|paper)
            export ENTROPY_MODE="bruteforce"
            export UPSTREAM_FIXED_SRC_PORT="${UPSTREAM_FIXED_SRC_PORT:-0}"
            export RESOLVER_UPSTREAM_PORT="${RESOLVER_UPSTREAM_PORT:-33333}"
            export TXID_SPACE="${TXID_SPACE:-65536}"
            export TXID_SCAN_LIMIT="${TXID_SCAN_LIMIT:-65536}"
            export IPID_SPACE="${IPID_SPACE:-65535}"
            export IPID_SCAN_LIMIT="${IPID_SCAN_LIMIT:-65535}"
            export SRC_PORT_START="${SRC_PORT_START:-1024}"
            export SRC_PORT_END="${SRC_PORT_END:-65535}"
            export SRC_PORT_SCAN_LIMIT="${SRC_PORT_SCAN_LIMIT:-$((SRC_PORT_END - SRC_PORT_START + 1))}"
            export PACKET_CHUNK_SIZE="${PACKET_CHUNK_SIZE:-512}"
            ;;
        weak|demo)
            export ENTROPY_MODE="weak"
            export UPSTREAM_FIXED_SRC_PORT="${UPSTREAM_FIXED_SRC_PORT:-33333}"
            export RESOLVER_UPSTREAM_PORT="${RESOLVER_UPSTREAM_PORT:-33333}"
            export TXID_SPACE="${TXID_SPACE:-1024}"
            export TXID_SCAN_LIMIT="${TXID_SCAN_LIMIT:-1024}"
            export IPID_SPACE="${IPID_SPACE:-2048}"
            export IPID_SCAN_LIMIT="${IPID_SCAN_LIMIT:-$IPID_SPACE}"
            unset SRC_PORT_START SRC_PORT_END SRC_PORT_SCAN_LIMIT
            export PACKET_CHUNK_SIZE="${PACKET_CHUNK_SIZE:-512}"
            ;;
        *)
            echo "[!] Unknown ENTROPY_MODE: $mode (use full, weak, or bruteforce)" >&2
            return 1
            ;;
    esac

    # Recreate containers so Docker Compose applies the entropy env vars.
    export FORCE_RECREATE="${FORCE_RECREATE:-1}"
    export BUILD_IMAGES="${BUILD_IMAGES:-1}"
    local src_port_desc="${UPSTREAM_FIXED_SRC_PORT:-0}"
    if [ "${ENTROPY_MODE}" = "bruteforce" ]; then
        src_port_desc="${SRC_PORT_START}-${SRC_PORT_END} scan=${SRC_PORT_SCAN_LIMIT}"
    fi
    echo "[+] entropy=${ENTROPY_MODE} txid=${TXID_SPACE} txid_scan=${TXID_SCAN_LIMIT} src_port=${src_port_desc} ipid=${IPID_SPACE} ipid_scan=${IPID_SCAN_LIMIT}"
}

# Restart resolver container to wipe its in-memory DNS cache. Without this,
# a poisoned bank.com -> 6.6.6.6 record cached during an attack-OFF case
# survives into the next attack-ON case and makes defense look broken.
flush_resolver_cache() {
    docker compose restart resolver >/dev/null 2>&1 || true
    # Wait until resolver's UDP socket is listening again. Small sleep
    # is fine; the dnslib server boots in well under a second.
    sleep 2
}

toggle_defense() {
    local mode="${1:-off}"
    # Wipe stale cache first so the new defense mode is exercised on a
    # clean slate (no leftover poisoned records from the previous case).
    flush_resolver_cache
    docker compose exec -T resolver bash /app/toggle_defense.sh "$mode"
}

run_client_probe() {
    local target_zone="$1"
    local rounds="$2"
    local profile="${3:-attack}"
    docker compose exec -T client bash /app/test.sh "$target_zone" "$rounds" "$profile"
}

start_attack_worker() {
    local cmd="$1"
    docker compose start attacker >/dev/null 2>&1 || true
    docker compose exec -T attacker sh -lc "$cmd"
}

stop_attack_worker() {
    local match_pattern="${1:-python3 /app/}"
    docker compose exec -T attacker sh -lc "pkill -f \"$match_pattern\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
}

collect_metrics() {
    local poison_ip="${1:-6.6.6.6}"
    bash "$BASE_SCRIPT_DIR/measure_asr.sh" client "$poison_ip" "/app/result.txt"
    bash "$BASE_SCRIPT_DIR/measure_latency.sh" client "/app/latency_ms.txt"
}
