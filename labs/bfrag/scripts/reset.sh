#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$LAB_DIR"

if ! command -v docker >/dev/null 2>&1; then
    echo "[!] docker command not found."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker daemon is not reachable. Start Docker Desktop/service first."
    exit 1
fi

docker compose down -v
docker compose up -d --build

echo "[+] Lab reset done"
