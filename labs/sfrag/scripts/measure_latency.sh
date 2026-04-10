#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_SCRIPT_DIR="$(cd "$LAB_DIR/../base/scripts" && pwd)"

cd "$LAB_DIR"
bash "$BASE_SCRIPT_DIR/measure_latency.sh" client "/app/latency_ms.txt"
