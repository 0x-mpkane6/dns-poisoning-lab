#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_SCRIPT_DIR="$(cd "$LAB_DIR/../base/scripts" && pwd)"
ROUNDS="${1:-${ROUNDS:-150}}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
export RUN_ID

source "$BASE_SCRIPT_DIR/run_case_common.sh"

VARIANTS=(txid port kaminsky)
CASES=(baseline attack-off attack-on)

usage() {
    cat <<'EOF'
Usage:
  bash ./scripts/run_all_cases.sh [rounds]

Examples:
  bash ./scripts/run_all_cases.sh
  bash ./scripts/run_all_cases.sh 150
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if ! [[ "$ROUNDS" =~ ^[0-9]+$ ]]; then
    echo "[-] rounds must be an integer"
    exit 1
fi

cd "$LAB_DIR"
ensure_docker_ready
mkdir -p "$LAB_DIR/artifacts/$RUN_ID"

echo "[+] Run artifacts: $LAB_DIR/artifacts/$RUN_ID"

for variant in "${VARIANTS[@]}"; do
    echo
    echo "=============================="
    echo " S-type variant: $variant"
    echo "=============================="

    for case_name in "${CASES[@]}"; do
        echo
        echo "--- Running $case_name ($variant), rounds=$ROUNDS ---"
        # Keep each measurement isolated so poisoned cache cannot leak into the next case.
        compose down -v --remove-orphans >/dev/null 2>&1 || true
        ATTACK_VARIANT="$variant" bash "$SCRIPT_DIR/run_case.sh" "$case_name" "$ROUNDS"
    done
done

echo
echo "[+] All S-type cases completed"
echo "[+] Artifacts saved under $LAB_DIR/artifacts/$RUN_ID"
