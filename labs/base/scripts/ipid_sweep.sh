#!/bin/bash
# Run sfrag attack-off with a series of IPID_SPACE values to plot ASR vs IPID space.
#
# Usage:
#   bash ipid_sweep.sh [rounds] [runs] [out_csv] [ipid_list]
#
# Defaults: rounds=50, runs=2, out_csv=./sfrag_ipid_sweep.csv,
#           ipid_list="256 512 1024 2048 4096 8192".
#
# CSV schema: lab,case,run,rounds,total,poisoned,asr_pct,latency_avg_ms,
#             latency_p95_ms,ipid_space

set -euo pipefail

ROUNDS="${1:-50}"
RUNS="${2:-2}"
OUT_CSV="${3:-./sfrag_ipid_sweep.csv}"
IPID_LIST="${4:-256 512 1024 2048 4096 8192}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LABS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SFRAG_DIR="$LABS_ROOT/sfrag"

source "$SCRIPT_DIR/run_case_common.sh"
configure_entropy_profile "${ENTROPY_MODE:-full}"

if [ ! -d "$SFRAG_DIR" ]; then
    echo "[!] missing sfrag lab dir: $SFRAG_DIR" >&2
    exit 1
fi

echo "lab,case,run,rounds,total,poisoned,asr_pct,latency_avg_ms,latency_p95_ms,ipid_space" > "$OUT_CSV"

pushd "$SFRAG_DIR" >/dev/null

for ipid in $IPID_LIST; do
    echo "================================================================"
    echo "[+] sfrag/attack-off  IPID_SPACE=${ipid}"
    echo "================================================================"

    export IPID_SPACE="$ipid"
    if [ "${ENTROPY_MODE:-full}" = "weak" ]; then
        export IPID_SCAN_LIMIT="$ipid"
    fi
    # Force docker compose to recreate auth/attacker/resolver with new entropy/IPID env.
    BUILD_ARGS=()
    if [ "${BUILD_IMAGES:-0}" = "1" ]; then
        BUILD_ARGS+=(--build)
    fi
    docker compose up -d "${BUILD_ARGS[@]}" --force-recreate >/dev/null 2>&1 || true
    sleep 2

    for run_idx in $(seq 1 "$RUNS"); do
        echo "[+] run ${run_idx}/${RUNS}"
        OUTPUT="$(ENTROPY_MODE="${ENTROPY_MODE:-full}" IPID_SPACE="$ipid" bash ./scripts/run_case.sh attack-off "$ROUNDS" 2>&1 || true)"
        echo "$OUTPUT" | tail -n 6

        TOTAL="$(echo "$OUTPUT"   | awk -F': ' '/^Total/   {print $2; exit}')"
        POISONED="$(echo "$OUTPUT"| awk -F': ' '/^Poisoned/{print $2; exit}')"
        ASR="$(echo "$OUTPUT"     | awk -F'= ' '/Success rate/ {gsub("%","",$2); print $2; exit}')"
        AVG_LAT="$(echo "$OUTPUT" | awk -F'= ' '/Latency avg/  {gsub(" ms","",$2); print $2; exit}')"
        P95_LAT="$(echo "$OUTPUT" | awk -F'= ' '/Latency p95/  {gsub(" ms","",$2); print $2; exit}')"

        echo "sfrag,attack-off,${run_idx},${ROUNDS},${TOTAL:-0},${POISONED:-0},${ASR:-0},${AVG_LAT:-0},${P95_LAT:-0},${ipid}" >> "$OUT_CSV"
    done
done

popd >/dev/null

echo
echo "[+] IPID sweep done. CSV: ${OUT_CSV}"
