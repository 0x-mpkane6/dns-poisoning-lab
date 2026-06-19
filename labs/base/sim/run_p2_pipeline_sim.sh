#!/bin/bash
# Simulator-based Person-2 pipeline (no Docker).
# Stages: core 3-lab × 5 cases (incl. multi-vector for OoB) + sfrag IPID sweep
# + Markdown summary + matplotlib charts.
#
# Usage:
#   bash run_p2_pipeline_sim.sh [--rounds 50] [--runs 3] [--entropy full|weak|bruteforce] [--out-dir DIR]
#                               [--labs oob,sfrag,bfrag]
#                               [--ipid-list "256,512,1024,2048,4096,8192"]
#                               [--quick]
# --quick = rounds=20, runs=2, ipid-list "512,2048,8192" (fast smoke).

set -euo pipefail

ROUNDS=50
RUNS=3
ENTROPY_MODE="${ENTROPY_MODE:-full}"
OUT_DIR=""
LABS_CSV="${LABS_CSV:-oob,sfrag,bfrag}"
IPID_LIST="256,512,1024,2048,4096,8192"

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds) ROUNDS="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --entropy) ENTROPY_MODE="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --labs) LABS_CSV="$2"; shift 2 ;;
        --ipid-list) IPID_LIST="$2"; shift 2 ;;
        --quick) ROUNDS=20; RUNS=2; IPID_LIST="512,2048,8192"; shift ;;
        -h|--help) sed -n '1,/^set -euo/p' "$0" | sed -n '/^# /p'; exit 0 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$(cd "$SCRIPT_DIR/../scripts" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="${PROJECT_ROOT}/Report/data"
fi
mkdir -p "$OUT_DIR"

CORE_CSV="${OUT_DIR}/p2_metrics_sim.csv"
SWEEP_CSV="${OUT_DIR}/sfrag_ipid_sweep_sim.csv"
SUMMARY_MD="${OUT_DIR}/p2_summary_sim.md"

echo "=== Person-2 simulator pipeline ==="
echo "  rounds=${ROUNDS} runs=${RUNS} entropy=${ENTROPY_MODE} labs=${LABS_CSV} ipid=${IPID_LIST}"
echo "  out_dir=${OUT_DIR}"
echo

# Stage 1: 3-lab core
python3 "${SCRIPT_DIR}/sim_runner.py" \
    --lab "$LABS_CSV" --rounds "$ROUNDS" --runs "$RUNS" \
    --entropy "$ENTROPY_MODE" \
    --cases "baseline,attack-off,attack-on" \
    --out "$CORE_CSV"

# Stage 2: oob multi-vector (append)
if [[ ",$LABS_CSV," == *",oob,"* ]]; then
    python3 "${SCRIPT_DIR}/sim_runner.py" \
        --lab oob --rounds "$ROUNDS" --runs "$RUNS" \
        --entropy "$ENTROPY_MODE" \
        --cases "attack-off-multi,attack-on-multi" \
        --append --out "$CORE_CSV"
fi

# Stage 3: sfrag IPID sweep
if [[ ",$LABS_CSV," == *",sfrag,"* ]]; then
    python3 "${SCRIPT_DIR}/ipid_sweep_sim.py" \
        --rounds "$ROUNDS" --runs "$RUNS" --entropy "$ENTROPY_MODE" --ipid-list "$IPID_LIST" \
        --out "$SWEEP_CSV"
fi

# Stage 4: analyze
python3 "${SCRIPTS_DIR}/analyze_metrics.py" "$CORE_CSV" --md "$SUMMARY_MD" || true

# Stage 5: charts
SWEEP_ARGS=()
if [ -f "$SWEEP_CSV" ]; then
    SWEEP_ARGS=(--sweep "$SWEEP_CSV")
fi
python3 "${SCRIPTS_DIR}/make_charts.py" \
    --core "$CORE_CSV" \
    "${SWEEP_ARGS[@]}" \
    --outdir "$OUT_DIR"

echo
echo "=== Sim pipeline done ==="
echo "  Core CSV:   $CORE_CSV"
echo "  Sweep CSV:  $SWEEP_CSV"
echo "  Summary MD: $SUMMARY_MD"
echo "  Charts:     ${OUT_DIR}/*.png"
