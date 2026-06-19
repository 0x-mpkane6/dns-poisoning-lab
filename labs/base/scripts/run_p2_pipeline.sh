#!/bin/bash
# Person-2 end-to-end pipeline (Docker version).
#
# Stages:
#   1. core         - 3 lab × 3 case × N run (baseline / attack-off / attack-on)
#   2. multi        - 2 extra OoB cases  (attack-off-multi, attack-on-multi)
#   3. ipid-sweep   - sfrag attack-off sweep over a list of IPID_SPACE values
#   4. analyze      - render markdown summary tables
#   5. charts       - matplotlib PNGs into <out_dir>/
#
# Usage:
#   bash run_p2_pipeline.sh [--rounds 50] [--runs 3] [--entropy full|weak|bruteforce] [--out-dir DIR]
#                           [--labs oob,sfrag,bfrag]
#                           [--artifact-dir DIR]
#                           [--ipid-list "256 512 1024 2048 4096 8192"]
#                           [--quick] [--no-multi] [--no-sweep] [--no-charts]
# --quick = rounds=20, runs=2, ipid-list "512 2048 8192".

set -euo pipefail

ROUNDS=50
RUNS=3
ENTROPY_MODE="${ENTROPY_MODE:-full}"
OUT_DIR=""
ARTIFACT_DIR=""
LABS_CSV="${LABS_CSV:-oob,sfrag,bfrag}"
IPID_LIST="256 512 1024 2048 4096 8192"
DO_CORE=1
DO_MULTI=1
DO_SWEEP=1
DO_CHARTS=1
DO_ANALYZE=1

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds) ROUNDS="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --entropy) ENTROPY_MODE="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --artifact-dir) ARTIFACT_DIR="$2"; shift 2 ;;
        --labs) LABS_CSV="$2"; shift 2 ;;
        --ipid-list) IPID_LIST="$2"; shift 2 ;;
        --quick) ROUNDS=20; RUNS=2; IPID_LIST="512 2048 8192"; shift ;;
        --no-multi) DO_MULTI=0; shift ;;
        --no-sweep) DO_SWEEP=0; shift ;;
        --no-charts) DO_CHARTS=0; shift ;;
        --no-analyze) DO_ANALYZE=0; shift ;;
        --no-core) DO_CORE=0; shift ;;
        -h|--help)
            sed -n '1,/^set -euo/p' "$0" | sed -n '/^# /p'; exit 0 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LABS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$(cd "$LABS_ROOT/../.." && pwd)/Report/data"
fi
mkdir -p "$OUT_DIR"
if [ -n "$ARTIFACT_DIR" ]; then
    mkdir -p "$ARTIFACT_DIR"
    ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
fi

CORE_CSV="${OUT_DIR}/p2_metrics.csv"
SWEEP_CSV="${OUT_DIR}/sfrag_ipid_sweep.csv"
SUMMARY_MD="${OUT_DIR}/p2_summary.md"

echo "=== Person-2 pipeline (Docker) ==="
IFS=',' read -r -a LABS <<< "$LABS_CSV"

lab_selected() {
    local target="$1"
    local lab
    for lab in "${LABS[@]}"; do
        if [ "$lab" = "$target" ]; then
            return 0
        fi
    done
    return 1
}

echo "  rounds=${ROUNDS} runs=${RUNS} entropy=${ENTROPY_MODE} labs=${LABS_CSV}"
echo "  core=${DO_CORE} multi=${DO_MULTI} sweep=${DO_SWEEP} analyze=${DO_ANALYZE} charts=${DO_CHARTS}"
echo "  out_dir=${OUT_DIR}"
[ -n "$ARTIFACT_DIR" ] && echo "  artifact_dir=${ARTIFACT_DIR}"
echo

CORE_CASES=(baseline attack-off attack-on)
MULTI_CASES=(attack-off-multi attack-on-multi)

run_case_collect() {
    local lab="$1" case_name="$2" run_idx="$3" rounds="$4"
    local lab_dir="${LABS_ROOT}/${lab}"
    pushd "$lab_dir" >/dev/null
    local OUTPUT
    OUTPUT="$(ENTROPY_MODE="$ENTROPY_MODE" bash ./scripts/run_case.sh "$case_name" "$rounds" 2>&1 || true)"
    echo "$OUTPUT" | tail -n 6
    local TOTAL POISONED ASR AVG_LAT P95_LAT
    TOTAL="$(echo "$OUTPUT"    | awk -F': ' '/^Total/   {print $2; exit}')"
    POISONED="$(echo "$OUTPUT" | awk -F': ' '/^Poisoned/{print $2; exit}')"
    ASR="$(echo "$OUTPUT"      | awk -F'= ' '/Success rate/ {gsub("%","",$2); print $2; exit}')"
    AVG_LAT="$(echo "$OUTPUT"  | awk -F'= ' '/Latency avg/  {gsub(" ms","",$2); print $2; exit}')"
    P95_LAT="$(echo "$OUTPUT"  | awk -F'= ' '/Latency p95/  {gsub(" ms","",$2); print $2; exit}')"
    echo "${lab},${case_name},${run_idx},${rounds},${TOTAL:-0},${POISONED:-0},${ASR:-0},${AVG_LAT:-0},${P95_LAT:-0}" >> "$CORE_CSV"
    if [ -n "$ARTIFACT_DIR" ]; then
        local target_dir="${ARTIFACT_DIR}/${lab}-${ENTROPY_MODE}/${case_name}"
        if [ "$RUNS" -gt 1 ]; then
            target_dir="${ARTIFACT_DIR}/${lab}-${ENTROPY_MODE}/run-${run_idx}/${case_name}"
        fi
        mkdir -p "$target_dir"
        echo "$OUTPUT" | awk '/^(Total|Poisoned|Success rate|Latency samples|Latency avg|Latency p95)/ {print}' > "${target_dir}/metrics.txt"
        docker compose exec -T client cat /app/result.txt > "${target_dir}/result.txt" 2>/dev/null || true
        docker compose exec -T client cat /app/latency_ms.txt > "${target_dir}/latency_ms.txt" 2>/dev/null || true
    fi
    popd >/dev/null
}

# Stage 1 - core
if [ "$DO_CORE" = "1" ]; then
    echo "lab,case,run,rounds,total,poisoned,asr_pct,latency_avg_ms,latency_p95_ms" > "$CORE_CSV"
    for lab in "${LABS[@]}"; do
        echo "================================================================"
        echo "[+] Lab ${lab} (core)"
        echo "================================================================"
        for case_name in "${CORE_CASES[@]}"; do
            for run_idx in $(seq 1 "$RUNS"); do
                echo "[+] ${lab}/${case_name} run ${run_idx}/${RUNS}"
                run_case_collect "$lab" "$case_name" "$run_idx" "$ROUNDS"
            done
        done
    done
fi

# Stage 2 - oob multi-vector
if [ "$DO_MULTI" = "1" ] && lab_selected oob; then
    echo "================================================================"
    echo "[+] Lab oob (multi-vector)"
    echo "================================================================"
    for case_name in "${MULTI_CASES[@]}"; do
        for run_idx in $(seq 1 "$RUNS"); do
            echo "[+] oob/${case_name} run ${run_idx}/${RUNS}"
            run_case_collect "oob" "$case_name" "$run_idx" "$ROUNDS"
        done
    done
fi

# Stage 3 - IPID sweep
if [ "$DO_SWEEP" = "1" ] && lab_selected sfrag; then
    bash "${SCRIPT_DIR}/ipid_sweep.sh" "$ROUNDS" "$RUNS" "$SWEEP_CSV" "$IPID_LIST"
fi

# Stage 4 - analyze
if [ "$DO_ANALYZE" = "1" ] && [ -f "$CORE_CSV" ]; then
    python3 "${SCRIPT_DIR}/analyze_metrics.py" "$CORE_CSV" --md "$SUMMARY_MD" || true
fi

# Stage 5 - charts
if [ "$DO_CHARTS" = "1" ] && [ -f "$CORE_CSV" ]; then
    SWEEP_FLAG=""
    if [ -f "$SWEEP_CSV" ]; then
        SWEEP_FLAG="--sweep $SWEEP_CSV"
    fi
    python3 "${SCRIPT_DIR}/make_charts.py" --core "$CORE_CSV" $SWEEP_FLAG --outdir "$OUT_DIR" || true
fi

echo
echo "=== Pipeline done ==="
echo "  CSV:        $CORE_CSV"
[ -f "$SWEEP_CSV" ] && echo "  Sweep CSV:  $SWEEP_CSV"
[ -f "$SUMMARY_MD" ] && echo "  Summary MD: $SUMMARY_MD"
[ -f "${OUT_DIR}/asr_by_case.png" ] && echo "  Charts:     ${OUT_DIR}/*.png"
exit 0
