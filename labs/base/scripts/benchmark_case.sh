#!/bin/bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <run_case_script> <baseline|attack-off|attack-on> [rounds] [runs]"
    exit 1
fi

RUN_CASE_SCRIPT="$1"
CASE_NAME="$2"
ROUNDS="${3:-50}"
RUNS="${4:-3}"

if [ ! -x "$RUN_CASE_SCRIPT" ]; then
    echo "run_case script is not executable: $RUN_CASE_SCRIPT"
    exit 1
fi

TMP_METRICS="$(mktemp)"
trap 'rm -f "$TMP_METRICS"' EXIT

for n in $(seq 1 "$RUNS"); do
    echo "[+] Run ${n}/${RUNS}"
    OUTPUT="$("$RUN_CASE_SCRIPT" "$CASE_NAME" "$ROUNDS")"
    echo "$OUTPUT"

    ASR="$(echo "$OUTPUT" | awk -F'= ' '/Success rate/ { gsub("%","",$2); print $2; exit }')"
    AVG_LAT="$(echo "$OUTPUT" | awk -F'= ' '/Latency avg/ { gsub(" ms","",$2); print $2; exit }')"
    P95_LAT="$(echo "$OUTPUT" | awk -F'= ' '/Latency p95/ { gsub(" ms","",$2); print $2; exit }')"

    echo "${ASR:-0} ${AVG_LAT:-0} ${P95_LAT:-0}" >> "$TMP_METRICS"
done

MEAN_ASR="$(awk '{ s += $1 } END { if (NR == 0) { print "0.00" } else { printf "%.2f", s / NR } }' "$TMP_METRICS")"
MEAN_AVG_LAT="$(awk '{ s += $2 } END { if (NR == 0) { print "0.000" } else { printf "%.3f", s / NR } }' "$TMP_METRICS")"
MEAN_P95_LAT="$(awk '{ s += $3 } END { if (NR == 0) { print "0.000" } else { printf "%.3f", s / NR } }' "$TMP_METRICS")"

echo
echo "===== Benchmark Summary ====="
echo "Case: ${CASE_NAME}"
echo "Rounds per run: ${ROUNDS}"
echo "Total runs: ${RUNS}"
echo "Mean ASR: ${MEAN_ASR}%"
echo "Mean latency avg: ${MEAN_AVG_LAT} ms"
echo "Mean latency p95: ${MEAN_P95_LAT} ms"
