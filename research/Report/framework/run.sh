#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${1:-}"
WORKLOAD="${2:-}"
ROUNDS_ARG="${3:-${ROUNDS:-150}}"

usage() {
    echo "Usage: $0 <b0|b1|b2|b3|b4|b5> <baseline|benign|attack> [rounds]"
}

case "$PROFILE" in b0|b1|b2|b3|b4|b5) ;; *) usage; exit 2 ;; esac
case "$WORKLOAD" in baseline|benign|attack) ;; *) usage; exit 2 ;; esac

ENV_FILE="$ROOT/config/$PROFILE.env"
COMPOSE=(docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -f "$ROOT/compose.yaml")
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
OUT="$ROOT/artifacts/$RUN_ID/$PROFILE/$WORKLOAD"
mkdir -p "$OUT/app"

export ROUNDS="$ROUNDS_ARG"
"${COMPOSE[@]}" up -d --build --force-recreate
"${COMPOSE[@]}" exec -T auth bash /app/toggle_benign_frag2.sh off
"${COMPOSE[@]}" exec -T resolver bash /app/toggle_defense.sh "$(
    awk -F= '$1=="DEFENSE_MODE"{print $2}' "$ENV_FILE"
)"
"${COMPOSE[@]}" stop attacker >/dev/null 2>&1 || true

case "$WORKLOAD" in
    baseline)
        CLIENT_PROFILE=baseline
        ;;
    benign)
        CLIENT_PROFILE=benign-frag
        "${COMPOSE[@]}" exec -T auth bash /app/toggle_benign_frag2.sh on
        ;;
    attack)
        CLIENT_PROFILE=attack
        "${COMPOSE[@]}" start attacker >/dev/null
        "${COMPOSE[@]}" exec -T attacker sh -lc \
            "nohup python3 /app/spoof_r2entropy.py >/tmp/attack.log 2>&1 &"
        sleep 1
        ;;
esac

"${COMPOSE[@]}" exec -T client bash /app/test.sh example.net "$ROUNDS_ARG" "$CLIENT_PROFILE"

"${COMPOSE[@]}" exec -T client cat /app/result.txt > "$OUT/result.txt" 2>/dev/null || true
"${COMPOSE[@]}" exec -T client cat /app/latency_ms.txt > "$OUT/latency_ms.txt" 2>/dev/null || true
"${COMPOSE[@]}" exec -T resolver cat /app/frag2_events.jsonl > "$OUT/app/frag2_events.jsonl" 2>/dev/null || true
"${COMPOSE[@]}" exec -T resolver cat /app/r2_entropy_decisions.jsonl > "$OUT/app/r2_decisions.jsonl" 2>/dev/null || true
"${COMPOSE[@]}" exec -T resolver cat /app/r2_entropy_summary.json > "$OUT/app/r2_summary.json" 2>/dev/null || true
"${COMPOSE[@]}" logs resolver > "$OUT/resolver.log" 2>&1 || true
cp "$ENV_FILE" "$OUT/profile.env"
printf 'profile=%s\nworkload=%s\nrounds=%s\n' "$PROFILE" "$WORKLOAD" "$ROUNDS_ARG" > "$OUT/run.meta"

echo "[+] Finished $PROFILE/$WORKLOAD; artifacts: $OUT"
