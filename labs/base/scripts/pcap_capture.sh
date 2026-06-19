#!/bin/bash
# Capture DNS-port traffic on the resolver for evidence.
# Usage: bash pcap_capture.sh [seconds] [output_pcap_path]
#   - Defaults to 10 seconds and ./capture-<lab>-<timestamp>.pcap.
#   - Requires tcpdump inside the resolver container (the resolver Dockerfile
#     installs it). Output is copied back to the host.

set -euo pipefail

SECONDS_LIMIT="${1:-10}"
LAB_NAME="$(basename "$(pwd)")"
DEFAULT_OUT="./capture-${LAB_NAME}-$(date +%Y%m%d-%H%M%S).pcap"
OUTPUT_FILE="${2:-$DEFAULT_OUT}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[!] docker command not found." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker daemon is not reachable." >&2
    exit 1
fi

RESOLVER_CID="$(docker compose ps -q resolver 2>/dev/null || true)"
if [ -z "$RESOLVER_CID" ]; then
    echo "[!] resolver container is not running. docker compose up -d first." >&2
    exit 1
fi

REMOTE_PATH="/tmp/resolver-$(date +%s).pcap"
echo "[+] tcpdump on resolver for ${SECONDS_LIMIT}s -> ${REMOTE_PATH}"

docker exec "$RESOLVER_CID" sh -lc \
    "command -v tcpdump >/dev/null 2>&1 || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y tcpdump >/dev/null 2>&1)"

docker exec "$RESOLVER_CID" sh -lc \
    "timeout ${SECONDS_LIMIT} tcpdump -i any -n -w '$REMOTE_PATH' 'port 53' >/dev/null 2>&1 || true"

docker cp "${RESOLVER_CID}:${REMOTE_PATH}" "$OUTPUT_FILE"
docker exec "$RESOLVER_CID" sh -lc "rm -f '$REMOTE_PATH'" >/dev/null 2>&1 || true

if [ ! -s "$OUTPUT_FILE" ]; then
    echo "[!] pcap empty - is there any traffic during the capture window?" >&2
    exit 2
fi

echo "[+] Saved pcap to ${OUTPUT_FILE}"
echo "[+] Open with Wireshark or summarize with: tcpdump -nn -r ${OUTPUT_FILE} -c 20"
