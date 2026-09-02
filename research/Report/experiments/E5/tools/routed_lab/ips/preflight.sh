#!/usr/bin/env bash
set -euo pipefail

# This is deliberately a hard gate.  E5-v2 has no non-NFQUEUE fallback.
if ! command -v iptables >/dev/null 2>&1; then
    echo "NFQUEUE preflight failed: iptables is unavailable" >&2
    exit 20
fi
if ! iptables -m NFQUEUE -h >/dev/null 2>&1; then
    echo "NFQUEUE preflight failed: the NFQUEUE target is unavailable" >&2
    exit 21
fi
if command -v modprobe >/dev/null 2>&1; then
    modprobe nfnetlink_queue 2>/dev/null || true
fi

if ! iptables -t filter -N E5V2_NFQ_PREFLIGHT 2>/dev/null; then
    iptables -t filter -F E5V2_NFQ_PREFLIGHT
fi
trap 'iptables -t filter -F E5V2_NFQ_PREFLIGHT; iptables -t filter -X E5V2_NFQ_PREFLIGHT' EXIT
iptables -t filter -A E5V2_NFQ_PREFLIGHT -j NFQUEUE --queue-num "${NFQUEUE_NUM:-5}"
iptables -t filter -C E5V2_NFQ_PREFLIGHT -j NFQUEUE --queue-num "${NFQUEUE_NUM:-5}"

test -r /proc/net/netfilter/nfnetlink_queue || {
    echo "NFQUEUE preflight failed: kernel queue interface is unavailable" >&2
    exit 22
}

ip route get "${RESOLVER_IP:-10.81.0.53}" >/app/log/preflight_route_resolver.txt
ip route get "${AUTH_IP:-10.82.0.100}" >/app/log/preflight_route_auth.txt
printf '{"schema_version":1,"nfqueue_target":true,"kernel_queue":true}\n' > /app/log/nfqueue_preflight.json
