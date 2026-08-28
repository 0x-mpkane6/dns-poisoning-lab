#!/usr/bin/env python3
"""B5 sidecar: observe real IPv4 fragments and drop offset>0 when locked B5 fires."""
from __future__ import annotations

import json
import math
import os
import subprocess
import threading
import time
from collections import Counter, deque
from typing import Deque, Dict, List, Tuple

from scapy.all import IP, sniff  # type: ignore

WINDOW = float(os.getenv("FRAG2_WINDOW_SECONDS", "2.0"))
MIN_SAMPLES = int(os.getenv("R2_MIN_SAMPLES", "8"))
H_TH = float(os.getenv("R2_ENTROPY_THRESHOLD", "6.0"))
U_TH = float(os.getenv("R2_UNIQUE_RATIO_THRESHOLD", "0.90"))
DEFENSE_FILE = "/app/defense_mode"
EVENTS = "/app/frag2_events.jsonl"
DECISIONS = "/app/r2_entropy_decisions.jsonl"
OCCUPANCY = "/app/r2_occupancy.json"
RULE = ["iptables", "-t", "raw", "-A", "PREROUTING", "-p", "udp", "-f", "-j", "DROP"]
RULE_DEL = ["iptables", "-t", "raw", "-D", "PREROUTING", "-p", "udp", "-f", "-j", "DROP"]

_lock = threading.Lock()
_events: Deque[Tuple[float, int]] = deque()
_blocking = False


def defense_on() -> bool:
    try:
        return open(DEFENSE_FILE, encoding="utf-8").read().strip().lower() == "on"
    except FileNotFoundError:
        return False


def entropy(values: List[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def occupancy_now() -> tuple[int, float, float, List[int]]:
    now = time.time()
    cutoff = now - WINDOW
    with _lock:
        while _events and _events[0][0] < cutoff:
            _events.popleft()
        ipids = [ipid for _, ipid in _events]
    n = len(ipids)
    uniq = len(set(ipids))
    h = entropy(ipids)
    u = (uniq / n) if n else 0.0
    return n, h, u, ipids


def set_drop(enabled: bool) -> None:
    global _blocking
    if enabled == _blocking:
        return
    if enabled:
        subprocess.run(RULE, check=False, capture_output=True)
    else:
        subprocess.run(RULE_DEL, check=False, capture_output=True)
    _blocking = enabled


def append(path: str, row: dict) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def score(reason: str) -> None:
    n, h, u, _ = occupancy_now()
    gates = {"samples": n >= MIN_SAMPLES, "entropy": h >= H_TH, "unique_ratio": u >= U_TH}
    block = defense_on() and all(gates.values())
    set_drop(block)
    decision = {
        "ts": time.time(),
        "reason": reason,
        "samples": n,
        "unique_ipids": len(set(_events_ipids())),
        "unique_ratio": round(u, 4),
        "entropy": round(h, 4),
        "min_samples": MIN_SAMPLES,
        "entropy_threshold": H_TH,
        "unique_ratio_threshold": U_TH,
        "defense_on": defense_on(),
        "gate_pass": gates,
        "failed_gates": [name for name, ok in gates.items() if not ok],
        "action": "tc_block" if block else "allow",
    }
    append(DECISIONS, decision)
    with open(OCCUPANCY, "w", encoding="utf-8") as handle:
        json.dump({"occupancy": n, "entropy": round(h, 4), "unique_ratio": round(u, 4), "blocking": block}, handle)
        handle.write("\n")


def _events_ipids() -> List[int]:
    with _lock:
        return [ipid for _, ipid in _events]


def on_packet(pkt) -> None:
    if IP not in pkt:
        return
    ip = pkt[IP]
    offset = int(ip.frag)
    mf = bool(ip.flags.MF) if hasattr(ip.flags, "MF") else bool(int(ip.flags) & 0x1)
    if offset <= 0 and not mf:
        return
    # Count second-and-later fragments (offset > 0), matching Rℓ2.
    if offset <= 0:
        return
    event = {"ts": time.time(), "src_ip": ip.src, "dst_ip": ip.dst, "ipid": int(ip.id), "offset": offset * 8, "mf": mf}
    with _lock:
        _events.append((event["ts"], event["ipid"]))
    append(EVENTS, event)
    score("frag2")


def scorer_loop() -> None:
    while True:
        time.sleep(0.25)
        score("tick")


def main() -> None:
    for path in (EVENTS, DECISIONS, OCCUPANCY):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    open(DEFENSE_FILE, "a", encoding="utf-8").close()
    threading.Thread(target=scorer_loop, daemon=True).start()
    print("[b5] sniffing IPv4 fragments on eth0", flush=True)
    sniff(iface="eth0", filter="ip", store=False, prn=on_packet)


if __name__ == "__main__":
    main()
