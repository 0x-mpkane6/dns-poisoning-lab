#!/usr/bin/env python3
"""Instrument the unchanged B5 rule and its existing iptables enforcement path."""
from __future__ import annotations

import json
import math
import os
import subprocess
import threading
import time
from collections import Counter, deque

from scapy.all import IP, sniff

WINDOW = float(os.getenv("FRAG2_WINDOW_SECONDS", "2.0"))
MIN_SAMPLES = int(os.getenv("R2_MIN_SAMPLES", "8"))
H_TH = float(os.getenv("R2_ENTROPY_THRESHOLD", "6.0"))
U_TH = float(os.getenv("R2_UNIQUE_RATIO_THRESHOLD", "0.90"))
DEFENSE_FILE = "/app/defense_mode"
EVENTS = "/app/frag2_events.jsonl"
DECISIONS = "/app/r2_entropy_decisions.jsonl"
OCCUPANCY = "/app/r2_occupancy.json"
ENFORCEMENT = "/app/enforcement.jsonl"
RULE = ["iptables", "-w", "2", "-t", "raw", "-A", "PREROUTING", "-p", "udp", "-f", "-j", "DROP"]
RULE_DEL = ["-D" if item == "-A" else item for item in RULE]
RULE_CHECK = ["-C" if item == "-A" else item for item in RULE]
_lock = threading.Lock()
_score_lock = threading.Lock()
_events = deque()
_blocking = False
_last_enforcement = {"ok": True, "requested": False, "installed": False, "returncode": 0}
_sequence = 0


def defense_on() -> bool:
    try:
        with open(DEFENSE_FILE, encoding="utf-8") as handle:
            return handle.read().strip().lower() == "on"
    except FileNotFoundError:
        return False


def entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    n = len(values)
    return -sum((count / n) * math.log2(count / n) for count in Counter(values).values())


def snapshot() -> tuple[float, list[int]]:
    with _lock:
        now = time.monotonic()
        while _events and _events[0][0] < now - WINDOW:
            _events.popleft()
        return now, [ipid for _, ipid in _events]


def occupancy_now() -> tuple[int, float, float, list[int]]:
    _, ipids = snapshot()
    n = len(ipids)
    return n, entropy(ipids), len(set(ipids)) / n if n else 0.0, ipids


def append(path: str, row: dict) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def set_drop(enabled: bool) -> bool:
    global _blocking, _last_enforcement
    if enabled == _blocking:
        return True
    command = RULE if enabled else RULE_DEL
    record = {"mono_s": time.monotonic(), "ts": time.time(), "requested": enabled, "command": command}
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
        verify = subprocess.run(RULE_CHECK, check=False, capture_output=True, text=True, timeout=5)
        installed = verify.returncode == 0
        ok = proc.returncode == 0 and installed == enabled and verify.returncode in (0, 1)
        record.update(returncode=proc.returncode, stderr=proc.stderr, check_returncode=verify.returncode,
                      check_stderr=verify.stderr, installed=installed, ok=ok)
        if ok:
            _blocking = enabled
    except (OSError, subprocess.TimeoutExpired) as exc:
        record.update(returncode=None, stderr=str(exc), installed=_blocking, ok=False)
    _last_enforcement = record
    append(ENFORCEMENT, record)
    return bool(record["ok"])


def score(reason: str) -> None:
    global _sequence
    with _score_lock:
        mono_s, ipids = snapshot()
        n = len(ipids)
        unique = len(set(ipids))
        h = entropy(ipids)
        u = unique / n if n else 0.0
        gates = {"samples": n >= MIN_SAMPLES, "entropy": h >= H_TH, "unique_ratio": u >= U_TH}
        enabled = defense_on()
        requested = enabled and all(gates.values())
        enforcement_ok = set_drop(requested)
        _sequence += 1
        decision = {
            "ts": time.time(), "mono_s": mono_s, "decision_seq": _sequence, "reason": reason,
            "samples": n, "unique_ipids": unique, "unique_ratio": u, "entropy": h,
            "window_seconds": WINDOW, "min_samples": MIN_SAMPLES,
            "entropy_threshold": H_TH, "unique_ratio_threshold": U_TH,
            "defense_on": enabled, "gate_pass": gates,
            "failed_gates": [name for name, passed in gates.items() if not passed],
            "action": "tc_block" if requested else "allow",
            "drop_requested": requested, "rule_installed": _blocking,
            "enforcement_ok": enforcement_ok,
        }
        append(DECISIONS, decision)
        temporary = OCCUPANCY + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"occupancy": n, "mono_s": mono_s, "entropy": h, "unique_ratio": u,
                       "blocking": _blocking, "enforcement_ok": enforcement_ok}, handle, allow_nan=False)
        os.replace(temporary, OCCUPANCY)


def on_packet(pkt) -> None:
    if IP not in pkt or int(pkt[IP].frag) <= 0:
        return
    ip = pkt[IP]
    with _lock:
        mono_s = time.monotonic()
        event = {"ts": time.time(), "mono_s": mono_s, "src_ip": ip.src, "dst_ip": ip.dst,
                 "ipid": int(ip.id), "offset": int(ip.frag) * 8, "mf": bool(int(ip.flags) & 1)}
        _events.append((mono_s, event["ipid"]))
        append(EVENTS, event)
    score("frag2")


def scorer_loop() -> None:
    while True:
        time.sleep(0.25)
        score("tick")


def main() -> None:
    for path in (EVENTS, DECISIONS, ENFORCEMENT):
        with open(path, "w", encoding="utf-8"):
            pass
    threading.Thread(target=scorer_loop, daemon=True).start()
    print("[e5-supplement] monotonic B5; rule requests and installation are separate", flush=True)
    sniff(iface="eth0", filter="ip", store=False, prn=on_packet)


if __name__ == "__main__":
    main()
