#!/usr/bin/env python3
"""Read-only cache probe service used for per-trial cache evidence."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path


LISTEN_IP = os.environ.get("CACHE_PROBE_IP", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CACHE_PROBE_PORT", "10053"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def cache_lookup(qname: str) -> dict:
    started = time.monotonic_ns()
    try:
        proc = subprocess.run(
            [
                "dig",
                "@127.0.0.1",
                "-p",
                "53",
                qname,
                "+norecurse",
                "+tries=1",
                "+time=1",
                "+noall",
                "+answer",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        answers = []
        for line in proc.stdout.splitlines():
            fields = line.strip().split()
            if fields and IPV4.match(fields[-1]):
                answers.append(fields[-1])
        return {
            "cache_hit": bool(answers),
            "answers": answers,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-1000:],
            "probe_duration_ns": time.monotonic_ns() - started,
        }
    except Exception as exc:
        return {
            "cache_hit": False,
            "answers": [],
            "returncode": None,
            "stdout": "",
            "stderr": repr(exc),
            "probe_duration_ns": time.monotonic_ns() - started,
            "probe_error": True,
        }


def append(row: dict) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / "cache_events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "cache_events.jsonl").write_text("", encoding="utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    append(
        {
            "schema_version": 1,
            "event": "cache_probe_ready",
            "run_id": RUN_ID,
            "rep": REP,
            "policy": POLICY,
            "workload": WORKLOAD,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "listen_port": LISTEN_PORT,
        }
    )
    while True:
        payload, source = sock.recvfrom(8192)
        received_ns = time.monotonic_ns()
        try:
            request = json.loads(payload.decode("utf-8"))
            phase = str(request["phase"])
            if phase not in {"before", "after"}:
                raise ValueError(f"unsupported cache probe phase: {phase}")
            qname = str(request["qname"])
            result = cache_lookup(qname)
            row = {
                "schema_version": 1,
                "event": f"cache_{phase}",
                "run_id": RUN_ID,
                "rep": REP,
                "policy": POLICY,
                "workload": WORKLOAD,
                "mono_ns": received_ns,
                "wall_ns": time.time_ns(),
                "trial_id": request.get("trial_id"),
                "qname": qname,
                "source_ip": source[0],
                "source_port": source[1],
                **result,
            }
            append(row)
            ack = {"ok": True, **result}
        except Exception as exc:
            ack = {"ok": False, "error": repr(exc)}
        sock.sendto(json.dumps(ack, sort_keys=True).encode("utf-8"), source)


if __name__ == "__main__":
    main()
