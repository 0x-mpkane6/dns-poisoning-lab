#!/usr/bin/env python3
"""Unique-qname resolver probe with cache-before/cache-after evidence."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
CACHE_PROBE_PORT = int(os.environ.get("CACHE_PROBE_PORT", "10053"))
QUERY_DEADLINE_S = float(os.environ.get("CLIENT_QUERY_DEADLINE_S", "2.0"))
SCHEDULE_PATH = Path(os.environ.get("SCHEDULE_FILE", "/app/schedule.json"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
POISON_IP = os.environ.get("POISON_IP", "6.6.6.6")
LEGITIMATE_IP = os.environ.get("LEGITIMATE_IP", "203.0.113.80")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def envelope(event: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event": event,
        "run_id": RUN_ID,
        "rep": REP,
        "policy": POLICY,
        "workload": WORKLOAD,
        "mono_ns": time.monotonic_ns(),
        "wall_ns": time.time_ns(),
        **fields,
    }


def cache_probe(phase: str, trial_id: str, qname: str) -> dict[str, Any]:
    request = json.dumps({"phase": phase, "trial_id": trial_id, "qname": qname}).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    started = time.monotonic_ns()
    try:
        sock.sendto(request, (RESOLVER_IP, CACHE_PROBE_PORT))
        raw, source = sock.recvfrom(16384)
        reply = json.loads(raw.decode("utf-8"))
        reply.update({"probe_send_mono_ns": started, "probe_reply_mono_ns": time.monotonic_ns(), "probe_source": source[0]})
        return reply
    except Exception as exc:
        return {
            "ok": False,
            "cache_hit": False,
            "answers": [],
            "error": repr(exc),
            "probe_send_mono_ns": started,
            "probe_reply_mono_ns": time.monotonic_ns(),
        }
    finally:
        sock.close()


def run_dig(qname: str) -> tuple[dict[str, Any], str]:
    started = time.monotonic_ns()
    try:
        proc = subprocess.run(
            [
                "dig",
                f"@{RESOLVER_IP}",
                qname,
                "+tries=1",
                "+time=2",
                "+noall",
                "+answer",
                "+comments",
            ],
            capture_output=True,
            text=True,
            timeout=max(QUERY_DEADLINE_S + 2.0, 4.0),
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        answers = []
        for line in proc.stdout.splitlines():
            fields = line.strip().split()
            if fields and IPV4.match(fields[-1]):
                answers.append(fields[-1])
        tc_seen = bool(re.search(r"(?:flags:.*\btc\b|truncated, retrying in TCP mode)", output, re.IGNORECASE | re.DOTALL))
        if POISON_IP in answers:
            status = "poisoned_answer"
        elif LEGITIMATE_IP in answers:
            status = "legitimate_answer"
        elif answers:
            status = "other_answer"
        elif proc.returncode != 0:
            status = "timeout_or_command_error"
        else:
            status = "no_answer"
        return (
            {
                "status": status,
                "returncode": proc.returncode,
                "answers": answers,
                "answer_ip": answers[0] if answers else None,
                "tc_seen": tc_seen,
                "query_start_mono_ns": started,
                "query_end_mono_ns": time.monotonic_ns(),
                "latency_ms": (time.monotonic_ns() - started) / 1_000_000.0,
                "stdout_b64": base64.b64encode(proc.stdout.encode("utf-8")).decode("ascii"),
                "stderr_b64": base64.b64encode(proc.stderr.encode("utf-8")).decode("ascii"),
            },
            output,
        )
    except Exception as exc:
        ended = time.monotonic_ns()
        return (
            {
                "status": "timeout_or_command_error",
                "returncode": None,
                "answers": [],
                "answer_ip": None,
                "tc_seen": False,
                "query_start_mono_ns": started,
                "query_end_mono_ns": ended,
                "latency_ms": (ended - started) / 1_000_000.0,
                "error": repr(exc),
                "stdout_b64": "",
                "stderr_b64": "",
            },
            repr(exc),
        )


def main() -> int:
    schedule = json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))
    trials = schedule.get("trials", [])
    if len({row["qname"] for row in trials}) != len(trials):
        raise RuntimeError("schedule contains duplicate qnames")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    trials_path = LOG_DIR / "trials.jsonl"
    client_events_path = LOG_DIR / "client_events.jsonl"
    trials_path.write_text("", encoding="utf-8")
    client_events_path.write_text("", encoding="utf-8")
    append(client_events_path, envelope("client_ready", trial_count=len(trials), deadline_s=QUERY_DEADLINE_S))

    for row in trials:
        trial_id = str(row["trial_id"])
        qname = str(row["qname"])
        before = cache_probe("before", trial_id, qname)
        append(client_events_path, envelope("cache_before_reply", trial_id=trial_id, qname=qname, **before))
        query_start = time.monotonic_ns()
        append(client_events_path, envelope("client_query_send", trial_id=trial_id, qname=qname))
        result, raw_output = run_dig(qname)
        append(
            client_events_path,
            envelope("client_answer_receive", trial_id=trial_id, qname=qname, status=result["status"], answer_ip=result["answer_ip"], tc_seen=result["tc_seen"]),
        )
        after = cache_probe("after", trial_id, qname)
        append(client_events_path, envelope("cache_after_reply", trial_id=trial_id, qname=qname, **after))
        end_ns = time.monotonic_ns()
        record = envelope(
            "trial",
            trial_id=trial_id,
            qname=qname,
            trial=int(row["trial"]),
            client_query_start_mono_ns=query_start,
            client_answer_end_mono_ns=end_ns,
            client_latency_ms=(end_ns - query_start) / 1_000_000.0,
            cache_before=before,
            cache_after=after,
            **result,
            raw_output_b64=base64.b64encode(raw_output.encode("utf-8")).decode("ascii"),
        )
        append(trials_path, record)
        print(f"{trial_id} {result['status']} {result['answer_ip'] or '-'} {result['latency_ms']:.3f}ms", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
