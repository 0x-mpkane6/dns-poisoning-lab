#!/usr/bin/env python3
"""NFQUEUE policy plane for the E5-v2 routed resolver experiment."""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from netfilterqueue import NetfilterQueue  # type: ignore
from scapy.all import IP, send  # type: ignore

from e5_v2_lib import Policy, policy_decision, raw_shannon_entropy
from ips.packet_logic import PacketMeta, build_tc_response, parse_packet


# Registered and locked for E5-v2.  These are constants rather than
# environment overrides so a runtime invocation cannot silently retune E3's
# operating point.
WINDOW_SECONDS = 2.0
MIN_SAMPLES = 8
ENTROPY_THRESHOLD = 6.0
UNIQUE_RATIO_THRESHOLD = 0.90
QUEUE_NUM = int(os.environ.get("NFQUEUE_NUM", "5"))
AUTH_IP = os.environ.get("AUTH_IP", "10.82.0.100")
RESOLVER_IP = os.environ.get("RESOLVER_IP", "10.81.0.53")
INSIDE_IP = os.environ.get("IPS_INSIDE_IP", "10.81.0.1")
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log"))
WORKLOAD = os.environ.get("WORKLOAD", "unregistered")
TRIAL_RE = re.compile(r"(?:^|\.)r(?P<rep>\d+)-t(?P<trial>\d+)-(?P<nonce>[0-9a-f]+)\.bank\.com\.?$")


class RoutedPolicy:
    def __init__(self) -> None:
        try:
            self.policy = Policy(os.environ.get("POLICY_MODE", Policy.B0_OFF.value))
        except ValueError as exc:
            raise SystemExit(f"unsupported POLICY_MODE: {exc}") from exc
        self.run_id = os.environ.get("RUN_ID", "unregistered")
        self.rep = int(os.environ.get("REP", "0"))
        self.workload = WORKLOAD
        self.events_path = LOG_DIR / "ips_events.jsonl"
        self.state_path = LOG_DIR / "detector_state.json"
        self.ready_path = LOG_DIR / "ips_ready.json"
        self.query_map: dict[tuple[int, int], str] = {}
        self.datagram_map: dict[tuple[str, str, int], str] = {}
        self.datagram_last_seen: dict[tuple[str, str, int], float] = {}
        self.events: deque[tuple[float, int]] = deque()
        self.state_lock = threading.Lock()
        self.ready = False
        self.last_active = False

    def append(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, allow_nan=False) + "\n")

    def event(self, event: str, **fields: object) -> None:
        row = {
            "schema_version": 1,
            "event": event,
            "run_id": self.run_id,
            "rep": self.rep,
            "policy": self.policy.value,
            "workload": self.workload,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            **fields,
        }
        qname = fields.get("qname")
        if isinstance(qname, str):
            match = TRIAL_RE.search(qname.rstrip("."))
            row["trial_id"] = (
                f"r{match.group('rep')}-t{match.group('trial')}-{match.group('nonce')}"
                if match
                else None
            )
        else:
            row["trial_id"] = None
        self.append(self.events_path, row)

    def cleanup(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        with self.state_lock:
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
            old = [key for key, seen in self.datagram_last_seen.items() if seen < cutoff]
            for key in old:
                self.datagram_last_seen.pop(key, None)
                self.datagram_map.pop(key, None)

    def b5_state(self) -> tuple[int, float, float, bool]:
        now = time.monotonic()
        self.cleanup(now)
        with self.state_lock:
            ipids = [ipid for _, ipid in self.events]
        n = len(ipids)
        entropy = raw_shannon_entropy(ipids)
        unique_ratio = len(set(ipids)) / n if n else 0.0
        active = n >= MIN_SAMPLES and entropy >= ENTROPY_THRESHOLD and unique_ratio >= UNIQUE_RATIO_THRESHOLD
        return n, entropy, unique_ratio, active

    def write_state(self, reason: str) -> bool:
        n, entropy, unique_ratio, active = self.b5_state()
        payload = {
            "schema_version": 1,
            "run_id": self.run_id,
            "rep": self.rep,
            "policy": self.policy.value,
            "workload": self.workload,
            "reason": reason,
            "mono_ns": time.monotonic_ns(),
            "wall_ns": time.time_ns(),
            "samples": n,
            "entropy": entropy,
            "unique_ratio": unique_ratio,
            "min_samples": MIN_SAMPLES,
            "entropy_threshold": ENTROPY_THRESHOLD,
            "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
            "b5_active": active,
        }
        self.state_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        self.event("detector_state", reason=reason, samples=n, entropy=entropy, unique_ratio=unique_ratio, b5_active=active)
        if active and not self.last_active:
            self.event("detector_trigger", reason=reason, samples=n, entropy=entropy, unique_ratio=unique_ratio)
        self.last_active = active
        return active

    def observe_noninitial(self, meta: PacketMeta, payload_sha256: str) -> bool:
        with self.state_lock:
            self.events.append((time.monotonic(), meta.ipid))
        self.event(
            "fragment_observed",
            src=meta.src,
            dst=meta.dst,
            ipid=meta.ipid,
            offset=meta.offset,
            more_fragments=meta.more_fragments,
            qname=meta.qname,
            payload_sha256=payload_sha256,
        )
        return self.write_state("noninitial_fragment")

    def inside_iface(self) -> str:
        configured = os.environ.get("INSIDE_IFACE")
        if configured:
            return configured
        output = subprocess.run(["ip", "-o", "-4", "addr", "show"], check=True, capture_output=True, text=True).stdout
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[3].split("/")[0] == INSIDE_IP:
                return fields[1]
        raise RuntimeError(f"could not find interface for {INSIDE_IP}")

    def inject_tc(self, meta: PacketMeta, qname: str | None) -> bool:
        if not qname or meta.txid is None or meta.dst_port is None:
            self.event("tc_injection_failed", reason="missing_dns_metadata", qname=qname, txid=meta.txid, dst_port=meta.dst_port)
            return False
        payload = build_tc_response(
            qname=qname,
            txid=meta.txid,
            resolver_port=meta.dst_port,
            auth_ip=AUTH_IP,
            resolver_ip=RESOLVER_IP,
            ipid=meta.ipid,
        )
        send(IP(payload), iface=self.inside_iface(), verbose=0)
        self.event("tc_injected", qname=qname, txid=meta.txid, resolver_port=meta.dst_port, packet_len=len(payload))
        return True

    def record_query(self, meta: PacketMeta) -> None:
        if meta.txid is None or meta.src_port is None or not meta.qname:
            self.event("query_unmapped", src=meta.src, dst=meta.dst, txid=meta.txid, src_port=meta.src_port)
            return
        self.query_map[(meta.src_port, meta.txid)] = meta.qname
        self.event("resolver_query", qname=meta.qname, txid=meta.txid, resolver_port=meta.src_port, auth_port=meta.dst_port)

    def handle(self, nfq_packet) -> None:  # noqa: ANN001
        raw = nfq_packet.get_payload()
        payload_sha256 = hashlib.sha256(raw).hexdigest()
        try:
            meta = parse_packet(raw, auth_ip=AUTH_IP, resolver_ip=RESOLVER_IP, query_map=self.query_map)
        except Exception as exc:
            self.event("packet_parse_error", error=repr(exc), payload_len=len(raw))
            # Fail closed on an unparseable queued packet.  Accepting here
            # would create an implicit fail-open path outside the registered
            # B0/B1/B5/RFC policy semantics.
            self.event("packet_verdict", verdict="drop", reason="parse_error", payload_sha256=payload_sha256)
            nfq_packet.drop()
            return

        if meta.is_query:
            self.record_query(meta)
            nfq_packet.accept()
            return

        key = (meta.src, meta.dst, meta.ipid)
        qname = meta.qname or self.datagram_map.get(key)
        if meta.is_dns_response:
            self.event(
                "packet_ingress",
                qname=qname,
                src=meta.src,
                dst=meta.dst,
                ipid=meta.ipid,
                offset=meta.offset,
                more_fragments=meta.more_fragments,
                txid=meta.txid,
                dst_port=meta.dst_port,
                payload_sha256=payload_sha256,
            )
            self.datagram_last_seen[key] = time.monotonic()
            if meta.qname:
                self.datagram_map[key] = meta.qname
                qname = meta.qname

        b5_active = self.b5_state()[3]
        if meta.is_noninitial_fragment:
            b5_active = self.observe_noninitial(meta, payload_sha256)

        if meta.is_dns_response and (meta.is_first_fragment or meta.is_noninitial_fragment):
            action = policy_decision(
                self.policy,
                is_dns_fragment=True,
                offset=meta.offset,
                b5_active=b5_active,
            )
            self.event(
                "packet_decision",
                qname=qname,
                src=meta.src,
                dst=meta.dst,
                ipid=meta.ipid,
                offset=meta.offset,
                more_fragments=meta.more_fragments,
                verdict=action.verdict,
                reason=action.reason,
                b5_active=b5_active,
                payload_sha256=payload_sha256,
            )
            if action.verdict == "inject_tc_drop":
                injected = self.inject_tc(meta, qname)
                self.event(
                    "enforcement_action",
                    qname=qname,
                    action="tc_inject_and_drop",
                    injection_ok=injected,
                    offset=meta.offset,
                    payload_sha256=payload_sha256,
                )
                self.event("packet_verdict", qname=qname, verdict="drop", injection_ok=injected, offset=meta.offset, payload_sha256=payload_sha256)
                nfq_packet.drop()
                return
            if action.verdict in {"drop_tail", "drop_fragment"}:
                self.event(
                    "enforcement_action",
                    qname=qname,
                    action=action.verdict,
                    injection_ok=False,
                    offset=meta.offset,
                    payload_sha256=payload_sha256,
                )
                self.event("packet_verdict", qname=qname, verdict="drop", injection_ok=False, offset=meta.offset, payload_sha256=payload_sha256)
                nfq_packet.drop()
                return

        if meta.is_dns_response or meta.is_noninitial_fragment:
            self.event("packet_verdict", qname=qname, src=meta.src, dst=meta.dst, ipid=meta.ipid, offset=meta.offset, verdict="forward", payload_sha256=payload_sha256)
        nfq_packet.accept()

    def run(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.events_path.write_text("", encoding="utf-8")
        self.state_path.write_text("", encoding="utf-8")
        self.event("ips_start", auth_ip=AUTH_IP, resolver_ip=RESOLVER_IP, inside_ip=INSIDE_IP, queue_num=QUEUE_NUM)
        self.write_state("startup")
        queue = NetfilterQueue()
        queue.bind(QUEUE_NUM, self.handle)
        self.ready = True
        self.ready_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": self.run_id,
                    "rep": self.rep,
                    "policy": self.policy.value,
                    "workload": self.workload,
                    "queue_num": QUEUE_NUM,
                    "window_seconds": WINDOW_SECONDS,
                    "min_samples": MIN_SAMPLES,
                    "entropy_threshold": ENTROPY_THRESHOLD,
                    "unique_ratio_threshold": UNIQUE_RATIO_THRESHOLD,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.event("ips_ready", queue_num=QUEUE_NUM)

        def tick_loop() -> None:
            while self.ready:
                time.sleep(0.25)
                try:
                    self.write_state("tick")
                except Exception as exc:  # pragma: no cover
                    self.event("tick_error", error=repr(exc))

        threading.Thread(target=tick_loop, daemon=True).start()
        try:
            queue.run()
        finally:
            self.ready = False
            queue.unbind()
            self.event("ips_stop")


if __name__ == "__main__":
    RoutedPolicy().run()
