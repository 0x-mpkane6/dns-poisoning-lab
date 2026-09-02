from __future__ import annotations

import sys
from pathlib import Path

from dnslib import DNSRecord
from scapy.all import IP, Raw, fragment  # type: ignore

E5_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E5_ROOT / "tools" / "routed_lab"))

from wire import build_dns_answer, fragment_udp_payload, udp_payload  # noqa: E402


def test_fragmented_authoritative_answer_has_matching_udp_and_ip_metadata() -> None:
    qname = "r01-t000-abcdef01.bank.com."
    query = DNSRecord.question(qname, "A")
    body = build_dns_answer(query, "203.0.113.80")
    packets = fragment_udp_payload(
        src="10.82.0.100",
        dst="10.81.0.53",
        ipid=777,
        dst_port=33333,
        body=body,
        fragsize=40,
    )
    assert len(packets) >= 2
    first = IP(bytes(packets[0]))
    tail = IP(bytes(packets[1]))
    assert first.id == 777
    assert first.frag == 0
    assert first.flags.MF
    assert tail.frag > 0
    assert first.proto == 17
    assert bytes(first.payload)[:2] == (53).to_bytes(2, "big")
    assert bytes(first.payload)[2:4] == (33333).to_bytes(2, "big")
    assert str(DNSRecord.parse(body).rr[0].rdata) == "203.0.113.80"


def test_udp_payload_uses_zero_checksum_for_replayed_fragments() -> None:
    raw = udp_payload(40000, b"payload")
    assert raw[:8] == (53).to_bytes(2, "big") + (40000).to_bytes(2, "big") + (15).to_bytes(2, "big") + b"\x00\x00"
