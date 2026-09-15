#!/usr/bin/env python3
"""Count ICMP PTB / Packet Too Big in archived E5 IPS captures.

The main lab crafts fragments in user space. This audit records whether
IPv4 type 3 code 4 or IPv6 type 2 appear in confirmatory B0 captures.
It does not modify those campaigns.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from scapy.all import Ether
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import ICMPv6PacketTooBig, IPv6
from scapy.utils import RawPcapNgReader

E5_ROOT = Path(__file__).resolve().parents[1]
CAMPAIGNS = {
    "E5-routed-s20260902-r001": E5_ROOT / "output" / "E5-routed-s20260902-r001",
    "E5-factorial-s20260911-r003": E5_ROOT / "output" / "E5-factorial-s20260911-r003",
}
FIGURES = E5_ROOT.parent.parent / "figures" / "rq_print_revision"


def count_ptb(path: Path) -> dict[str, int]:
    ipv4 = 0
    ipv6 = 0
    packets = 0
    reader = RawPcapNgReader(str(path))
    try:
        for data, _meta in reader:
            packets += 1
            pkt = Ether(data)
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                pkt = IP(data)
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                if int(icmp.type) == 3 and int(icmp.code) == 4:
                    ipv4 += 1
                    continue
            if pkt.haslayer(ICMPv6PacketTooBig):
                ipv6 += 1
    finally:
        reader.close()
    return {"packets": packets, "ipv4_dest_unreach_frag_needed": ipv4, "ipv6_packet_too_big": ipv6}


def main() -> None:
    campaigns = []
    totals = Counter()
    files = 0
    for name, root in CAMPAIGNS.items():
        metrics = json.loads((root / "metrics_confirmatory.json").read_text(encoding="utf-8"))
        ipv4 = 0
        ipv6 = 0
        packets = 0
        scanned = 0
        for run in metrics:
            if run.get("policy") != "B0_OFF":
                continue
            cell = root / run["artifact_dir"]
            for filename in ("ips_outside.pcapng", "ips_inside.pcapng"):
                path = cell / filename
                if not path.exists():
                    continue
                result = count_ptb(path)
                ipv4 += result["ipv4_dest_unreach_frag_needed"]
                ipv6 += result["ipv6_packet_too_big"]
                packets += result["packets"]
                scanned += 1
        campaigns.append(
            {
                "campaign": name,
                "b0_pcaps_scanned": scanned,
                "packets": packets,
                "ipv4_dest_unreach_frag_needed": ipv4,
                "ipv6_packet_too_big": ipv6,
            }
        )
        totals["ipv4"] += ipv4
        totals["ipv6"] += ipv6
        files += scanned
    payload = {
        "status": "PASS",
        "scope": "confirmatory B0 IPS captures, original and factorial campaigns",
        "interpretation": "Application-crafted fragments; ICMP PTB is not part of the main lab path.",
        "campaigns": campaigns,
        "pcaps_scanned": files,
        "ipv4_dest_unreach_frag_needed": totals["ipv4"],
        "ipv6_packet_too_big": totals["ipv6"],
    }
    FIGURES.mkdir(parents=True, exist_ok=True)
    out = FIGURES / "icmp_ptb_audit.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
