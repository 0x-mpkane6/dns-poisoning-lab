import os
import socket
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, SOA

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

EXAMPLE_ZONE = "example.net."
BANK_ZONE = "bank.com."
EXAMPLE_IP = os.getenv("EXAMPLE_IP", "198.51.100.10")
BANK_REAL_IP = os.getenv("BANK_REAL_IP", "203.0.113.80")
DELAY_SECONDS = float(os.getenv("AUTH_DELAY_SECONDS", "0.25"))


def normalize(name: str) -> str:
    value = name.lower().strip()
    if not value.endswith("."):
        value += "."
    return value


def build_base_reply(request: DNSRecord) -> DNSRecord:
    header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=0, rd=request.header.rd)
    return DNSRecord(header, q=request.q)


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[auth] listening on {LISTEN_IP}:{LISTEN_PORT} | delay={DELAY_SECONDS}s")

    soa = SOA(
        mname="ns1.example.net.",
        rname="hostmaster.example.net.",
        times=(2026041001, 3600, 1200, 604800, 300),
    )

    while True:
        payload, addr = sock.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
            qname = normalize(str(request.q.qname))
            qtype_name = QTYPE.get(request.q.qtype)

            time.sleep(DELAY_SECONDS)
            reply = build_base_reply(request)

            if qtype_name == "A" and qname.endswith(EXAMPLE_ZONE):
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=60, rdata=A(EXAMPLE_IP)))
            elif qtype_name == "A" and qname.endswith(BANK_ZONE):
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=120, rdata=A(BANK_REAL_IP)))
            else:
                reply.header.rcode = 3
                reply.add_auth(RR(EXAMPLE_ZONE, QTYPE.SOA, rclass=1, ttl=60, rdata=soa))

            sock.sendto(reply.pack(), addr)
        except Exception as exc:
            print(f"[auth] error: {exc}")


if __name__ == "__main__":
    main()
