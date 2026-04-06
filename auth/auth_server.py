import os
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, SOA, NS

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
ZONE = "example.net."
NAMESERVER = "ns1.example.net."
ZONE_IP = os.getenv("ZONE_IP", "198.51.100.10")
BANK_REAL_IP = os.getenv("BANK_REAL_IP", "203.0.113.80")
DELAY_SECONDS = float(os.getenv("AUTH_DELAY_SECONDS", "0.25"))


def normalize(name: str) -> str:
    value = name.lower().strip()
    if not value.endswith("."):
        value += "."
    return value


def build_base_reply(request: DNSRecord) -> DNSRecord:
    header = DNSHeader(
        id=request.header.id,
        qr=1,
        aa=1,
        ra=0,
        rd=request.header.rd,
        tc=0,
    )
    return DNSRecord(header, q=request.q)


def main() -> None:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(
        f"[auth] authoritative DNS listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"zone={ZONE} | delay={DELAY_SECONDS}s"
    )

    soa = SOA(
        mname=NAMESERVER,
        rname="hostmaster.example.net.",
        times=(2026040601, 3600, 1200, 604800, 300),
    )

    while True:
        data, addr = sock.recvfrom(4096)
        try:
            request = DNSRecord.parse(data)
            qname = normalize(str(request.q.qname))
            qtype_name = QTYPE.get(request.q.qtype)

            # Delay on purpose so attacker can race with spoofed response.
            time.sleep(DELAY_SECONDS)

            reply = build_base_reply(request)

            if qtype_name == "A" and qname.endswith(ZONE):
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=60, rdata=A(ZONE_IP)))
                reply.add_auth(RR(ZONE, QTYPE.NS, rclass=1, ttl=300, rdata=NS(NAMESERVER)))
                reply.add_ar(RR(NAMESERVER, QTYPE.A, rclass=1, ttl=300, rdata=A("10.10.0.100")))
            elif qtype_name == "A" and qname == "bank.com.":
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=120, rdata=A(BANK_REAL_IP)))
            else:
                # Minimal authoritative negative response with SOA.
                reply.header.rcode = 3
                reply.add_auth(RR(ZONE, QTYPE.SOA, rclass=1, ttl=60, rdata=soa))

            sock.sendto(reply.pack(), addr)
        except Exception as exc:
            print(f"[auth] error: {exc}")


if __name__ == "__main__":
    main()
