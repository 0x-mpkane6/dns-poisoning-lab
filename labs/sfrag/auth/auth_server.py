import os
import random
import socket
import time

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, SOA, TXT

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

ZONE = "example.net."
ZONE_IP = os.getenv("ZONE_IP", "198.51.100.10")
BANK_REAL_IP = os.getenv("BANK_REAL_IP", "203.0.113.80")
DELAY_SECONDS = float(os.getenv("AUTH_DELAY_SECONDS", "0.25"))

FRAG_MODE = os.getenv("FRAG_MODE", "sfrag").strip().lower()
IPID_SPACE = int(os.getenv("IPID_SPACE", "65535"))
BULLSEYE_IPID = int(os.getenv("BULLSEYE_IPID", "777"))
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")
FRAG_TRIGGER_PREFIX = os.getenv("FRAG_TRIGGER_PREFIX", "frag").strip().lower()


def normalize(name: str) -> str:
    value = name.lower().strip()
    if not value.endswith("."):
        value += "."
    return value


def pick_ipid() -> int:
    if FRAG_MODE == "bfrag":
        return BULLSEYE_IPID
    return random.randint(0, max(1, IPID_SPACE - 1))


def should_attach_frag_marker(qname: str) -> bool:
    zone = normalize(ZONE)
    if not qname.endswith(zone):
        return False

    relative = qname[: -len(zone)].strip(".")
    if not relative:
        return False

    first_label = relative.split(".")[0]
    return first_label.startswith(FRAG_TRIGGER_PREFIX)


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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(
        f"[auth] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"mode={FRAG_MODE} | delay={DELAY_SECONDS}s"
    )

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

            if qtype_name == "A" and qname.endswith(ZONE):
                ipid = pick_ipid()
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=60, rdata=A(ZONE_IP)))
                if should_attach_frag_marker(qname):
                    reply.add_ar(
                        RR(
                            FRAGMETA_QNAME,
                            QTYPE.TXT,
                            rclass=1,
                            ttl=1,
                            rdata=TXT(f"TYPE=FRAG1;IPID={ipid}"),
                        )
                    )
            elif qtype_name == "A" and qname == "bank.com.":
                reply.add_answer(RR(qname, QTYPE.A, rclass=1, ttl=120, rdata=A(BANK_REAL_IP)))
            else:
                reply.header.rcode = 3
                reply.add_auth(RR(ZONE, QTYPE.SOA, rclass=1, ttl=60, rdata=soa))

            sock.sendto(reply.pack(), addr)
        except Exception as exc:
            print(f"[auth] error: {exc}")


if __name__ == "__main__":
    main()
