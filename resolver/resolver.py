import os
import random
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR, RCODE

LISTEN_IP = os.getenv("RESOLVER_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RESOLVER_LISTEN_PORT", "53"))
UPSTREAM_IP = os.getenv("UPSTREAM_DNS_IP", "10.10.0.100")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_DNS_PORT", "53"))
CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "1.2"))
UPSTREAM_FIXED_SRC_PORT = int(os.getenv("UPSTREAM_FIXED_SRC_PORT", "33333"))
TXID_SPACE = int(os.getenv("TXID_SPACE", "1024"))

DEFENSE_FILE = "/app/defense_mode"
DEFENSE_ON_VALUE = "on"


class DNSCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, Tuple[str, float]] = {}

    def get(self, qname: str) -> Optional[str]:
        with self._lock:
            value = self._data.get(qname)
            if not value:
                return None
            ip, expires_at = value
            if time.time() >= expires_at:
                del self._data[qname]
                return None
            return ip

    def set(self, name: str, ip: str, ttl: int) -> None:
        expires_at = time.time() + max(1, ttl)
        with self._lock:
            self._data[name] = (ip, expires_at)


def normalize_name(name: str) -> str:
    value = name.lower().strip()
    if value.endswith("."):
        value = value[:-1]
    return value


def zone_from_qname(qname: str) -> str:
    labels = normalize_name(qname).split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return normalize_name(qname)


def is_within_bailiwick(rrname: str, qname: str) -> bool:
    rr = normalize_name(rrname)
    zone = zone_from_qname(qname)
    return rr == zone or rr.endswith("." + zone)


def defense_enabled() -> bool:
    try:
        with open(DEFENSE_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip().lower() == DEFENSE_ON_VALUE
    except FileNotFoundError:
        return False


def build_response(
    request: DNSRecord,
    answer_ip: Optional[str],
    tc_flag: bool = False,
    rcode: int = RCODE.NOERROR,
) -> DNSRecord:
    header = DNSHeader(
        id=request.header.id,
        qr=1,
        aa=0,
        ra=1,
        rd=request.header.rd,
        tc=1 if tc_flag else 0,
        rcode=rcode,
    )
    response = DNSRecord(header, q=request.q)
    if answer_ip:
        response.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=CACHE_DEFAULT_TTL,
                rdata=A(answer_ip),
            )
        )
    return response


def extract_a_records(response: DNSRecord) -> List[Tuple[str, str, int]]:
    records: List[Tuple[str, str, int]] = []
    for section in (response.rr, response.auth, response.ar):
        for rr in section:
            if QTYPE.get(rr.rtype) != "A":
                continue
            name = normalize_name(str(rr.rname))
            ip = str(rr.rdata)
            records.append((name, ip, int(rr.ttl)))
    return records


def query_upstream(qname: str, qtype: str = "A") -> Optional[DNSRecord]:
    request = DNSRecord.question(qname, qtype)
    # Intentionally weak entropy so poisoning can be reproduced in a small lab.
    request.header.id = random.randint(0, max(1, TXID_SPACE - 1))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("10.10.0.53", UPSTREAM_FIXED_SRC_PORT))
        sock.settimeout(UPSTREAM_TIMEOUT)
        sock.sendto(request.pack(), (UPSTREAM_IP, UPSTREAM_PORT))

        while True:
            data, _ = sock.recvfrom(4096)
            response = DNSRecord.parse(data)
            if response.header.id == request.header.id:
                return response


def main() -> None:
    if not os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write("off\n")

    cache = DNSCache()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, LISTEN_PORT))

    print(
        f"[resolver] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"upstream={UPSTREAM_IP}:{UPSTREAM_PORT}"
    )

    while True:
        payload, client_addr = server.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
            if request.q.qtype != QTYPE.A:
                response = build_response(request, None, rcode=RCODE.NXDOMAIN)
                server.sendto(response.pack(), client_addr)
                continue

            qname = normalize_name(str(request.q.qname))

            cached_ip = cache.get(qname)
            if cached_ip:
                response = build_response(request, cached_ip)
                server.sendto(response.pack(), client_addr)
                continue

            upstream_response = query_upstream(qname, "A")
            if not upstream_response:
                response = build_response(request, None, rcode=RCODE.SERVFAIL)
                server.sendto(response.pack(), client_addr)
                continue

            defense_on = defense_enabled()
            records = extract_a_records(upstream_response)

            if defense_on:
                for rrname, _, _ in records:
                    if not is_within_bailiwick(rrname, qname):
                        print(
                            f"[resolver] Rl3 block: qname={qname} "
                            f"out_of_bailiwick={rrname}"
                        )
                        tc_response = build_response(request, None, tc_flag=True)
                        server.sendto(tc_response.pack(), client_addr)
                        break
                else:
                    for rrname, ip, ttl in records:
                        if is_within_bailiwick(rrname, qname):
                            cache.set(rrname, ip, ttl)
                    answer_ip = cache.get(qname)
                    response = build_response(request, answer_ip)
                    server.sendto(response.pack(), client_addr)
                continue

            for rrname, ip, ttl in records:
                cache.set(rrname, ip, ttl)

            answer_ip = cache.get(qname)
            response = build_response(request, answer_ip)
            server.sendto(response.pack(), client_addr)

        except Exception as exc:
            print(f"[resolver] error: {exc}")
            try:
                request = DNSRecord.parse(payload)
                response = build_response(request, None, rcode=RCODE.SERVFAIL)
                server.sendto(response.pack(), client_addr)
            except Exception:
                continue


if __name__ == "__main__":
    main()
