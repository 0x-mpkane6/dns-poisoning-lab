import os
import random
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, RCODE

LISTEN_IP = os.getenv("RESOLVER_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RESOLVER_LISTEN_PORT", "53"))
RESOLVER_BIND_IP = os.getenv("RESOLVER_BIND_IP", "10.50.0.53")

UPSTREAM_IP = os.getenv("UPSTREAM_DNS_IP", "10.50.0.100")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_DNS_PORT", "53"))
UPSTREAM_FIXED_SRC_PORT = int(os.getenv("UPSTREAM_FIXED_SRC_PORT", "33333"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "1.2"))

CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))
TXID_SPACE = int(os.getenv("TXID_SPACE", "200"))
PORT_BRUTE_BASE = int(os.getenv("PORT_BRUTE_BASE", "33300"))
PORT_BRUTE_SPACE = int(os.getenv("PORT_BRUTE_SPACE", "20"))
PORT_TXID_SPACE = int(os.getenv("PORT_TXID_SPACE", "10"))
ATTACK_VARIANT = os.getenv("ATTACK_VARIANT", "txid").strip().lower()
DEFENSE_DEFAULT_MODE = os.getenv("DEFENSE_MODE", "off").strip().lower()
FLUSH_QNAME = os.getenv("FLUSH_QNAME", "_flush.stype-control")

DEFENSE_FILE = "/app/defense_mode"


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

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


def normalize_name(name: str) -> str:
    value = name.lower().strip()
    if value.endswith("."):
        value = value[:-1]
    return value


def defense_enabled() -> bool:
    try:
        with open(DEFENSE_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip().lower() == "on"
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
            records.append((normalize_name(str(rr.rname)), str(rr.rdata), int(rr.ttl)))
    return records


def choose_source_port(defense_on: bool) -> int:
    if defense_on:
        return random.randint(40000, 60999)
    if ATTACK_VARIANT == "port":
        return PORT_BRUTE_BASE + random.randint(0, max(0, PORT_BRUTE_SPACE - 1))
    return UPSTREAM_FIXED_SRC_PORT


def choose_txid(defense_on: bool) -> int:
    if defense_on:
        return random.randint(0, 65535)
    if ATTACK_VARIANT == "port":
        return random.randint(0, max(1, PORT_TXID_SPACE - 1))
    return random.randint(0, max(1, TXID_SPACE - 1))


def query_upstream(qname: str, defense_on: bool) -> Tuple[Optional[DNSRecord], bool]:
    request = DNSRecord.question(qname, "A")
    request.header.id = choose_txid(defense_on)
    source_port = choose_source_port(defense_on)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((RESOLVER_BIND_IP, source_port))
        sock.settimeout(UPSTREAM_TIMEOUT)
        sock.sendto(request.pack(), (UPSTREAM_IP, UPSTREAM_PORT))

        deadline = time.time() + UPSTREAM_TIMEOUT
        suspicious = 0

        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                break

            response = DNSRecord.parse(data)
            response_qname = normalize_name(str(response.q.qname)) if response.q else ""
            expected_qname = normalize_name(qname)

            if response.header.id == request.header.id and response_qname == expected_qname:
                return response, False

            suspicious += 1
            if defense_on:
                print(
                    f"[resolver] Rl1 block: qname={qname} "
                    f"txid={request.header.id} source_port={source_port} suspicious={suspicious}"
                )
                return None, True

        return None, False


def main() -> None:
    if not os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write("on\n" if DEFENSE_DEFAULT_MODE == "on" else "off\n")

    cache = DNSCache()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, LISTEN_PORT))

    print(
        f"[resolver] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"upstream={UPSTREAM_IP}:{UPSTREAM_PORT} | variant={ATTACK_VARIANT}"
    )

    while True:
        payload, client_addr = server.recvfrom(4096)
        try:
            request = DNSRecord.parse(payload)
            if request.q.qtype != QTYPE.A:
                server.sendto(build_response(request, None, rcode=RCODE.NXDOMAIN).pack(), client_addr)
                continue

            qname = normalize_name(str(request.q.qname))
            if qname == normalize_name(FLUSH_QNAME):
                cache.clear()
                server.sendto(build_response(request, None).pack(), client_addr)
                continue

            cached_ip = cache.get(qname)
            if cached_ip:
                server.sendto(build_response(request, cached_ip).pack(), client_addr)
                continue

            defense_on = defense_enabled()
            upstream_response, rl1_detected = query_upstream(qname, defense_on)

            if rl1_detected:
                server.sendto(build_response(request, None, tc_flag=True).pack(), client_addr)
                continue

            if upstream_response is None:
                server.sendto(build_response(request, None, rcode=RCODE.SERVFAIL).pack(), client_addr)
                continue

            for rrname, ip, ttl in extract_a_records(upstream_response):
                cache.set(rrname, ip, ttl)

            answer_ip = cache.get(qname)
            server.sendto(build_response(request, answer_ip).pack(), client_addr)

        except Exception as exc:
            print(f"[resolver] error: {exc}")
            try:
                request = DNSRecord.parse(payload)
                server.sendto(build_response(request, None, rcode=RCODE.SERVFAIL).pack(), client_addr)
            except Exception:
                continue


if __name__ == "__main__":
    main()
