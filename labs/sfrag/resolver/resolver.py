import os
import random
import re
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR, RCODE

LISTEN_IP = os.getenv("RESOLVER_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RESOLVER_LISTEN_PORT", "53"))
RESOLVER_BIND_IP = os.getenv("RESOLVER_BIND_IP", "10.30.0.53")

UPSTREAM_IP = os.getenv("UPSTREAM_DNS_IP", "10.30.0.100")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_DNS_PORT", "53"))
UPSTREAM_FIXED_SRC_PORT = int(os.getenv("UPSTREAM_FIXED_SRC_PORT", "33333"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "1.2"))

CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))
TXID_SPACE = int(os.getenv("TXID_SPACE", "1024"))

FRAG2_KEEP_SECONDS = float(os.getenv("FRAG2_KEEP_SECONDS", "2.0"))
FRAGMETA_QNAME = os.getenv("FRAGMETA_QNAME", "_fragmeta.example.net.")
FRAG2_QNAME = os.getenv("FRAG2_QNAME", "_frag2.example.net.")

DEFENSE_FILE = "/app/defense_mode"
DEFENSE_DEFAULT_MODE = os.getenv("DEFENSE_MODE", "off").strip().lower()

IPID_RE = re.compile(r"IPID=(\d+)")


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


class Frag2Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[int, Tuple[str, str, int, float]] = {}

    def put(self, ipid: int, rrname: str, ip: str, ttl: int) -> None:
        expires_at = time.time() + max(0.1, FRAG2_KEEP_SECONDS)
        with self._lock:
            self._data[ipid] = (rrname, ip, ttl, expires_at)

    def get(self, ipid: int) -> Optional[Tuple[str, str, int]]:
        now = time.time()
        with self._lock:
            stale = [key for key, (_, _, _, exp) in self._data.items() if exp <= now]
            for key in stale:
                self._data.pop(key, None)

            value = self._data.get(ipid)
            if not value:
                return None
            rrname, ip, ttl, _ = value
            return rrname, ip, ttl


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


def extract_txt_values(response: DNSRecord) -> List[str]:
    values: List[str] = []
    for section in (response.rr, response.auth, response.ar):
        for rr in section:
            if QTYPE.get(rr.rtype) != "TXT":
                continue
            raw = str(rr.rdata).strip().strip('"')
            values.append(raw)
    return values


def parse_ipid(txt_values: List[str]) -> Optional[int]:
    for value in txt_values:
        match = IPID_RE.search(value.upper())
        if match:
            return int(match.group(1))
    return None


def is_frag2_marker(qname: str, txt_values: List[str]) -> bool:
    qname_norm = normalize_name(qname)
    if qname_norm == normalize_name(FRAG2_QNAME):
        return True
    for value in txt_values:
        if "TYPE=FRAG2" in value.upper():
            return True
    return False


def is_frag1_marker(txt_values: List[str]) -> bool:
    for value in txt_values:
        if "TYPE=FRAG1" in value.upper():
            return True
    return False


def extract_a_records(response: DNSRecord) -> List[Tuple[str, str, int]]:
    records: List[Tuple[str, str, int]] = []
    fragmeta_norm = normalize_name(FRAGMETA_QNAME)
    frag2_norm = normalize_name(FRAG2_QNAME)

    for section in (response.rr, response.auth, response.ar):
        for rr in section:
            if QTYPE.get(rr.rtype) != "A":
                continue
            name = normalize_name(str(rr.rname))
            if name in (fragmeta_norm, frag2_norm):
                continue
            records.append((name, str(rr.rdata), int(rr.ttl)))
    return records


def handle_frag2_packet(response: DNSRecord, frag_store: Frag2Store) -> bool:
    if not response.q:
        return False

    qname = str(response.q.qname)
    txt_values = extract_txt_values(response)
    if not is_frag2_marker(qname, txt_values):
        return False

    ipid = parse_ipid(txt_values)
    if ipid is None:
        return False

    for rrname, ip, ttl in extract_a_records(response):
        frag_store.put(ipid, rrname, ip, ttl)
        print(f"[resolver] captured forged frag2: ipid={ipid} {rrname}->{ip}")
        return True

    return False


def query_upstream(
    upstream_sock: socket.socket,
    qname: str,
    defense_on: bool,
    frag_store: Frag2Store,
) -> Tuple[Optional[List[Tuple[str, str, int]]], bool]:
    request = DNSRecord.question(qname, "A")
    request.header.id = random.randint(0, max(1, TXID_SPACE - 1))
    upstream_sock.sendto(request.pack(), (UPSTREAM_IP, UPSTREAM_PORT))

    deadline = time.time() + UPSTREAM_TIMEOUT
    while time.time() < deadline:
        remaining = max(0.01, deadline - time.time())
        upstream_sock.settimeout(remaining)
        try:
            payload, _ = upstream_sock.recvfrom(4096)
        except socket.timeout:
            break

        response = DNSRecord.parse(payload)

        if handle_frag2_packet(response, frag_store):
            continue

        if response.header.id != request.header.id:
            continue

        if not response.q:
            continue

        if normalize_name(str(response.q.qname)) != normalize_name(qname):
            continue

        txt_values = extract_txt_values(response)
        frag1_ipid = parse_ipid(txt_values) if is_frag1_marker(txt_values) else None

        if defense_on and frag1_ipid is not None:
            print(f"[resolver] R2 block: qname={qname} ipid={frag1_ipid}")
            return None, True

        records = extract_a_records(response)
        if not defense_on and frag1_ipid is not None:
            forged = frag_store.get(frag1_ipid)
            if forged:
                rrname, ip, ttl = forged
                records.append((normalize_name(rrname), ip, ttl))
                print(
                    f"[resolver] merged forged frag2: qname={qname} "
                    f"ipid={frag1_ipid} {rrname}->{ip}"
                )

        return records, False

    return None, False


def main() -> None:
    if not os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write("on\n" if DEFENSE_DEFAULT_MODE == "on" else "off\n")

    cache = DNSCache()
    frag_store = Frag2Store()

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, LISTEN_PORT))

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind((RESOLVER_BIND_IP, UPSTREAM_FIXED_SRC_PORT))

    print(
        f"[resolver] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"upstream={UPSTREAM_IP}:{UPSTREAM_PORT} | bind={RESOLVER_BIND_IP}:{UPSTREAM_FIXED_SRC_PORT}"
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
                server.sendto(build_response(request, cached_ip).pack(), client_addr)
                continue

            defense_on = defense_enabled()
            records, frag_detected = query_upstream(upstream_sock, qname, defense_on, frag_store)

            if frag_detected:
                server.sendto(build_response(request, None, tc_flag=True).pack(), client_addr)
                continue

            if records is None:
                server.sendto(build_response(request, None, rcode=RCODE.SERVFAIL).pack(), client_addr)
                continue

            for rrname, ip, ttl in records:
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
