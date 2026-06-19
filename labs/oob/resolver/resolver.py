"""OoB lab recursive resolver with toggleable R3 (bailiwick) defense.

Design notes
------------
* Uses dnslib for parsing/building DNS messages.
* Cache is a simple name -> (ip, expires_at) dict. A cache HIT returns the cached
  value; a cache MISS triggers a single upstream query to the lab's authoritative
  server (no recursion to real internet).
* Entropy defaults to the realistic lab mode: 16-bit TXID and an OS-chosen
  random upstream source port. Set ``TXID_SPACE=1024`` and
  ``UPSTREAM_FIXED_SRC_PORT=33333`` only when you deliberately want the old
  weak-entropy demo.
* R3 defense, when ON, scans every section of the upstream response and rejects
  the entire packet (TC=1 returned to the client) if any record is OUT-of-
  bailiwick. R3 also additionally rejects responses where ``response.q.qname``
  does not match the question we sent (paper assumption: this guards against
  the attacker reusing a different qname).
"""

from __future__ import annotations

import os
import random
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR, RCODE

LISTEN_IP = os.getenv("RESOLVER_LISTEN_IP", "0.0.0.0")
LISTEN_PORT = int(os.getenv("RESOLVER_LISTEN_PORT", "53"))
RESOLVER_BIND_IP = os.getenv("RESOLVER_BIND_IP", "10.20.0.53")
UPSTREAM_IP = os.getenv("UPSTREAM_DNS_IP", "10.20.0.100")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_DNS_PORT", "53"))
CACHE_DEFAULT_TTL = int(os.getenv("CACHE_DEFAULT_TTL", "60"))
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "1.2"))
UPSTREAM_FIXED_SRC_PORT = int(os.getenv("UPSTREAM_FIXED_SRC_PORT", "0"))
TXID_SPACE = max(1, min(65536, int(os.getenv("TXID_SPACE", "65536"))))
DEFENSE_DEFAULT_MODE = os.getenv("DEFENSE_MODE", "off").strip().lower()

DEFENSE_FILE = "/app/defense_mode"
DEFENSE_ON_VALUE = "on"


def random_txid() -> int:
    return random.randint(0, TXID_SPACE - 1)


def bind_upstream_socket(sock: socket.socket) -> None:
    """Bind upstream socket.

    ``UPSTREAM_FIXED_SRC_PORT=0`` asks the OS for an ephemeral source port, which
    is the realistic/default setting. A positive value is kept for reproducible
    weak-entropy demos.
    """
    port = UPSTREAM_FIXED_SRC_PORT if UPSTREAM_FIXED_SRC_PORT > 0 else 0
    sock.bind((RESOLVER_BIND_IP, port))


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
    """Infer the bailiwick zone for ``qname``.

    Lab uses zones like ``example.net``; the heuristic is "last 2 labels of the
    qname" which is sufficient for the test domains. For production resolvers
    you would derive bailiwick from the parent NS chain instead.
    """
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


def extract_named_records(response: DNSRecord) -> List[Tuple[str, str, int, str]]:
    """Return (name, ip, ttl, section) for every A record across all sections.

    ``section`` is one of ``"AN"``, ``"AU"``, ``"AR"`` so a verdict can pinpoint
    where the OoB record lived (useful for evidence in the report).
    """
    records: List[Tuple[str, str, int, str]] = []
    for label, rrset in (("AN", response.rr), ("AU", response.auth), ("AR", response.ar)):
        for rr in rrset:
            if QTYPE.get(rr.rtype) != "A":
                continue
            name = normalize_name(str(rr.rname))
            ip = str(rr.rdata)
            records.append((name, ip, int(rr.ttl), label))
    return records


def query_upstream(qname: str, qtype: str = "A") -> Optional[DNSRecord]:
    request = DNSRecord.question(qname, qtype)
    request.header.id = random_txid()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        bind_upstream_socket(sock)
        sock.settimeout(UPSTREAM_TIMEOUT)
        sock.sendto(request.pack(), (UPSTREAM_IP, UPSTREAM_PORT))

        deadline = time.time() + UPSTREAM_TIMEOUT
        while time.time() < deadline:
            remaining = max(0.01, deadline - time.time())
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                return None
            response = DNSRecord.parse(data)
            if response.header.id == request.header.id:
                return response
        return None


def main() -> None:
    if not os.path.exists(DEFENSE_FILE):
        with open(DEFENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write(("on\n" if DEFENSE_DEFAULT_MODE == "on" else "off\n"))

    cache = DNSCache()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((LISTEN_IP, LISTEN_PORT))

    print(
        f"[resolver] listening on {LISTEN_IP}:{LISTEN_PORT} | "
        f"upstream={UPSTREAM_IP}:{UPSTREAM_PORT} | "
        f"bind={RESOLVER_BIND_IP}:{UPSTREAM_FIXED_SRC_PORT or 'random'} | "
        f"txid_space={TXID_SPACE}"
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
            records = extract_named_records(upstream_response)

            if defense_on:
                # R3 strict: question section sanity (paper-style anti-cross-qname).
                resp_qname = normalize_name(str(upstream_response.q.qname)) if upstream_response.q else ""
                if resp_qname and resp_qname != qname:
                    print(
                        f"[resolver] R3 block: response qname mismatch "
                        f"asked={qname} got={resp_qname}"
                    )
                    server.sendto(build_response(request, None, tc_flag=True).pack(), client_addr)
                    continue

                # R3 strict: reject the whole packet if ANY OoB record is present.
                offenders = [
                    (rrname, ip, section)
                    for rrname, ip, _, section in records
                    if not is_within_bailiwick(rrname, qname)
                ]
                if offenders:
                    for rrname, ip, section in offenders:
                        print(
                            f"[resolver] R3 block: qname={qname} "
                            f"section={section} out_of_bailiwick={rrname}->{ip}"
                        )
                    server.sendto(build_response(request, None, tc_flag=True).pack(), client_addr)
                    continue

                # All in-bailiwick - cache and answer.
                for rrname, ip, ttl, _ in records:
                    cache.set(rrname, ip, ttl)
                answer_ip = cache.get(qname)
                response = build_response(request, answer_ip)
                server.sendto(response.pack(), client_addr)
                continue

            # Defense OFF: vulnerable behavior - greedily cache everything.
            for rrname, ip, ttl, section in records:
                cache.set(rrname, ip, ttl)
                if not is_within_bailiwick(rrname, qname):
                    print(
                        f"[resolver] (no-defense) cached OoB record "
                        f"section={section} {rrname}->{ip} (ttl={ttl})"
                    )
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
