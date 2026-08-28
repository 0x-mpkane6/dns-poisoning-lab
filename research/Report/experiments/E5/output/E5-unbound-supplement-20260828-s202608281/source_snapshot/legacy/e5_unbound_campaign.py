#!/usr/bin/env python3
"""Run the Unbound real-fragment E5 campaign. Do not pool with the marker-lab runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parent
E5_DIR = LAB.parent
PROTOCOL_PATH = LAB / "e5_unbound_protocol.json"
ENV_FILE = LAB / "e5.env"
COMPOSE_FILE = LAB / "compose.yaml"
POISON_IP = "6.6.6.6"
LEGIT_BANK_IP = "203.0.113.80"

CASES: dict[str, dict[str, Any]] = {
    "C0_attack_flood_b0": {
        "defense": "off",
        "ipid_mode": "random",
        "bank_tail": "omit",
        "client_profile": "attack",
        "poison": True,
        "occupancy": None,
        "flood": False,
        "control": True,
        "warmup_s": 2.0,
        "target_pps": None,
        "wait_occupancy": False,
    },
    "C1_benign_low": {
        "defense": "on",
        "ipid_mode": "random",
        "bank_tail": "send",
        "client_profile": "benign-frag",
        "poison": False,
        "occupancy": {"rate_pps": 2.5, "ipid_mode": "random"},
        "flood": False,
        "control": False,
        "warmup_s": 3.0,
        "target_pps": 2.5,
        "wait_occupancy": True,
    },
    "C2_benign_boundary": {
        "defense": "on",
        "ipid_mode": "random",
        "bank_tail": "send",
        "client_profile": "benign-frag",
        "poison": False,
        "occupancy": {"rate_pps": 12.0, "ipid_mode": "random"},
        "flood": False,
        "control": False,
        "warmup_s": 3.0,
        "target_pps": 12.0,
        "wait_occupancy": True,
    },
    "C3_attack_matched": {
        "defense": "on",
        "ipid_mode": "fixed:777",
        "bank_tail": "omit",
        "client_profile": "attack",
        "poison": True,
        "occupancy": {"rate_pps": 12.0, "ipid_mode": "fixed", "fixed_ipid": 777},
        "flood": False,
        "control": False,
        "warmup_s": 3.0,
        "target_pps": 12.0,
        "wait_occupancy": True,
    },
    "C4_attack_flood": {
        "defense": "on",
        "ipid_mode": "random",
        "bank_tail": "omit",
        "client_profile": "attack",
        "poison": True,
        "occupancy": None,
        "flood": True,
        "control": False,
        "warmup_s": 5.0,
        "target_pps": None,
        "wait_occupancy": True,
    },
}


def derive_seed(experiment_seed: int, *parts: object) -> int:
    material = "|".join([str(experiment_seed), *(str(part) for part in parts)])
    return int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big") % (2**31 - 1)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_protocol() -> dict[str, Any]:
    return json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))


def compose_cmd(*args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-directory",
        str(LAB),
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(COMPOSE_FILE),
        *args,
    ]


def run(cmd: list[str], *, check: bool = True, capture: bool = False, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, capture_output=capture, text=True, timeout=timeout, cwd=str(LAB))


def compose_exec(service: str, command: str, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return run(compose_cmd("exec", "-T", service, "sh", "-lc", command), check=False, capture=True, timeout=timeout)


def wait_for_docker(timeout_s: int = 180) -> None:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        proc = subprocess.run(["docker", "info"], capture_output=True, text=True)
        if proc.returncode == 0:
            return
        last = (proc.stderr or proc.stdout or "").strip().splitlines()[-1] if (proc.stderr or proc.stdout) else "docker not ready"
        time.sleep(3)
    raise SystemExit(f"Docker daemon did not become ready: {last}")


def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (q / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def parse_mem_mib(text: str) -> float | None:
    try:
        used = text.split("/")[0].strip()
        number = float("".join(ch for ch in used if ch.isdigit() or ch == "."))
        unit = "".join(ch for ch in used if ch.isalpha()).lower()
        if unit in {"gib", "gb"}:
            return number * 1024.0
        if unit in {"kib", "kb"}:
            return number / 1024.0
        return number
    except (ValueError, IndexError):
        return None


class StatsSampler:
    def __init__(self, container_id: str, interval_s: float = 1.0) -> None:
        self.container_id = container_id
        self.interval_s = interval_s
        self.samples: list[dict[str, float]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            proc = subprocess.run(
                ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}\t{{.MemUsage}}", self.container_id],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                cpu_raw, mem_raw = proc.stdout.strip().split("\t", 1)
                try:
                    cpu = float(cpu_raw.replace("%", "").strip())
                except ValueError:
                    cpu = float("nan")
                mem = parse_mem_mib(mem_raw)
                if mem is not None and cpu == cpu:
                    self.samples.append({"cpu_percent": cpu, "memory_mib": mem, "ts": time.time()})
            self._stop.wait(self.interval_s)

    def summary(self) -> dict[str, float]:
        if not self.samples:
            return {
                "cpu_percent_mean": float("nan"),
                "cpu_percent_max": float("nan"),
                "memory_mib_mean": float("nan"),
                "memory_mib_max": float("nan"),
                "n_samples": 0,
            }
        cpu = [row["cpu_percent"] for row in self.samples]
        mem = [row["memory_mib"] for row in self.samples]
        return {
            "cpu_percent_mean": statistics.fmean(cpu),
            "cpu_percent_max": max(cpu),
            "memory_mib_mean": statistics.fmean(mem),
            "memory_mib_max": max(mem),
            "n_samples": len(self.samples),
        }


def ensure_stack(build: bool) -> None:
    args = ["up", "-d"]
    if build:
        args.extend(["--build", "--force-recreate"])
    run(compose_cmd(*args))
    time.sleep(4)


def resolver_id() -> str:
    proc = run(compose_cmd("ps", "-q", "resolver"), capture=True)
    cid = proc.stdout.strip().splitlines()[-1].strip()
    if not cid:
        raise RuntimeError("resolver container id missing")
    return cid


def stop_workers() -> None:
    run(compose_cmd("restart", "attacker"), check=False)
    time.sleep(2.0)


def write_container_file(service: str, path: str, content: str) -> None:
    compose_exec(service, f"printf '%s\\n' '{content}' > {path}")


def reset_run_state(case: dict[str, Any]) -> None:
    stop_workers()
    run(compose_cmd("up", "-d", "--force-recreate", "resolver", "auth"), check=False)
    time.sleep(4)
    write_container_file("resolver", "/app/defense_mode", case["defense"])
    write_container_file("resolver", "/app/poison_mode", "on" if case["poison"] else "off")
    write_container_file("auth", "/app/ipid_mode", case["ipid_mode"])
    write_container_file("auth", "/app/bank_tail_mode", case["bank_tail"])
    write_container_file("auth", "/app/notify_attacker", "on" if case["poison"] else "off")


def collect_text(service: str, path: str) -> str:
    proc = compose_exec(service, f"cat {path} 2>/dev/null || true")
    return proc.stdout or ""


def wait_for_occupancy(min_samples: int, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    last = 0
    while time.monotonic() < deadline:
        text = collect_text("resolver", "/app/r2_occupancy.json")
        try:
            stripped = text.strip()
            payload = json.loads(stripped) if stripped else {}
            last = int(payload.get("occupancy") or 0)
        except (json.JSONDecodeError, TypeError, ValueError):
            last = 0
        if last >= min_samples:
            return last
        time.sleep(0.2)
    raise RuntimeError(f"resolver warm-up gate failed: occupancy={last}, target={min_samples}")


def target_warmup_occupancy(spec: dict[str, Any]) -> int:
    if spec.get("target_pps") == 2.5:
        return 3
    return 8


def start_sender(case: dict[str, Any], seed: int) -> None:
    warmup = float(case.get("warmup_s") or 2.0)
    if case["poison"]:
        run(compose_cmd("exec", "-d", "attacker", "python3", "/app/sender.py", "--role", "notify-poison"), check=False)
        time.sleep(0.4)
    if case["flood"]:
        cmd = ["exec", "-d", "attacker", "python3", "/app/sender.py", "--role", "occupancy", "--mode", "flood", "--ipid-mode", "sweep", "--seed", str(seed)]
        run(compose_cmd(*cmd), check=False)
        time.sleep(warmup)
        return
    occ = case.get("occupancy")
    if not occ:
        time.sleep(warmup)
        return
    cmd = [
        "exec", "-d", "attacker", "python3", "/app/sender.py",
        "--role", "occupancy", "--mode", "rate",
        "--rate-pps", str(occ["rate_pps"]),
        "--seed", str(seed),
    ]
    if occ.get("ipid_mode") == "fixed":
        cmd.extend(["--ipid-mode", "fixed", "--fixed-ipid", str(occ["fixed_ipid"])])
    else:
        cmd.extend(["--ipid-mode", "random"])
    run(compose_cmd(*cmd), check=False)
    time.sleep(warmup)
    cmd = [
        "exec", "-d", "attacker", "python3", "/app/sender.py",
        "--role", "occupancy", "--mode", "rate",
        "--rate-pps", str(occ["rate_pps"]),
        "--seed", str(seed),
    ]
    if occ.get("ipid_mode") == "fixed":
        cmd.extend(["--ipid-mode", "fixed", "--fixed-ipid", str(occ["fixed_ipid"])])
    else:
        cmd.extend(["--ipid-mode", "random"])
    run(compose_cmd(*cmd), check=False)
    time.sleep(warmup)


def parse_result_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_latency(text: str) -> list[float]:
    values: list[float] = []
    for line in parse_result_lines(text):
        try:
            values.append(float(line))
        except ValueError:
            continue
    return values


def parse_decisions(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def summarize_run(
    *,
    case_id: str,
    spec: dict[str, Any],
    result_text: str,
    trigger_lat_text: str,
    bank_lat_text: str,
    decision_text: str,
    stats: dict[str, float],
    wall_s: float,
) -> dict[str, Any]:
    answers = parse_result_lines(result_text)
    trigger_lat = parse_latency(trigger_lat_text)
    bank_lat = parse_latency(bank_lat_text)
    decisions = parse_decisions(decision_text)
    poisoned = sum(1 for item in answers if item == POISON_IP)
    total = len(answers)
    triggers = [row for row in decisions if row.get("action") == "tc_block"]
    allows = [row for row in decisions if row.get("action") == "allow"]
    samples = [float(row.get("samples") or 0) for row in decisions]
    entropies = [float(row.get("entropy") or 0) for row in decisions]
    ratios = [float(row.get("unique_ratio") or 0) for row in decisions]
    failed = []
    for row in allows:
        failed.extend(row.get("failed_gates") or [])
    first = answers[0] if answers else None
    return {
        "case_id": case_id,
        "defense": spec["defense"],
        "control": spec["control"],
        "total_rounds": total,
        "poisoned": poisoned,
        "legit": sum(1 for item in answers if item == LEGIT_BANK_IP),
        "noanswer": sum(1 for item in answers if item == "NOANSWER"),
        "run_asr": (poisoned / total) if total else float("nan"),
        "any_poison": poisoned > 0,
        "first_answer": first,
        "first_poisoned": first == POISON_IP,
        "trigger_command_latency_p50_ms": percentile(trigger_lat, 50),
        "trigger_command_latency_p95_ms": percentile(trigger_lat, 95),
        "bank_lookup_latency_p50_ms": percentile(bank_lat, 50),
        "bank_lookup_latency_p95_ms": percentile(bank_lat, 95),
        "n_trigger_latency": len(trigger_lat),
        "n_bank_latency": len(bank_lat),
        "n_decisions": len(decisions),
        "n_allow": len(allows),
        "n_tc_block": len(triggers),
        "trigger_rate": (len(triggers) / len(decisions)) if decisions else float("nan"),
        "mean_samples": statistics.fmean(samples) if samples else float("nan"),
        "mean_entropy": statistics.fmean(entropies) if entropies else float("nan"),
        "mean_unique_ratio": statistics.fmean(ratios) if ratios else float("nan"),
        "allow_failed_gates": sorted(set(failed)),
        "probe_rounds_per_s": (total / wall_s) if wall_s > 0 else float("nan"),
        "wall_s": wall_s,
        **stats,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def artifact_dir(run_root: Path, case_id: str, rep: int) -> Path:
    return run_root / "raw" / case_id / f"rep_{rep:02d}"


def execute_one(run_root: Path, case_id: str, rep: int, rounds: int, experiment_seed: int) -> dict[str, Any]:
    spec = CASES[case_id]
    out = artifact_dir(run_root, case_id, rep)
    out.mkdir(parents=True, exist_ok=True)
    sender_seed = derive_seed(experiment_seed, case_id, rep, "sender")
    reset_run_state(spec)
    start_sender(spec, sender_seed)
    warmup_occupancy = 0
    try:
        if spec["wait_occupancy"]:
            warmup_occupancy = wait_for_occupancy(target_warmup_occupancy(spec), 20.0)
    except Exception:
        stop_workers()
        raise
    sampler = StatsSampler(resolver_id())
    sampler.start()
    started = time.perf_counter()
    probe = compose_exec(
        "client",
        f"bash /app/test.sh example.net {rounds} {spec['client_profile']}",
        timeout=max(240, rounds * 10),
    )
    wall_s = time.perf_counter() - started
    sampler.stop()
    stop_workers()

    result_text = collect_text("client", "/app/result.txt")
    trigger_lat_text = collect_text("client", "/app/trigger_latency_ms.txt")
    bank_lat_text = collect_text("client", "/app/bank_latency_ms.txt")
    rounds_text = collect_text("client", "/app/rounds.tsv")
    trigger_raw_text = collect_text("client", "/app/trigger_raw.tsv")
    decision_text = collect_text("resolver", "/app/r2_entropy_decisions.jsonl")
    events_text = collect_text("resolver", "/app/frag2_events.jsonl")
    version_text = collect_text("resolver", "/app/unbound_version.txt")

    (out / "client_stdout.txt").write_text(probe.stdout or "", encoding="utf-8")
    (out / "client_stderr.txt").write_text(probe.stderr or "", encoding="utf-8")
    (out / "result.txt").write_text(result_text, encoding="utf-8")
    (out / "trigger_latency_ms.txt").write_text(trigger_lat_text, encoding="utf-8")
    (out / "bank_latency_ms.txt").write_text(bank_lat_text, encoding="utf-8")
    (out / "rounds.tsv").write_text(rounds_text, encoding="utf-8")
    (out / "trigger_raw.tsv").write_text(trigger_raw_text, encoding="utf-8")
    (out / "r2_decisions.jsonl").write_text(decision_text, encoding="utf-8")
    (out / "frag2_events.jsonl").write_text(events_text, encoding="utf-8")
    (out / "unbound_version.txt").write_text(version_text, encoding="utf-8")
    write_json(out / "docker_stats.json", sampler.samples)
    occupancy_text = collect_text("resolver", "/app/r2_occupancy.json")
    (out / "r2_occupancy.json").write_text(occupancy_text, encoding="utf-8")
    write_json(
        out / "run_meta.json",
        {
            "case_id": case_id,
            "rep": rep,
            "sender_seed": sender_seed,
            "rounds": rounds,
            "warmup_occupancy": warmup_occupancy,
            "warmup_target": target_warmup_occupancy(spec) if spec["wait_occupancy"] else 0,
        },
    )
    metrics = summarize_run(
        case_id=case_id,
        spec=spec,
        result_text=result_text,
        trigger_lat_text=trigger_lat_text,
        bank_lat_text=bank_lat_text,
        decision_text=decision_text,
        stats=sampler.summary(),
        wall_s=wall_s,
    )
    metrics.update(
        {
            "rep": rep,
            "sender_seed": sender_seed,
            "warmup_occupancy": warmup_occupancy,
            "finished_utc": utc_now(),
            "client_exit_code": probe.returncode,
            "artifact_dir": str(out.relative_to(run_root)).replace("\\", "/"),
        }
    )
    write_json(out / "metrics.json", metrics)
    print(
        f"[{case_id} rep={rep:02d}] ASR={metrics['run_asr']:.3f} "
        f"trig={metrics['trigger_rate']:.3f} samples={metrics['mean_samples']:.1f} "
        f"cpu={metrics['cpu_percent_mean']:.2f}% n={metrics['total_rounds']}",
        flush=True,
    )
    return metrics


def schedule_for(stage: str, protocol: dict[str, Any]) -> list[dict[str, Any]]:
    if stage == "sanity":
        return [{"case_id": case_id, "rep": 0} for case_id in protocol["sanity"]["order"]]
    items: list[dict[str, Any]] = []
    k = int(protocol["k_runs_per_case"])
    case_ids = ["C0_attack_flood_b0", "C1_benign_low", "C2_benign_boundary", "C3_attack_matched", "C4_attack_flood"]
    for case_id in case_ids:
        for rep in range(1, k + 1):
            items.append({"case_id": case_id, "rep": rep})
    rng = random.Random(int(protocol["experiment_seed"]))
    rng.shuffle(items)
    return items


def occupancy_rel_diff(a: float, b: float) -> float:
    if a != a or b != b or a <= 0 or b <= 0:
        return float("inf")
    return abs(a - b) / ((a + b) / 2.0)


def write_provenance(run_root: Path) -> None:
    snap = run_root / "source_snapshot"
    snap.mkdir(parents=True, exist_ok=True)
    files = {
        "auth_server.py": LAB / "auth" / "auth_server.py",
        "sender.py": LAB / "attacker" / "sender.py",
        "poisoner.py": LAB / "resolver" / "poisoner.py",
        "detector.py": LAB / "resolver" / "detector.py",
        "unbound.conf": LAB / "resolver" / "unbound.conf",
        "e5mod.py": LAB / "resolver" / "e5mod.py",
        "test.sh": LAB / "client" / "test.sh",
        "compose.yaml": COMPOSE_FILE,
        "e5_unbound_campaign.py": Path(__file__),
        "e5_unbound_protocol.json": PROTOCOL_PATH,
        "e5.env": ENV_FILE,
    }
    hashes = {}
    for name, path in files.items():
        shutil.copy2(path, snap / name)
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    git = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=str(E5_DIR.parents[3]))
    write_json(
        run_root / "provenance.json",
        {"utc": utc_now(), "git_head": (git.stdout or "").strip(), "file_sha256": hashes},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=("sanity", "confirmatory", "all"), default="all")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--rounds", type=int, default=0)
    args = parser.parse_args()

    protocol = load_protocol()
    run_id = protocol["run_id"]
    experiment_seed = int(protocol["experiment_seed"])
    rounds = int(args.rounds or protocol["rounds_per_run"])
    run_root = E5_DIR / "runs" / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PROTOCOL_PATH, run_root / "e5_protocol.json")
    write_json(run_root / "started.json", {"utc": utc_now(), "stage": args.stage, "rounds": rounds})

    print("[e5-unbound] waiting for Docker...", flush=True)
    wait_for_docker()
    print("[e5-unbound] bringing stack up", flush=True)
    ensure_stack(build=not args.skip_build)
    write_provenance(run_root)
    stop_workers()

    stages = ["sanity", "confirmatory"] if args.stage == "all" else [args.stage]
    all_metrics: list[dict[str, Any]] = []
    for stage in stages:
        jobs = schedule_for(stage, protocol)
        write_json(run_root / f"schedule_{stage}.json", jobs)
        print(f"[e5-unbound] stage={stage} jobs={len(jobs)}", flush=True)
        stage_metrics: list[dict[str, Any]] = []
        for job in jobs:
            metrics = execute_one(run_root, job["case_id"], int(job["rep"]), rounds, experiment_seed)
            metrics["stage"] = stage
            stage_metrics.append(metrics)
            all_metrics.append(metrics)
            write_json(run_root / "metrics_partial.json", all_metrics)
            if stage == "sanity" and job["case_id"] == "C0_attack_flood_b0" and metrics["poisoned"] == 0:
                write_json(run_root / "ABORT.json", {"reason": "C0 ASR is 0; Unbound poison path is not working", "metrics": metrics})
                print("[e5-unbound] ABORT: B0 produced no poison.", flush=True)
                return 2
        write_json(run_root / f"metrics_{stage}.json", stage_metrics)
        if stage == "sanity":
            by_case = {row["case_id"]: row for row in stage_metrics}
            c2 = float(by_case["C2_benign_boundary"]["mean_samples"])
            c3 = float(by_case["C3_attack_matched"]["mean_samples"])
            rel = occupancy_rel_diff(c2, c3)
            write_json(run_root / "sanity_occupancy_gate.json", {"C2": c2, "C3": c3, "rel_diff": rel})
            if rel > 0.15:
                write_json(run_root / "ABORT.json", {"reason": "C2/C3 occupancy mismatch", "C2": c2, "C3": c3, "rel_diff": rel})
                print(f"[e5-unbound] ABORT: C2/C3 occupancy rel_diff={rel:.3f} > 0.15", flush=True)
                return 3
            print(f"[e5-unbound] occupancy gate PASS C2={c2:.1f} C3={c3:.1f} rel={rel:.3f}", flush=True)

    write_json(run_root / "metrics_all.json", all_metrics)
    write_json(run_root / "finished.json", {"utc": utc_now()})
    print(f"[e5-unbound] done. artifacts: {run_root}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
