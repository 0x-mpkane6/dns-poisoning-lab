#!/usr/bin/env python3
"""Run the outline-scoped E5 experiment; save each run under output/."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import random
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

E5 = Path(__file__).resolve().parent
LAB = E5 / "tools" / "unbound_lab"
HERE = LAB / "supplement"
spec = importlib.util.spec_from_file_location("e5_legacy_runner", LAB / "e5_unbound_campaign.py")
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
CASES = copy.deepcopy(legacy.CASES)
run = legacy.run


def compose_cmd(*args: str) -> list[str]:
    return ["docker", "compose", "--project-directory", str(LAB), "--env-file", str(LAB / "e5.env"),
            "-f", str(LAB / "compose.yaml"), "-f", str(HERE / "compose.yaml"), *args]


legacy.compose_cmd = compose_cmd


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def start_sender(case: dict, seed: int) -> None:
    if case["poison"]:
        run(compose_cmd("exec", "-d", "attacker", "python3", "/app/sender.py", "--role", "notify-poison"))
        time.sleep(0.4)
    if case["flood"]:
        run(compose_cmd("exec", "-d", "attacker", "python3", "/app/sender.py", "--role", "occupancy",
                        "--mode", "flood", "--ipid-mode", "sweep", "--seed", str(seed)))
    elif case.get("occupancy"):
        occupancy = case["occupancy"]
        cmd = compose_cmd("exec", "-d", "attacker", "python3", "/app/sender.py", "--role", "occupancy",
                          "--mode", "rate", "--rate-pps", str(occupancy["rate_pps"]), "--seed", str(seed))
        if occupancy.get("ipid_mode") == "fixed":
            cmd.extend(["--ipid-mode", "fixed", "--fixed-ipid", str(occupancy["fixed_ipid"])])
        else:
            cmd.extend(["--ipid-mode", "random"])
        run(cmd)
    time.sleep(float(case["warmup_s"]))


def summarize_run(**kwargs) -> dict:
    result = legacy.summarize_run(**kwargs)
    for prefix, source in (("trigger_command", "trigger_lat_text"), ("bank_lookup", "bank_lat_text")):
        result[f"{prefix}_latency_p99_ms"] = legacy.percentile(legacy.parse_latency(kwargs[source]), 99)
    decisions = [json.loads(line) for line in kwargs["decision_text"].splitlines() if line.strip()]
    ticks = [row for row in decisions if row.get("reason") == "tick"]
    result["n_ticks"] = len(ticks)
    result["tick_trigger_rate"] = sum(row["action"] == "tc_block" for row in ticks) / len(ticks) if ticks else None
    result["tick_mean_samples"] = statistics.fmean(row["samples"] for row in ticks) if ticks else None
    result["rule_installed_rate"] = sum(bool(row.get("rule_installed")) for row in decisions) / len(decisions) if decisions else None
    result["enforcement_error_decisions"] = sum(row.get("enforcement_ok") is False for row in decisions)
    result["legitimate_answer_rate"] = result["legit"] / result["total_rounds"] if result["total_rounds"] else None
    result["noanswer_rate"] = result["noanswer"] / result["total_rounds"] if result["total_rounds"] else None
    return result


def schedule_for(stage: str, protocol: dict) -> list[dict]:
    if stage == "sanity":
        return [{"case_id": case, "rep": 0} for case in protocol["case_ids"]]
    rng = random.Random(protocol["experiment_seed"])
    schedule = []
    for rep in range(1, protocol["k_runs_per_case"] + 1):
        cells = list(protocol["case_ids"])
        rng.shuffle(cells)
        schedule.extend({"case_id": case, "rep": rep} for case in cells)
    return schedule


def sender_seed_for(seed: int, case_id: str, rep: int) -> int:
    return legacy.derive_seed(seed, case_id, rep, "sender")


def container_clock() -> float:
    proc = run(compose_cmd("exec", "-T", "resolver", "python3", "-c", "import time; print(time.monotonic())"), capture=True)
    return float(proc.stdout.strip())


def save_firewall(out: Path, label: str) -> None:
    proc = run(compose_cmd("exec", "-T", "resolver", "iptables-save", "-c", "-t", "raw"), capture=True, check=False)
    write_json(out / f"firewall_{label}.json", {"returncode": proc.returncode, "stdout": proc.stdout,
                                              "stderr": proc.stderr, "mono_s": container_clock()})


def execute_one(root: Path, case_id: str, rep: int, protocol: dict) -> dict:
    case = CASES[case_id]
    out = root / "raw" / case_id / f"rep_{rep:02d}"
    out.mkdir(parents=True, exist_ok=False)
    seed = sender_seed_for(protocol["experiment_seed"], case_id, rep)
    legacy.reset_run_state(case)
    start_sender(case, seed)
    warmup = legacy.wait_for_occupancy(legacy.target_warmup_occupancy(case), 20) if case["wait_occupancy"] else 0
    worker_state = run(compose_cmd("top", "attacker"), capture=True)
    (out / "attacker_processes.txt").write_text(worker_state.stdout, encoding="utf-8")
    sampler = legacy.StatsSampler(legacy.resolver_id())
    sampler.start()
    start_mono = container_clock()
    started = time.perf_counter()
    probe = None
    try:
        probe = legacy.compose_exec("client", f"bash /app/test.sh example.net {protocol['rounds_per_run']} {case['client_profile']}",
                                    timeout=max(240, protocol["rounds_per_run"] * 10))
    finally:
        wall_s = time.perf_counter() - started
        end_mono = container_clock()
        sampler.stop()
        legacy.stop_workers()
        write_json(out / "measurement.json", {"start_mono_s": start_mono, "end_mono_s": end_mono,
                                              "host_command_duration_s": wall_s})
        for filename, service, path in (
            ("result.txt", "client", "/app/result.txt"),
            ("trigger_latency_ms.txt", "client", "/app/trigger_latency_ms.txt"),
            ("bank_latency_ms.txt", "client", "/app/bank_latency_ms.txt"),
            ("rounds.tsv", "client", "/app/rounds.tsv"),
            ("trigger_raw.tsv", "client", "/app/trigger_raw.tsv"),
            ("r2_decisions.jsonl", "resolver", "/app/r2_entropy_decisions.jsonl"),
            ("frag2_events.jsonl", "resolver", "/app/frag2_events.jsonl"),
            ("enforcement.jsonl", "resolver", "/app/enforcement.jsonl"),
            ("unbound_version.txt", "resolver", "/app/unbound_version.txt"),
        ):
            (out / filename).write_text(legacy.collect_text(service, path), encoding="utf-8")
        write_json(out / "docker_stats.json", sampler.samples)
    if probe is None:
        raise RuntimeError("client did not finish; available evidence retained")
    (out / "client_stdout.txt").write_text(probe.stdout or "", encoding="utf-8")
    (out / "client_stderr.txt").write_text(probe.stderr or "", encoding="utf-8")
    all_decisions = [json.loads(line) for line in (out / "r2_decisions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    selected = [row for row in all_decisions if start_mono <= row["mono_s"] <= end_mono]
    metrics = summarize_run(
        case_id=case_id, spec=case, result_text=(out / "result.txt").read_text(encoding="utf-8"),
        trigger_lat_text=(out / "trigger_latency_ms.txt").read_text(encoding="utf-8"),
        bank_lat_text=(out / "bank_latency_ms.txt").read_text(encoding="utf-8"),
        decision_text="\n".join(json.dumps(row) for row in selected), stats=sampler.summary(), wall_s=wall_s,
    )
    metrics.update(rep=rep, sender_seed=seed, warmup_occupancy=warmup, finished_utc=legacy.utc_now(),
                   client_exit_code=probe.returncode, artifact_dir=out.relative_to(root).as_posix(),
                   n_decisions_all=len(all_decisions), measurement_start_mono_s=start_mono,
                   measurement_end_mono_s=end_mono)
    write_json(out / "metrics.json", metrics)
    print(f"[{case_id} rep={rep:02d}] ASR={metrics['run_asr']:.3f} event_trigger={metrics['trigger_rate']:.3f} "
          f"tick_trigger={metrics['tick_trigger_rate']:.3f} samples={metrics['mean_samples']:.1f} "
          f"enforcement_errors={metrics['enforcement_error_decisions']} n={metrics['total_rounds']}", flush=True)
    return metrics


def source_files() -> dict[str, Path]:
    files = {f"supplement/{path.name}": path for path in HERE.iterdir()
             if path.suffix in {".py", ".json", ".yaml", ".sh", ".md"} and path.name != "resources.json"}
    files["run_e5.py"] = Path(__file__)
    for relative in ("e5_unbound_campaign.py", "e5.env", "compose.yaml", "resolver/unbound.conf",
                     "resolver/e5mod.py", "resolver/Dockerfile", "auth/auth_server.py", "auth/Dockerfile",
                     "attacker/sender.py", "attacker/Dockerfile", "client/test.sh", "client/Dockerfile"):
        files[f"legacy/{relative}"] = LAB / relative
    files["analysis/e5_aggregate.py"] = E5 / "tools" / "e5_aggregate.py"
    return files


def write_provenance(root: Path, resume: bool) -> None:
    paths = source_files()
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    if resume:
        old = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
        if hashes != old["file_sha256"]:
            raise RuntimeError("source changed since registration; create a new run ID")
        return
    for name, path in paths.items():
        target = root / "source_snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    info = subprocess.run(["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True, check=True)
    docker_info = json.loads(info.stdout)
    environment = {key: docker_info.get(key) for key in ("NCPU", "MemTotal", "KernelVersion", "OperatingSystem", "ServerVersion")}
    write_json(root / "provenance.json", {"registered_utc": legacy.utc_now(), "file_sha256": hashes, "docker": environment,
                                          "command": sys.argv, "python": sys.version})


def witness() -> None:
    expected = json.loads((HERE / "env-spec.json").read_text(encoding="utf-8"))["images"]
    for service, wanted in expected.items():
        actual = subprocess.run(["docker", "image", "inspect", f"e5-unbound-{service}:latest", "--format", "{{.Id}}"],
                                check=True, capture_output=True, text=True).stdout.strip()
        if actual != wanted:
            raise RuntimeError(f"{service} image differs from env-spec")
    code = "import random; from scapy.all import IP,UDP,Raw,fragment; random.seed(202608281); p=IP(dst='10.80.0.53',id=random.randrange(65536))/UDP()/Raw(b'x'*120); f=fragment(p,fragsize=40); assert len(f)>1 and int(f[1].frag)>0; print('E5_WITNESS',len(f),int(f[1].frag),len(bytes(f[0])))"
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--memory", "128m", "--cpus", "1",
                    "--entrypoint", "python3", expected["resolver"], "-c", code], check=True)
    print("E5_ENV_IMAGES_VERIFIED", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=("sanity", "confirmatory", "all"), default="all")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--witness", action="store_true")
    args = parser.parse_args()
    if args.witness:
        witness()
        return 0
    protocol = json.loads((HERE / "protocol.json").read_text(encoding="utf-8"))
    if args.run_id:
        if Path(args.run_id).name != args.run_id or "/" in args.run_id or "\\" in args.run_id or args.run_id in (".", ".."):
            raise ValueError("run ID must be one directory name")
        protocol["run_id"] = args.run_id
    root = E5 / "output" / protocol["run_id"]
    if root.exists() and not args.resume:
        raise FileExistsError(f"refusing to overwrite {root}")
    if args.resume:
        saved = json.loads((root / "e5_protocol.json").read_text(encoding="utf-8"))
        if saved != protocol:
            raise RuntimeError("protocol changed; use a new run ID")
    else:
        root.mkdir(parents=True, exist_ok=False)
        write_json(root / "e5_protocol.json", protocol)
        write_json(root / "registered.json", {"utc": legacy.utc_now(), "note": "before any new data collection"})
        for stage in ("sanity", "confirmatory"):
            write_json(root / f"schedule_{stage}.json", schedule_for(stage, protocol))
    write_provenance(root, args.resume)
    run(compose_cmd("up", "-d", "--no-build"))
    stages = ("sanity", "confirmatory") if args.stage == "all" else (args.stage,)
    sys.path.insert(0, str(HERE))
    import validate
    for stage in stages:
        destination = root / f"metrics_{stage}.json"
        if destination.exists():
            raise FileExistsError(f"stage already exists: {destination}")
        if stage == "confirmatory":
            gate = json.loads((root / "validation_sanity.json").read_text(encoding="utf-8"))
            if gate["status"] != "PASS":
                raise RuntimeError("sanity integrity gate has not passed")
        rows = []
        jobs = schedule_for(stage, protocol)
        print(f"[e5-supplement] {stage}: {len(jobs)} runs", flush=True)
        try:
            for index, job in enumerate(jobs, 1):
                print(f"[e5-supplement] {stage} {index}/{len(jobs)} starting {job}", flush=True)
                metrics = execute_one(root, job["case_id"], job["rep"], protocol)
                metrics["stage"] = stage
                rows.append(metrics)
                write_json(root / f"metrics_partial_{stage}.json", rows)
                check = validate.validate_run(root, metrics, protocol)
                write_json(root / metrics["artifact_dir"] / "validation.json", check)
                if check["status"] != "PASS":
                    raise RuntimeError(f"per-run integrity failed: {job}; see validation.json")
                if stage == "sanity" and job["case_id"] == "C0_attack_flood_b0" and not metrics["any_poison"]:
                    raise RuntimeError(f"positive control produced no poison: {job}")
            write_json(destination, rows)
            validation = validate.validate_stage(root, stage)
            write_json(root / f"validation_{stage}.json", validation)
            if validation["status"] != "PASS":
                raise RuntimeError(f"{stage} validation failed; see saved validation")
        except Exception as exc:
            write_json(root / "ABORT.json", {"utc": legacy.utc_now(), "stage": stage, "error": repr(exc), "completed_runs": len(rows)})
            legacy.stop_workers()
            raise
    write_json(root / f"finished_{args.stage}.json", {"utc": legacy.utc_now()})
    print(f"[e5-supplement] COMPLETE: {root}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
