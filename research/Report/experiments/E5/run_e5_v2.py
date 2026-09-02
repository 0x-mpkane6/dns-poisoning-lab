#!/usr/bin/env python3
"""Run the registered E5-v2 routed IPS campaign.

The runner deliberately keeps the old E5 tree untouched.  It registers a
source/image snapshot before data collection, recreates the Docker stack for
each cell, and writes raw evidence before deriving any metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import sys
import time
from pathlib import Path
from statistics import fmean
from typing import Any, Iterable

from e5_v2_aggregate import exact_binomial_ci, paired_bootstrap_mean, paired_differences
from e5_v2_analysis import compute_run_metrics
from e5_v2_lib import CONFIRMATORY_POLICIES, WORKLOADS, make_complete_block
from e5_v2_schedule import build_replay_schedule, schedule_digest
from e5_v2_validate import pilot_gate, validate_run


E5_ROOT = Path(__file__).resolve().parent
LAB_ROOT = E5_ROOT / "tools" / "routed_lab"
PROTOCOL_PATH = E5_ROOT / "e5_v2_protocol.json"
OUTPUT_ROOT = E5_ROOT / "output"
DEFAULT_RUN_ID = "E5-v2-routed-s20260902-r001"
STAGE_NAMES = ("pilot", "sanity", "confirmatory")
SERVICE_LOG_DIRS = ("ips", "resolver", "auth", "attacker", "client", "ips_pcap")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_run_id(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError("run ID must be one directory name")
    if not all(char.isalnum() or char in "-_" for char in value):
        raise ValueError("run ID may contain only letters, digits, hyphen, and underscore")
    return value


def load_protocol(run_id: str) -> dict[str, Any]:
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    protocol["run_id"] = run_id
    protocol["protocol_id"] = run_id
    return protocol


def source_guard(root: Path = LAB_ROOT) -> dict[str, Any]:
    """Reject any resolver-local poisoner or an equivalent stale path."""

    errors: list[str] = []
    if not root.exists():
        return {"status": "FAIL", "errors": [f"missing lab root: {root}"]}
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if "poisoner" in path.name.lower():
            errors.append(f"forbidden resolver-local poisoner path: {path.relative_to(root)}")
        if path.suffix.lower() in {".py", ".sh", ".yaml", ".yml", ".json", ".dockerfile"}:
            try:
                text = path.read_text(encoding="utf-8").lower()
            except UnicodeDecodeError:
                continue
            if "poisoner.py" in text or "/poisoner" in text or "\\poisoner" in text:
                errors.append(f"forbidden poisoner reference: {path.relative_to(root)}")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return "missing"
    for path in sorted(path for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def source_files() -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in (
        E5_ROOT / "run_e5_v2.py",
        E5_ROOT / "e5_v2_lib.py",
        E5_ROOT / "e5_v2_schedule.py",
        E5_ROOT / "e5_v2_analysis.py",
        E5_ROOT / "e5_v2_aggregate.py",
        E5_ROOT / "e5_v2_validate.py",
        E5_ROOT / "e5_v2_protocol.json",
    ):
        files[path.relative_to(E5_ROOT).as_posix()] = path
    for path in sorted(LAB_ROOT.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix.lower() not in {".pyc", ".pcap", ".pcapng"}:
            files[f"tools/routed_lab/{path.relative_to(LAB_ROOT).as_posix()}"] = path
    return files


def source_manifest() -> dict[str, Any]:
    return {
        "file_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in source_files().items()},
        "unbound_source_tree_sha256": _tree_digest(LAB_ROOT.parent / "unbound"),
    }


def copy_source_snapshot(root: Path) -> None:
    for name, path in source_files().items():
        destination = root / "source_snapshot" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def docker_info() -> dict[str, Any]:
    proc = subprocess.run(["docker", "info", "--format", "{{json .}}"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "Docker daemon unavailable").strip()
        raise RuntimeError(f"Docker Desktop/daemon is unavailable: {detail}")
    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        info = {"raw": proc.stdout.strip()}
    return {key: info.get(key) for key in ("NCPU", "MemTotal", "KernelVersion", "OperatingSystem", "ServerVersion")}


def project_name(run_id: str) -> str:
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8]
    return f"e5v2-{run_id.lower()[:35]}-{digest}"


def compose_base(run_id: str, env_file: Path, override: Path | None = None) -> list[str]:
    command = [
        "docker",
        "compose",
        "--project-name",
        project_name(run_id),
        "--project-directory",
        str(LAB_ROOT),
        "--env-file",
        str(env_file),
        "-f",
        str(LAB_ROOT / "compose.yaml"),
    ]
    if override is not None:
        command.extend(["-f", str(override)])
    return command


def run_command(command: list[str], *, check: bool = True, capture: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(command), flush=True)
    result = subprocess.run(command, capture_output=capture, text=True, check=False, timeout=timeout)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail[-4000:]}")
    return result


def yaml_quote(value: Path | str) -> str:
    text = str(value).replace("\\", "/").replace("'", "''")
    return f"'{text}'"


def write_runtime_env(path: Path, *, run_id: str, rep: int, policy: str, workload: str) -> None:
    path.write_text(
        "\n".join(
            [
                f"RUN_ID={run_id}",
                f"REP={rep}",
                f"POLICY_MODE={policy}",
                f"WORKLOAD={workload}",
                "COMPOSE_PROJECT_NAME=" + project_name(run_id),
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_compose_override(
    path: Path,
    *,
    log_dirs: dict[str, Path],
    pcap_dir: Path | None = None,
    schedule_path: Path | None = None,
) -> None:
    lines = ["services:"]
    mounts: dict[str, list[tuple[Path, str, bool]]] = {service: [] for service in log_dirs}
    for service, source in log_dirs.items():
        mounts.setdefault(service, []).append((source, "/app/log", False))
    if pcap_dir is not None:
        mounts.setdefault("ips", []).append((pcap_dir, "/app/pcap", False))
    if schedule_path is not None:
        for service in ("resolver", "auth", "attacker", "client"):
            mounts.setdefault(service, []).append((schedule_path, "/app/schedule.json", True))
    for service, service_mounts in mounts.items():
        if not service_mounts:
            continue
        lines.extend([f"  {service}:", "    volumes:"])
        for source, target, read_only in service_mounts:
            lines.extend(
                [
                    "      - type: bind",
                    f"        source: {yaml_quote(source.resolve())}",
                    f"        target: {target}",
                ]
            )
            if read_only:
                lines.append("        read_only: true")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def protocol_policies(protocol: dict[str, Any]) -> list[str]:
    values = protocol.get("policies") or [item.value for item in CONFIRMATORY_POLICIES]
    return [item if isinstance(item, str) else str(item["id"]) for item in values]


def protocol_workloads(protocol: dict[str, Any]) -> list[str]:
    values = protocol.get("workloads") or list(WORKLOADS)
    return [item if isinstance(item, str) else str(item["id"]) for item in values]


def build_stage_jobs(stage: str, protocol: dict[str, Any]) -> list[dict[str, Any]]:
    """Return pilot/sanity/confirmatory jobs in their registered order."""

    seed = int(protocol.get("experiment_seed", protocol.get("schedule", {}).get("experiment_seed", 20260902)))
    policies = protocol_policies(protocol)
    workloads = protocol_workloads(protocol)
    if stage == "pilot":
        stage_config = protocol.get("stages", {}).get("pilot", {})
        cells = stage_config.get("cells", protocol.get("pilot", []))
        return [{"stage": stage, "rep": 0, "policy": str(policy), "workload": str(workload)} for policy, workload in cells]
    if stage == "sanity":
        return [
            {"stage": stage, "rep": 0, "policy": cell.policy, "workload": cell.workload}
            for cell in make_complete_block(rep=0, seed=seed)
        ]
    if stage == "confirmatory":
        runs = int(protocol.get("k_runs_per_cell", protocol.get("stages", {}).get("confirmatory", {}).get("runs_per_cell", 20)))
        jobs: list[dict[str, Any]] = []
        for rep in range(1, runs + 1):
            block = make_complete_block(rep=rep, seed=seed)
            jobs.extend({"stage": stage, "rep": rep, "policy": cell.policy, "workload": cell.workload} for cell in block)
        return jobs
    raise ValueError(f"unknown stage: {stage}")


def _stage_trials(stage: str, protocol: dict[str, Any]) -> int:
    if stage == "pilot":
        return int(protocol.get("stages", {}).get("pilot", {}).get("trials_per_run", 5))
    return int(protocol.get("trials_per_run", protocol.get("schedule", {}).get("trials_per_run", 50)))


def _stage_duration(stage: str, protocol: dict[str, Any]) -> float:
    if stage == "pilot":
        return 20.0
    return float(protocol.get("schedule", {}).get("schedule_duration_seconds", 120.0))


def schedule_for_cell(root: Path, protocol: dict[str, Any], job: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    stage = job["stage"]
    rep = int(job["rep"])
    workload = str(job["workload"])
    destination = root / "schedules" / stage / f"rep_{rep:02d}" / f"{workload}.json"
    schedule = build_replay_schedule(
        run_id=str(protocol["run_id"]),
        rep=rep,
        workload=workload,
        seed=int(protocol.get("experiment_seed", protocol.get("schedule", {}).get("experiment_seed", 20260902))),
        trials=_stage_trials(stage, protocol),
        duration_s=_stage_duration(stage, protocol),
    )
    expected_digest = schedule_digest(schedule)
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if schedule_digest(existing) != expected_digest:
            raise RuntimeError(f"registered schedule changed: {destination}")
    else:
        write_json(destination, schedule)
    return schedule, destination


def _wait_file(path: Path, timeout_s: float, description: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}: {path}")


def _service_dirs(cell_dir: Path) -> dict[str, Path]:
    result = {}
    for name in SERVICE_LOG_DIRS:
        result[name] = cell_dir / name
        result[name].mkdir(parents=True, exist_ok=True)
    return result


def _flatten_artifacts(cell_dir: Path) -> None:
    mappings = {
        "client/trials.jsonl": "trials.jsonl",
        "client/client_events.jsonl": "client_events.jsonl",
        "auth/auth_events.jsonl": "auth_events.jsonl",
        "attacker/attacker_events.jsonl": "attacker_events.jsonl",
        "ips/ips_events.jsonl": "ips_events.jsonl",
        "ips/detector_state.json": "detector_state.json",
        "ips/ips_ready.json": "ips_ready.json",
        "ips/interfaces.json": "interfaces.json",
        "ips/firewall_before.rules": "firewall_before.rules",
        "ips/firewall_after.rules": "firewall_after.rules",
        "ips/routes_before.txt": "routes_before.txt",
        "ips/routes_after.txt": "routes_after.txt",
        "ips/ip_forward_before.txt": "ip_forward_before.txt",
        "ips/ip_forward_after.txt": "ip_forward_after.txt",
        "ips/nfqueue_preflight.json": "nfqueue_preflight.json",
        "resolver/unbound_events.jsonl": "unbound_events.jsonl",
        "resolver/cache_events.jsonl": "cache_events.jsonl",
        "resolver/resolver_ready.json": "resolver_ready.json",
        "resolver/unbound_version.txt": "unbound_version.txt",
    }
    for source_name, destination_name in mappings.items():
        source = cell_dir / source_name
        destination = cell_dir / destination_name
        if source.exists():
            shutil.copy2(source, destination)
    pcap = cell_dir / "ips_pcap"
    for name in ("ips_inside.pcapng", "ips_outside.pcapng"):
        source = pcap / name
        if source.exists():
            shutil.copy2(source, cell_dir / name)


def _container_stats(command: list[str]) -> str:
    ids_result = run_command(command + ["ps", "-q"], check=False)
    ids = [line.strip() for line in ids_result.stdout.splitlines() if line.strip()]
    if not ids:
        return ""
    stats = run_command(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], check=False)
    return (stats.stdout or "") + (stats.stderr or "")


def _stop_stack(command: list[str]) -> None:
    run_command(command + ["exec", "-T", "ips", "/app/snapshot.sh", "before_stop"], check=False)
    run_command(command + ["logs", "--no-color"], check=False)
    run_command(command + ["down", "--volumes", "--remove-orphans"], check=False, timeout=60)


def run_cell(root: Path, protocol: dict[str, Any], job: dict[str, Any], schedule: dict[str, Any], schedule_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    stage = str(job["stage"])
    rep = int(job["rep"])
    policy = str(job["policy"])
    workload = str(job["workload"])
    cell_dir = root / "raw" / stage / f"rep_{rep:02d}" / f"{policy}__{workload}"
    if cell_dir.exists():
        raise FileExistsError(f"refusing to overwrite cell: {cell_dir}")
    cell_dir.mkdir(parents=True, exist_ok=False)
    dirs = _service_dirs(cell_dir)
    cell_schedule = cell_dir / "schedule.json"
    write_json(cell_schedule, schedule)
    env_file = cell_dir / "runtime.env"
    write_runtime_env(env_file, run_id=str(protocol["run_id"]), rep=rep, policy=policy, workload=workload)
    override = cell_dir / "compose.override.yaml"
    write_compose_override(override, log_dirs={name: dirs[name] for name in ("ips", "resolver", "auth", "attacker", "client")}, pcap_dir=dirs["ips_pcap"], schedule_path=cell_schedule)
    command = compose_base(str(protocol["run_id"]), env_file, override)
    expected_trials = len(schedule["trials"])
    client_proc: subprocess.CompletedProcess[str] | None = None
    client_error: str | None = None
    stack_started = False
    started_ns = time.monotonic_ns()
    try:
        run_command(command + ["up", "-d", "--no-build"], timeout=90)
        stack_started = True
        _wait_file(dirs["ips"] / "ips_ready.json", 30, "IPS NFQUEUE readiness")
        _wait_file(dirs["resolver"] / "resolver_ready.json", 45, "Unbound readiness")
        _wait_file(dirs["auth"] / "auth_events.jsonl", 30, "authoritative UDP/TCP readiness")
        _wait_file(dirs["attacker"] / "attacker_events.jsonl", 30, "external attacker readiness")
        try:
            client_proc = run_command(
                command + ["exec", "-T", "client", "python3", "/app/probe.py"],
                check=False,
                timeout=max(180.0, expected_trials * 6.0),
            )
        except subprocess.TimeoutExpired as exc:
            client_error = f"client timeout: {exc}"
    finally:
        if client_proc is not None:
            (cell_dir / "client_stdout.txt").write_text(client_proc.stdout or "", encoding="utf-8")
            (cell_dir / "client_stderr.txt").write_text(client_proc.stderr or "", encoding="utf-8")
        if client_error:
            (cell_dir / "client_error.txt").write_text(client_error + "\n", encoding="utf-8")
        (cell_dir / "resource_samples.jsonl").write_text(_container_stats(command), encoding="utf-8")
        if stack_started:
            _stop_stack(command)
    _flatten_artifacts(cell_dir)
    if client_proc is None and client_error is None:
        raise RuntimeError(f"client did not run for {cell_dir}")
    metrics = compute_run_metrics(cell_dir, expected_trials=expected_trials)
    metrics.update(
        {
            "stage": stage,
            "run_id": protocol["run_id"],
            "rep": rep,
            "policy": policy,
            "workload": workload,
            "schedule_sha256": schedule_digest(schedule),
            "client_exit_code": client_proc.returncode if client_proc is not None else None,
            "client_error": client_error,
            "wall_duration_s": (time.monotonic_ns() - started_ns) / 1_000_000_000.0,
            "artifact_dir": str(cell_dir.relative_to(root)).replace("\\", "/"),
        }
    )
    write_json(cell_dir / "metrics.json", metrics)
    expected = {"run_id": protocol["run_id"], "rep": rep, "policy": policy, "workload": workload}
    validation = validate_run(
        cell_dir,
        expected=expected,
        expected_qnames=[row["qname"] for row in schedule["trials"]],
        expected_trials=expected_trials,
        require_pcap=True,
    )
    write_json(cell_dir / "validation.json", validation)
    return metrics, validation


def _compose_image_names(run_id: str, env_file: Path) -> list[str]:
    command = compose_base(run_id, env_file)
    result = run_command(command + ["config", "--images"])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def _image_ids(image_names: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in image_names:
        inspected = run_command(["docker", "image", "inspect", name, "--format", "{{.Id}}"], check=False)
        if inspected.returncode == 0 and inspected.stdout.strip():
            result[name] = inspected.stdout.strip()
    return result


def _ensure_source_guard() -> None:
    guard = source_guard(LAB_ROOT)
    if guard["status"] != "PASS":
        raise RuntimeError("E5-v2 source guard failed:\n" + "\n".join(guard["errors"]))


def _preflight_stack(root: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    """Start only the IPS/resolver pair and prove a routed NFQUEUE counter."""

    preflight = root / "preflight"
    dirs = _service_dirs(preflight)
    env_file = preflight / "runtime.env"
    write_runtime_env(env_file, run_id=str(protocol["run_id"]), rep=0, policy="B0_OFF", workload="PREFLIGHT")
    override = preflight / "compose.override.yaml"
    write_compose_override(override, log_dirs={"ips": dirs["ips"]}, pcap_dir=dirs["ips_pcap"])
    command = compose_base(str(protocol["run_id"]), env_file, override)
    started = False
    try:
        run_command(command + ["up", "-d", "--no-build", "ips", "resolver"], timeout=90)
        started = True
        _wait_file(dirs["ips"] / "ips_ready.json", 30, "IPS NFQUEUE readiness")
        smoke = run_command(command + ["run", "--rm", "--no-deps", "attacker", "python3", "/app/smoke.py"], timeout=30)
        (preflight / "smoke.stdout").write_text(smoke.stdout or "", encoding="utf-8")
        (preflight / "smoke.stderr").write_text(smoke.stderr or "", encoding="utf-8")
        run_command(command + ["exec", "-T", "ips", "/app/snapshot.sh", "preflight_after"], check=False)
        _flatten_artifacts(preflight)
        firewall = preflight / "ips" / "firewall_preflight_after.rules"
        if not firewall.exists():
            raise RuntimeError("NFQUEUE preflight did not produce firewall counter evidence")
        firewall_text = firewall.read_text(encoding="utf-8", errors="replace")
        if "NFQUEUE" not in firewall_text or not any(int(value) > 0 for value in __import__("re").findall(r"\[(\d+):\d+\]", firewall_text)):
            raise RuntimeError("NFQUEUE preflight packet counter did not increase")
        result = {
            "status": "PASS",
            "smoke": (smoke.stdout or "").strip(),
            "firewall": firewall_text,
            "ips_ready": json.loads((preflight / "ips" / "ips_ready.json").read_text(encoding="utf-8")),
        }
        write_json(root / "preflight.json", result)
        return result
    finally:
        if started:
            _stop_stack(command)


def prepare_registration(root: Path, protocol: dict[str, Any]) -> None:
    if root.exists():
        raise FileExistsError(f"refusing to overwrite registered output: {root}")
    _ensure_source_guard()
    root.mkdir(parents=True, exist_ok=False)
    write_json(root / "e5_v2_protocol.json", protocol)
    runtime_env = root / "registration.env"
    write_runtime_env(runtime_env, run_id=str(protocol["run_id"]), rep=0, policy="B0_OFF", workload="REGISTRATION")
    compose = compose_base(str(protocol["run_id"]), runtime_env)
    run_command(compose + ["config", "--quiet"], timeout=60)
    print("[e5-v2] building frozen images", flush=True)
    run_command(compose + ["build"], capture=False, timeout=1800)
    image_names = _compose_image_names(str(protocol["run_id"]), runtime_env)
    image_hashes = _image_ids(image_names)
    if len(image_hashes) != len(image_names):
        missing = sorted(set(image_names) - set(image_hashes))
        raise RuntimeError(f"could not resolve built image IDs: {missing}")
    copy_source_snapshot(root)
    manifest = source_manifest()
    write_json(
        root / "registered.json",
        {
            "schema_version": 1,
            "run_id": protocol["run_id"],
            "registered_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "protocol_sha256": hashlib.sha256(json.dumps(protocol, sort_keys=True).encode("utf-8")).hexdigest(),
            "source_manifest": manifest,
            "image_names": image_names,
            "image_ids": image_hashes,
            "docker": docker_info(),
            "command": sys.argv,
            "python": sys.version,
        },
    )
    print("[e5-v2] registration frozen; running NFQUEUE/routing preflight", flush=True)
    _preflight_stack(root, protocol)


def ensure_registered(root: Path, protocol: dict[str, Any]) -> None:
    _ensure_source_guard()
    if not (root / "registered.json").exists() or not (root / "e5_v2_protocol.json").exists():
        raise RuntimeError(f"no frozen registration found at {root}; run --stage preflight first")
    saved_protocol = json.loads((root / "e5_v2_protocol.json").read_text(encoding="utf-8"))
    if saved_protocol != protocol:
        raise RuntimeError("protocol differs from the registered output; use a new run ID")
    registered = json.loads((root / "registered.json").read_text(encoding="utf-8"))
    if registered.get("source_manifest") != source_manifest():
        raise RuntimeError("source or configuration changed after registration; use a new run ID")
    for image_name, expected_id in registered.get("image_ids", {}).items():
        current = run_command(["docker", "image", "inspect", image_name, "--format", "{{.Id}}"], check=False)
        if current.returncode != 0 or current.stdout.strip() != expected_id:
            raise RuntimeError(f"frozen image changed: {image_name}; use a new run ID")
    if not (root / "preflight.json").exists() or json.loads((root / "preflight.json").read_text(encoding="utf-8")).get("status") != "PASS":
        raise RuntimeError("NFQUEUE/routing preflight is not PASS")


def aggregate_confirmatory(rows: list[dict[str, Any]], protocol: dict[str, Any]) -> dict[str, Any]:
    policies = protocol_policies(protocol)
    workloads = protocol_workloads(protocol)
    output: dict[str, Any] = {"schema_version": 1, "n_runs": len(rows), "groups": {}, "paired": {}}
    for policy in policies:
        for workload in workloads:
            group = [row for row in rows if row.get("policy") == policy and row.get("workload") == workload]
            key = f"{policy}__{workload}"
            attack = workload.startswith("ATTACK_")
            any_success = sum(bool(row.get("any_poison")) for row in group)
            first_success = sum(bool(row.get("first_trial_poison")) for row in group)
            entry: dict[str, Any] = {
                "policy": policy,
                "workload": workload,
                "runs": len(group),
                "any_poison_runs": any_success,
                "any_poison_rate": any_success / len(group) if group else None,
                "any_poison_ci95": list(exact_binomial_ci(any_success, len(group))) if group else None,
                "first_trial_poison_runs": first_success,
                "first_trial_poison_ci95": list(exact_binomial_ci(first_success, len(group))) if group else None,
                "mean_run_asr": fmean(row["run_asr"] for row in group) if attack and group else None,
                "mean_legitimate_answer_rate": fmean(row["legitimate_answer_rate"] for row in group) if group else None,
                "mean_noanswer_rate": fmean(row["noanswer_rate"] for row in group) if group else None,
                "mean_trigger_rate": fmean(row["trigger_rate"] for row in group) if group else None,
                "mean_forged_tail_drop_rate": fmean(row["forged_tail_drop_rate"] for row in group) if group else None,
                "mean_tc_injection_rate": fmean(row["tc_injection_rate"] for row in group) if group else None,
                "mean_tcp_retry_rate": fmean(row["tcp_retry_rate"] for row in group) if group else None,
            }
            output["groups"][key] = entry
    seed = int(protocol.get("experiment_seed", 20260902))
    for policy in policies:
        if policy == "B0_OFF":
            continue
        for workload in workloads:
            metric = "run_asr" if workload.startswith("ATTACK_") else "legitimate_answer_rate"
            differences = paired_differences(rows, target_policy=policy, baseline_policy="B0_OFF", workload=workload, metric=metric)
            if differences:
                output["paired"][f"{policy}_vs_B0_OFF__{workload}__{metric}"] = paired_bootstrap_mean(
                    differences, replicates=5000, seed=seed + sum(ord(char) for char in policy + workload)
                )
    return output


def run_stage(root: Path, protocol: dict[str, Any], stage: str) -> list[dict[str, Any]]:
    if stage not in STAGE_NAMES:
        raise ValueError(stage)
    if stage == "confirmatory":
        sanity_validation = root / "validation_sanity.json"
        if not sanity_validation.exists() or json.loads(sanity_validation.read_text(encoding="utf-8")).get("status") != "PASS":
            raise RuntimeError("confirmatory campaign is locked behind a PASS sanity gate")
    jobs = build_stage_jobs(stage, protocol)
    rows: list[dict[str, Any]] = []
    partial_path = root / f"metrics_{stage}_partial.json"
    for index, job in enumerate(jobs, 1):
        print(f"[e5-v2] {stage} {index}/{len(jobs)}: {job}", flush=True)
        schedule, schedule_path = schedule_for_cell(root, protocol, job)
        metrics, validation = run_cell(root, protocol, job, schedule, schedule_path)
        metrics["job_index"] = index
        rows.append(metrics)
        write_json(partial_path, rows)
        if validation.get("status") != "PASS":
            raise RuntimeError(f"integrity validation failed for {job}: {validation.get('errors')}")
        if stage == "pilot":
            gate = pilot_gate(metrics, policy=str(job["policy"]), workload=str(job["workload"]))
            write_json(root / "raw" / stage / "rep_00" / f"{job['policy']}__{job['workload']}" / "pilot_gate.json", gate)
            if gate["status"] != "PASS":
                raise RuntimeError(f"pilot engineering gate failed for {job}: {gate['errors']}")
    write_json(root / f"metrics_{stage}.json", rows)
    stage_validation = {
        "schema_version": 1,
        "stage": stage,
        "status": "PASS" if len(rows) == len(jobs) else "FAIL",
        "expected_runs": len(jobs),
        "completed_runs": len(rows),
        "errors": [] if len(rows) == len(jobs) else ["not all registered jobs completed"],
    }
    write_json(root / f"validation_{stage}.json", stage_validation)
    if stage == "confirmatory":
        write_json(root / "aggregate_confirmatory.json", aggregate_confirmatory(rows, protocol))
    print(f"[e5-v2] {stage} PASS ({len(rows)} runs)", flush=True)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("preflight", "pilot", "sanity", "confirmatory", "all"), default="preflight")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--dry-run", action="store_true", help="print the registered job matrix without Docker")
    args = parser.parse_args(argv)
    run_id = safe_run_id(args.run_id)
    protocol = load_protocol(run_id)
    root = OUTPUT_ROOT / run_id
    if args.dry_run:
        if args.stage == "preflight":
            print(json.dumps({"stage": "preflight", "run_id": run_id}, indent=2))
            return 0
        print(json.dumps(build_stage_jobs(args.stage if args.stage != "all" else "confirmatory", protocol), indent=2))
        return 0

    stages: list[str]
    if args.stage == "all":
        stages = ["pilot", "sanity", "confirmatory"]
        docker_info()
        prepare_registration(root, protocol)
    elif args.stage == "preflight":
        docker_info()
        prepare_registration(root, protocol)
        print(f"[e5-v2] registered output: {root}", flush=True)
        return 0
    else:
        ensure_registered(root, protocol)
        stages = [args.stage]

    for stage in stages:
        ensure_registered(root, protocol)
        run_stage(root, protocol, stage)
    write_json(root / "finished.json", {"run_id": run_id, "stages": stages, "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    print(f"[e5-v2] COMPLETE: {root}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"[e5-v2] ABORTED: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2) from exc
