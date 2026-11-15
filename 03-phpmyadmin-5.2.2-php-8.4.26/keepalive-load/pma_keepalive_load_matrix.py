#!/usr/bin/env python3
"""Run the proven retained-socket profile under ordinary concurrent GET load."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
CHAIN = HERE / "pma_keepalive_chain.py"
LOAD = HERE / "http_load.py"
EXPECTED_CHAIN_SHA256 = (
    "977e50f80df67eb892dfcf82e1c80ccf877771606c425659e5cf870ed6628f2c"
)
EXPECTED_LOAD_SHA256 = (
    "9e9140b9fe6dd776ae35c4bf88b8ddd9789c0449000142529090e532491648b8"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tiers", default="1,5")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--prefix", default="D")
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    tiers = [int(value) for value in args.tiers.split(",")]
    if not tiers or any(value < 1 or value > 50 for value in tiers):
        parser.error("--tiers must contain concurrency values within 1..50")
    if not 1 <= args.rounds <= 5:
        parser.error("--rounds must be within 1..5")
    if len(args.prefix) != 1 or not args.prefix.isascii() or not args.prefix.isalpha():
        parser.error("--prefix must be one ASCII letter")
    if not 0 <= args.interval <= 5:
        parser.error("--interval must be within 0..5")
    if sha256(CHAIN) != EXPECTED_CHAIN_SHA256:
        raise RuntimeError("refusing an unpinned combined chain driver")
    if sha256(LOAD) != EXPECTED_LOAD_SHA256:
        raise RuntimeError("refusing an unpinned load helper")

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    summary: dict[str, object] = {
        "schema": "q618-pma-keepalive-load-matrix-v1",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "target": "http://127.0.0.1:18212",
        "chain": str(CHAIN),
        "chain_sha256": EXPECTED_CHAIN_SHA256,
        "load_helper": str(LOAD),
        "load_helper_sha256": EXPECTED_LOAD_SHA256,
        "tiers": tiers,
        "rounds": args.rounds,
        "marker_prefix": args.prefix.upper(),
        "interval_seconds": args.interval,
        "cases": [],
        "status": "running",
    }
    summary_path = out / "summary.json"
    atomic_json(summary_path, summary)
    all_pass = True

    for tier in tiers:
        for round_number in range(1, args.rounds + 1):
            case_dir = out / f"tier-{tier:02d}-round-{round_number:02d}"
            case_dir.mkdir()
            stop_file = case_dir / "load.stop"
            ready_file = case_dir / "load.ready.json"
            marker = f"{args.prefix.upper()}{tier:X}{round_number:X}"
            command = f"printf {marker}>{marker.lower()}"
            if len(marker) != 3 or len(command.encode()) != 14:
                raise RuntimeError("marker encoding exceeded exact Fire command budget")
            load_argv = [
                sys.executable,
                str(LOAD),
                "http://127.0.0.1:18212",
                "--concurrency", str(tier),
                "--stop-file", str(stop_file),
                "--path", "/",
                "--method", "GET",
                "--timeout", "5",
                "--interval", str(args.interval),
                "--ready-file", str(ready_file),
                "--max-runtime", "300",
            ]
            load_process = subprocess.Popen(
                load_argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            ready_deadline = time.monotonic() + 30.0
            while not ready_file.exists() and time.monotonic() < ready_deadline:
                if load_process.poll() is not None:
                    break
                time.sleep(0.02)
            if not ready_file.exists():
                stdout, stderr = load_process.communicate(timeout=10)
                (case_dir / "load.stdout.txt").write_text(stdout, encoding="utf-8")
                (case_dir / "load.stderr.txt").write_text(stderr, encoding="utf-8")
                case = {
                    "tier": tier,
                    "round": round_number,
                    "status": "load_not_ready",
                    "load_exit_code": load_process.returncode,
                }
                cases = summary["cases"]
                assert isinstance(cases, list)
                cases.append(case)
                all_pass = False
                atomic_json(summary_path, summary)
                continue
            ready = json.loads(ready_file.read_text(encoding="utf-8"))
            atomic_json(case_dir / "load.ready.snapshot.json", ready)
            time.sleep(0.5)

            chain_dir = case_dir / "chain"
            chain_argv = [
                sys.executable,
                str(CHAIN),
                "--ack-exact-profile",
                "--stock-live-profile",
                "--cmd", command,
                "--fetch", "/" + marker.lower(),
                "--expect", marker,
                "--attempts", "3",
                "--out", str(chain_dir),
            ]
            print(f"tier={tier} round={round_number} marker={marker}", flush=True)
            try:
                chain_completed = subprocess.run(
                    chain_argv, capture_output=True, text=True, timeout=300
                )
            finally:
                stop_file.touch(exist_ok=False)
            load_stdout, load_stderr = load_process.communicate(timeout=20)
            (case_dir / "load.stdout.txt").write_text(load_stdout, encoding="utf-8")
            (case_dir / "load.stderr.txt").write_text(load_stderr, encoding="utf-8")
            (case_dir / "chain.stdout.txt").write_text(
                chain_completed.stdout, encoding="utf-8"
            )
            (case_dir / "chain.stderr.txt").write_text(
                chain_completed.stderr, encoding="utf-8"
            )
            load_final = json.loads(ready_file.read_text(encoding="utf-8"))
            chain_receipt_path = chain_dir / "receipt.json"
            chain_receipt = (
                json.loads(chain_receipt_path.read_text(encoding="utf-8"))
                if chain_receipt_path.exists()
                else {}
            )
            passed = (
                chain_completed.returncode == 0
                and chain_receipt.get("status") == "rce_proved"
                and chain_receipt.get("proof_fresh") is True
                and chain_receipt.get("same_socket_all_four_proved") is True
                and chain_receipt.get("target_healthy_after") is True
                and load_process.returncode == 0
                and load_final.get("status") == "complete"
                and load_final.get("stop_reason") == "stop_file"
                and int(load_final.get("attempts", 0)) > 0
                and int(load_final.get("http_responses", 0)) > 0
            )
            case = {
                "tier": tier,
                "round": round_number,
                "marker": marker,
                "status": "pass" if passed else "fail",
                "chain_exit_code": chain_completed.returncode,
                "chain_status": chain_receipt.get("status", "missing_receipt"),
                "chain_receipt": str(chain_receipt_path),
                "chain_receipt_sha256": (
                    sha256(chain_receipt_path) if chain_receipt_path.exists() else None
                ),
                "proof_fresh": chain_receipt.get("proof_fresh", False),
                "same_socket_all_four": chain_receipt.get(
                    "same_socket_all_four_proved", False
                ),
                "target_healthy_after": chain_receipt.get("target_healthy_after"),
                "load_exit_code": load_process.returncode,
                "load_started_utc": load_final.get("started_utc"),
                "load_ended_utc": load_final.get("ended_utc"),
                "load_attempts": load_final.get("attempts"),
                "load_http_responses": load_final.get("http_responses"),
                "load_http_2xx": load_final.get("http_2xx"),
                "load_transport_errors": load_final.get("transport_errors"),
                "load_status_counts": load_final.get("status_counts"),
                "load_request_rate_per_second": load_final.get(
                    "request_rate_per_second"
                ),
                "load_final_sha256": sha256(ready_file),
            }
            cases = summary["cases"]
            assert isinstance(cases, list)
            cases.append(case)
            if not passed:
                all_pass = False
            atomic_json(summary_path, summary)

    summary["status"] = "pass" if all_pass else "fail"
    summary["ended_utc"] = datetime.now(timezone.utc).isoformat()
    atomic_json(summary_path, summary)
    print(json.dumps(summary, indent=2))
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
