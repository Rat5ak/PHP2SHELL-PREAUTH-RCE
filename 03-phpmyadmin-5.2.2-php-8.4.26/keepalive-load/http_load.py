#!/usr/bin/env python3
"""Bounded HTTP load generator for owned loopback/RFC1918 lab targets.

This helper deliberately contains no exploit logic.  It sends ordinary GET or
HEAD requests with ``Connection: close`` and reports aggregate transport and
latency statistics as one JSON document on stdout.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit


PRIVATE_V4 = tuple(
    ipaddress.ip_network(value)
    for value in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MAX_CONCURRENCY = 256
MAX_DURATION_SECONDS = 3600.0
MAX_LATENCY_SAMPLES = 10_000
MAX_RESPONSE_BYTES = 1 << 20


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def require_private_ipv4(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("URL host must be a literal loopback/RFC1918 IPv4 address") from exc
    if address.version != 4 or not any(address in network for network in PRIVATE_V4):
        raise ValueError(f"refusing non-private target address: {address}")
    return str(address)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


class Statistics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.attempts = 0
        self.responses = 0
        self.statuses: Counter[int] = Counter()
        self.errors: Counter[str] = Counter()
        self.latency_count = 0
        self.latency_sum_ms = 0.0
        self.latency_min_ms: float | None = None
        self.latency_max_ms: float | None = None
        self.samples_ms: list[float] = []

    def begin(self) -> None:
        with self.lock:
            self.attempts += 1

    def response(self, status: int, elapsed_ms: float) -> None:
        with self.lock:
            self.responses += 1
            self.statuses[status] += 1
            self._latency(elapsed_ms)

    def error(self, exc: BaseException, elapsed_ms: float) -> None:
        label = type(exc).__name__
        with self.lock:
            self.errors[label] += 1
            self._latency(elapsed_ms)

    def _latency(self, elapsed_ms: float) -> None:
        self.latency_count += 1
        self.latency_sum_ms += elapsed_ms
        self.latency_min_ms = (
            elapsed_ms if self.latency_min_ms is None else min(self.latency_min_ms, elapsed_ms)
        )
        self.latency_max_ms = (
            elapsed_ms if self.latency_max_ms is None else max(self.latency_max_ms, elapsed_ms)
        )
        # A bounded deterministic sample is sufficient for comparative p50/p95
        # reporting without unbounded memory use in stop-file mode.
        if len(self.samples_ms) < MAX_LATENCY_SAMPLES:
            self.samples_ms.append(elapsed_ms)
        else:
            self.samples_ms[self.latency_count % MAX_LATENCY_SAMPLES] = elapsed_ms

    def document(self, elapsed_seconds: float) -> dict[str, object]:
        with self.lock:
            samples = list(self.samples_ms)
            mean = (
                self.latency_sum_ms / self.latency_count if self.latency_count else None
            )
            return {
                "attempts": self.attempts,
                "http_responses": self.responses,
                "http_2xx": sum(
                    count for status, count in self.statuses.items() if 200 <= status < 300
                ),
                "status_counts": {
                    str(status): count for status, count in sorted(self.statuses.items())
                },
                "transport_errors": sum(self.errors.values()),
                "error_counts": dict(sorted(self.errors.items())),
                "request_rate_per_second": (
                    self.attempts / elapsed_seconds if elapsed_seconds > 0 else 0.0
                ),
                "latency_ms": {
                    "count": self.latency_count,
                    "sample_count": len(samples),
                    "min": self.latency_min_ms,
                    "mean": mean,
                    "p50": percentile(samples, 0.50),
                    "p95": percentile(samples, 0.95),
                    "max": self.latency_max_ms,
                },
            }


def atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate bounded ordinary HTTP load against a private local lab target."
    )
    parser.add_argument("url", help="http:// literal loopback/RFC1918 IPv4 endpoint")
    parser.add_argument("--concurrency", type=int, required=True)
    stop = parser.add_mutually_exclusive_group(required=True)
    stop.add_argument("--duration", type=float, help="run duration in seconds (maximum 3600)")
    stop.add_argument("--stop-file", type=Path, help="stop when this initially absent file appears")
    parser.add_argument("--path", help="request path override; defaults to URL path/query")
    parser.add_argument("--method", choices=("GET", "HEAD"), default="GET")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--interval",
        type=float,
        default=0.0,
        help="per-worker delay after each request (default: 0)",
    )
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument(
        "--max-runtime",
        type=float,
        default=MAX_DURATION_SECONDS,
        help="hard safety bound for stop-file mode (default: 3600 seconds)",
    )
    args = parser.parse_args()

    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        parser.error(f"--concurrency must be within 1..{MAX_CONCURRENCY}")
    if not 0.05 <= args.timeout <= 120.0:
        parser.error("--timeout must be within 0.05..120 seconds")
    if not 0.0 <= args.interval <= 60.0:
        parser.error("--interval must be within 0..60 seconds")
    if args.duration is not None and not 0.1 <= args.duration <= MAX_DURATION_SECONDS:
        parser.error(f"--duration must be within 0.1..{MAX_DURATION_SECONDS:g} seconds")
    if not 1.0 <= args.max_runtime <= MAX_DURATION_SECONDS:
        parser.error(f"--max-runtime must be within 1..{MAX_DURATION_SECONDS:g} seconds")
    if args.stop_file is not None and args.stop_file.exists():
        parser.error("--stop-file must be absent at startup")
    return args


def main() -> int:
    args = parse_args()
    parsed = urlsplit(args.url)
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ValueError("only unauthenticated http:// URLs are accepted")
    host = require_private_ipv4(parsed.hostname or "")
    port = parsed.port or 80
    if not 1 <= port <= 65535:
        raise ValueError("invalid target port")

    target = args.path
    if target is None:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
    if not target.startswith("/") or "\r" in target or "\n" in target:
        raise ValueError("request path must begin with '/' and contain no CR/LF")

    statistics = Statistics()
    stop_event = threading.Event()
    reason_lock = threading.Lock()
    stop_reason = {"value": "unknown"}
    started_monotonic = time.monotonic()
    started_utc = utc_now()
    deadline = (
        started_monotonic + args.duration
        if args.duration is not None
        else started_monotonic + args.max_runtime
    )

    def request_stop(reason: str) -> None:
        with reason_lock:
            if not stop_event.is_set():
                stop_reason["value"] = reason
                stop_event.set()

    def signal_stop(signum: int, _frame: object) -> None:
        request_stop(f"signal_{signum}")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, signal_stop)
        except (AttributeError, ValueError):
            pass

    host_header = host if port == 80 else f"{host}:{port}"

    def worker() -> None:
        while not stop_event.is_set():
            statistics.begin()
            before = time.monotonic()
            connection = http.client.HTTPConnection(host, port, timeout=args.timeout)
            try:
                connection.request(
                    args.method,
                    target,
                    headers={
                        "Host": host_header,
                        "User-Agent": "q618-local-load/1",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                if args.method != "HEAD":
                    response.read(MAX_RESPONSE_BYTES)
                elapsed_ms = (time.monotonic() - before) * 1000.0
                statistics.response(response.status, elapsed_ms)
            except (OSError, TimeoutError, http.client.HTTPException) as exc:
                elapsed_ms = (time.monotonic() - before) * 1000.0
                statistics.error(exc, elapsed_ms)
            finally:
                connection.close()
            if args.interval and stop_event.wait(args.interval):
                return

    threads = [
        threading.Thread(target=worker, name=f"http-load-{index}")
        for index in range(args.concurrency)
    ]
    for thread in threads:
        thread.start()

    ready_document = {
        "status": "ready",
        "pid": os.getpid(),
        "started_utc": started_utc,
        "url": args.url,
        "target": target,
        "method": args.method,
        "concurrency": args.concurrency,
        "interval_seconds": args.interval,
    }
    if args.ready_file is not None:
        atomic_json(args.ready_file.resolve(), ready_document)

    try:
        while not stop_event.wait(0.1):
            now = time.monotonic()
            if args.stop_file is not None and args.stop_file.exists():
                request_stop("stop_file")
            elif now >= deadline:
                request_stop("duration" if args.duration is not None else "max_runtime")
    finally:
        stop_event.set()
        for thread in threads:
            thread.join(timeout=args.timeout + 1.0)

    ended_utc = utc_now()
    elapsed_seconds = time.monotonic() - started_monotonic
    document: dict[str, object] = {
        "status": "complete",
        "started_utc": started_utc,
        "ended_utc": ended_utc,
        "elapsed_seconds": elapsed_seconds,
        "stop_reason": stop_reason["value"],
        "target": {
            "url": args.url,
            "resolved_private_ipv4": host,
            "port": port,
            "path": target,
            "method": args.method,
        },
        "concurrency": args.concurrency,
        "timeout_seconds": args.timeout,
        "interval_seconds": args.interval,
    }
    document.update(statistics.document(elapsed_seconds))

    if args.ready_file is not None:
        atomic_json(args.ready_file.resolve(), document)
    print(json.dumps(document, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
