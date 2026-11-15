#!/usr/bin/env python3
"""Offline verifier for the retained-socket phpMyAdmin load evidence.

The verifier is intentionally self-contained and performs no network, Docker,
WSL, process, or target operations.  It binds the frozen source files and
receipts through ``PMA-KEEPALIVE-SHA256SUMS.txt``, then recalculates the
no-load positive, all six loaded positives, and the PHP 8.4.27 denial.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
EVIDENCE_NAME = "keepalive-load-20261025"
_repo_root = HERE.parent.parent
_flat_root = HERE.parent
if (_repo_root / "evidence" / EVIDENCE_NAME).is_dir():
    BUNDLE_ROOT = _repo_root
elif (_flat_root / "evidence" / EVIDENCE_NAME).is_dir():
    BUNDLE_ROOT = _flat_root
else:
    raise RuntimeError("could not resolve repository or flat archive evidence layout")
EVIDENCE = BUNDLE_ROOT / "evidence" / EVIDENCE_NAME
MANIFEST = EVIDENCE / "PMA-KEEPALIVE-SHA256SUMS.txt"
NO_LOAD = EVIDENCE / "pma-keepalive-chain-stock-live-20261025-1910"
FIXED = EVIDENCE / "pma-keepalive-chain-fixed-8427-control-20261025-1925"
MATRIX = EVIDENCE / "pma-keepalive-stock-live-load-1-5-3rounds-20261025-1930"
RESTART = EVIDENCE / "pma-functional-stock-restart-20261025-180118.json"

SOURCE_HASHES = {
    "pma_keepalive_chain.py": "977e50f80df67eb892dfcf82e1c80ccf877771606c425659e5cf870ed6628f2c",
    "pma_keepalive_leak.py": "30d581a068a2addbc04dc1776847b63cb4c2034c2459a364386d67eb6f36bdca",
    "pma_keepalive_fire.py": "28797042245d4738376e4b44f445287ddf60f759a0a0bb8d03c937b829407932",
    "pma_keepalive_load_matrix.py": "b5061db358ccc52674503e404c5c78e1fa35342644fff59de0f692a55f3ee658",
    "http_load.py": "9e9140b9fe6dd776ae35c4bf88b8ddd9789c0449000142529090e532491648b8",
    "KEEPALIVE-STOCK-LIVE-RESULTS-20261025.md": "fcf01c660663881e2683291a31780eaae3e42ae7258e3958850028d0ee282e78",
}
SOURCE_PATHS = {
    name: (EVIDENCE / name if name.endswith(".md") else HERE / name)
    for name in SOURCE_HASHES
}
NO_LOAD_SHA256 = "d9334aed012a48d7e91d558b3be78db3a14e0daf68c03daad7fbe8edf91ef30b"
FIXED_SHA256 = "87478065bd1a8d498ff6fbc91738ddafc67dc991002e09b37217660ef45abbb3"
MATRIX_SHA256 = "5ee341507fd517d52e1e98aabe006e5c394c5f3c9c674dfb98aa631af44a8dbf"
ENGINE_SHA256 = "007985fec968b2cea78a7b2d96aeb42dbe3b387dfcb88ab542614c4f9d2ffa5c"
PROFILE_PADS = ",".join(["31:31"] * 6 + ["7:7"] * 66)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"JSON object required: {path}")
    return value


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def relative(path: Path) -> str:
    resolved = path.resolve()
    if resolved.is_relative_to(HERE.resolve()):
        return "poc/keepalive-load/" + resolved.relative_to(HERE.resolve()).as_posix()
    if resolved.is_relative_to(EVIDENCE.resolve()):
        return "evidence/keepalive-load-20261025/" + resolved.relative_to(
            EVIDENCE.resolve()).as_posix()
    raise AssertionError(f"path escapes package roots: {path}")


def resolve_manifest_path(name: str) -> Path:
    code_prefix = "poc/keepalive-load/"
    evidence_prefix = "evidence/keepalive-load-20261025/"
    if name.startswith(code_prefix):
        path = (HERE / name[len(code_prefix):]).resolve()
        require(path.is_relative_to(HERE.resolve()),
                f"manifest path escapes code root: {name}")
        return path
    if name.startswith(evidence_prefix):
        path = (EVIDENCE / name[len(evidence_prefix):]).resolve()
        require(path.is_relative_to(EVIDENCE.resolve()),
                f"manifest path escapes evidence root: {name}")
        return path
    raise AssertionError(f"manifest path has an unsupported prefix: {name}")


def expected_manifest_paths() -> set[str]:
    paths = {relative(path) for path in SOURCE_PATHS.values()}
    paths.add(relative(HERE / "verify_pma_keepalive_load.py"))
    paths.update({
        relative(RESTART),
        relative(NO_LOAD / "receipt.json"),
        relative(NO_LOAD / "attempt-1" / "proof-after.body.bin"),
        relative(FIXED / "receipt.json"),
        relative(MATRIX / "summary.json"),
    })
    for attempt in range(1, 4):
        paths.add(relative(FIXED / f"attempt-{attempt}" / "proof-after.body.bin"))
    for tier in (1, 5):
        for round_number in range(1, 4):
            case = MATRIX / f"tier-{tier:02d}-round-{round_number:02d}"
            paths.update({
                relative(case / "chain" / "receipt.json"),
                relative(case / "chain" / "attempt-1" / "proof-after.body.bin"),
                relative(case / "load.ready.json"),
                relative(case / "load.ready.snapshot.json"),
            })
    return paths


def validate_manifest() -> dict[str, str]:
    require(MANIFEST.is_file(), "checksum manifest absent")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        expected, separator, name = line.partition("  ")
        require(separator == "  " and len(expected) == 64 and name,
                f"malformed manifest line {line_number}")
        require(name not in entries, f"duplicate manifest path: {name}")
        entries[name] = expected
    require(set(entries) == expected_manifest_paths(), "manifest path set")
    for name, expected in entries.items():
        path = resolve_manifest_path(name)
        require(path.is_file(), f"manifest file absent: {name}")
        require(sha256(path) == expected, f"manifest hash: {name}")
    return entries


def socket_identity(value: Any) -> tuple[Any, ...]:
    require(isinstance(value, dict), "socket identity object")
    return (
        value.get("python_object_id"),
        value.get("fileno"),
        tuple(value.get("local") or ()),
        tuple(value.get("peer") or ()),
    )


def validate_health(value: dict[str, Any], php_version: str, label: str) -> None:
    require(value.get("status") == 200, f"{label} status")
    require(value.get("status_line") == "HTTP/1.1 200 OK", f"{label} status line")
    require(value.get("x_powered_by") == f"PHP/{php_version}", f"{label} PHP version")
    require(value.get("server") == "Apache/2.4.69 (Debian)", f"{label} server")
    require(value.get("body_truncated") is False, f"{label} body truncation")
    require(value.get("body_bytes") == value.get("captured_body_bytes") == 18499,
            f"{label} body length")


def validate_profile(receipt: dict[str, Any], target: str, php_version: str) -> None:
    require(receipt.get("schema") == "q618-pma-keepalive-leak-fire-v1", "chain schema")
    require(receipt.get("target") == target, "target URL")
    require(receipt.get("host_header") == "x", "Host geometry")
    require(receipt.get("exact_profile_acknowledged") is True, "profile acknowledgement")
    require(receipt.get("blockers_started_by_diagnostic") == 0, "no blockers")
    require(receipt.get("diagnostic_sha256") == SOURCE_HASHES["pma_keepalive_chain.py"],
            "chain source binding")
    require(receipt.get("leak_driver_sha256") == SOURCE_HASHES["pma_keepalive_leak.py"],
            "leak source binding")
    require(receipt.get("fire_driver_sha256") == SOURCE_HASHES["pma_keepalive_fire.py"],
            "Fire source binding")
    require(receipt.get("engine_sha256") == ENGINE_SHA256, "engine source binding")
    offsets = receipt.get("offsets") or {}
    require(offsets == {
        "zif_system": "0x465370",
        "zval_ptr_dtor": "0x65eb60",
        "table": "0xb30d8",
    }, "exact offsets")
    require(receipt.get("rotate_before_each_attempt") is False, "no pre-rotate")
    require(receipt.get("fire_rotate_omitted") is True, "Fire rotate omitted")
    require(receipt.get("stock_live_profile") is True, "stock-live profile")
    require(receipt.get("fire_carrier") == "live", "live carrier")
    require(receipt.get("fire_live_n") == 800, "live carrier count")
    require(receipt.get("fire_live_len") == 31, "live carrier length")
    require(receipt.get("fire_fill_n") == 4, "filler count")
    require(receipt.get("fire_progress_late") is True, "late progress")
    require(receipt.get("producer_pads") == PROFILE_PADS, "producer padding profile")
    require(receipt.get("fire_decoy_n") == 2, "decoy count")
    require(receipt.get("transport") ==
            "one HTTP/1.1 socket for Leak producer/consumer then Fire producer/consumer",
            "transport description")
    validate_health(receipt.get("health_before") or {}, php_version, "health before")
    validate_health(receipt.get("health_after") or {}, php_version, "health after")
    require(receipt.get("target_healthy_after") is True, "target healthy after")
    proof_before = receipt.get("proof_before") or {}
    require(proof_before.get("status") == 404, "fresh-marker precheck")
    require(bytes.fromhex(receipt.get("proof_before_body_hex", "")).find(b"404 Not Found") >= 0,
            "fresh-marker 404 body")


def validate_same_socket_exchange(exchange: dict[str, Any], identity: tuple[Any, ...],
                                  label: str) -> None:
    require(exchange.get("label") == label, f"{label} exchange label")
    require(socket_identity(exchange.get("socket_before")) == identity,
            f"{label} socket before")
    require(socket_identity(exchange.get("socket_after")) == identity,
            f"{label} socket after")
    for field in ("same_python_socket", "same_fileno", "same_local_endpoint",
                  "same_peer_endpoint"):
        require(exchange.get(field) is True, f"{label} {field}")
    require(exchange.get("send_error") is None, f"{label} send error")
    require(exchange.get("request_bytes_sent", 0) > 0, f"{label} request bytes")
    require(len(exchange.get("request_head_sha256", "")) == 64, f"{label} request-head hash")
    require(len(exchange.get("request_stream_sha256", "")) == 64,
            f"{label} request-stream hash")


def validate_positive(receipt_path: Path, marker: str, proof_path: Path) -> dict[str, Any]:
    receipt = load_json(receipt_path)
    validate_profile(
        receipt,
        "http://127.0.0.1:18212/show_config_errors.php",
        "8.4.26",
    )
    marker_lower = marker.lower()
    require(receipt.get("status") == "rce_proved", f"{marker} chain status")
    require(receipt.get("command") == f"printf {marker}>{marker_lower}", f"{marker} command")
    require(receipt.get("fetch") == f"/{marker_lower}", f"{marker} fetch path")
    require(receipt.get("expected_body_text") == marker, f"{marker} expected body")
    require(receipt.get("expected_body_hex") == marker.encode().hex(), f"{marker} body hex")
    require(receipt.get("proof_fresh") is True, f"{marker} proof freshness")
    require(receipt.get("same_socket_all_four_proved") is True,
            f"{marker} same-socket aggregate")
    require(receipt.get("successful_attempt") == 1, f"{marker} successful attempt")
    attempts = receipt.get("attempts") or []
    require(len(attempts) == 1, f"{marker} attempt count")
    attempt = attempts[0]
    require(attempt.get("attempt") == 1 and attempt.get("status") == "rce_proved",
            f"{marker} attempt status")
    require(attempt.get("leak_error") is None and attempt.get("fire_error") is None,
            f"{marker} stage errors")
    heap = int(attempt.get("heap", "0"), 0)
    module = int(attempt.get("libphp", "0"), 0)
    require(heap >= 0x100000000000 and heap % 0x200000 == 0, f"{marker} heap base")
    require(0x100000000000 <= module < 0x800000000000, f"{marker} libphp base")
    require(attempt.get("pointer_count", 0) > 0, f"{marker} pointer count")
    require(attempt.get("cookie_bytes") == 600000, f"{marker} leak cookie length")
    require(attempt.get("leak_ready_on_persistent_socket") is True,
            f"{marker} persistent leak")
    require(int(attempt.get("fire_table_address", "0"), 0) == heap + 0xB30D8,
            f"{marker} table address")
    require(int(attempt.get("fire_system_address", "0"), 0) == module + 0x465370,
            f"{marker} system address")
    require(attempt.get("same_socket_for_all_four_requests") is True,
            f"{marker} same socket")
    require(attempt.get("fire_consumer_request_fully_sent") is True,
            f"{marker} Fire consumer sent")

    identity = socket_identity(attempt.get("persistent_socket_initial"))
    require(identity[2] and identity[3], f"{marker} socket endpoints")
    require(identity[3] == ("127.0.0.1", 18212), f"{marker} target socket")
    exchanges = attempt.get("exchanges") or []
    require(len(exchanges) == 4, f"{marker} exchange count")
    labels = ("producer", "consumer", "fire_producer", "fire_consumer")
    for exchange, label in zip(exchanges, labels):
        validate_same_socket_exchange(exchange, identity, label)
    for exchange in exchanges[:3]:
        require(exchange.get("status") == 200, f"{marker} {exchange['label']} status")
        require(exchange.get("will_close") is False, f"{marker} {exchange['label']} reusable")
    require(exchanges[2].get("request_fully_sent") is True and
            exchanges[2].get("response_complete") is True,
            f"{marker} Fire producer completion")
    require(exchanges[3].get("request_fully_sent") is True,
            f"{marker} Fire consumer completion")
    require(exchanges[3].get("response_complete") is False and
            str(exchanges[3].get("response_error", "")).startswith("PeerEOF:"),
            f"{marker} expected terminal EOF")
    handoff = attempt.get("leak_to_fire_socket_handoff") or {}
    require(handoff.get("identical") is True, f"{marker} Leak-to-Fire handoff")
    require(socket_identity(handoff.get("before")) == identity ==
            socket_identity(handoff.get("after")), f"{marker} handoff identity")

    proof = attempt.get("proof_after") or {}
    require(proof.get("status") == 200 and attempt.get("proof_exact") is True,
            f"{marker} HTTP proof")
    require(attempt.get("proof_after_body_hex") == marker.encode().hex(),
            f"{marker} proof body receipt")
    require(proof_path.read_bytes() == marker.encode(), f"{marker} saved proof body")
    cookie_path = proof_path.parent / "leak.cookie.bin"
    require(cookie_path.stat().st_size == 600000, f"{marker} saved cookie length")
    require(sha256(cookie_path) == attempt.get("cookie_sha256"), f"{marker} saved cookie hash")
    return receipt


def validate_fixed() -> dict[str, Any]:
    receipt_path = FIXED / "receipt.json"
    require(sha256(receipt_path) == FIXED_SHA256, "fixed receipt hash")
    receipt = load_json(receipt_path)
    validate_profile(
        receipt,
        "http://127.0.0.1:18213/show_config_errors.php",
        "8.4.27",
    )
    require(receipt.get("status") == "chain_failed_no_exact_proof", "fixed status")
    require(receipt.get("proof_fresh") is False, "fixed proof freshness")
    require(receipt.get("command") == "printf E13>e13" and
            receipt.get("fetch") == "/e13" and
            receipt.get("expected_body_text") == "E13", "fixed marker")
    attempts = receipt.get("attempts") or []
    require(len(attempts) == 3, "fixed attempt count")
    for index, attempt in enumerate(attempts, 1):
        label = f"fixed attempt {index}"
        require(attempt.get("attempt") == index and attempt.get("status") == "leak_failed",
                f"{label} status")
        require(attempt.get("heap") == "0x0" and attempt.get("libphp") == "0x0",
                f"{label} bases")
        require(attempt.get("pointer_count") == 0 and attempt.get("cookie_bytes") == 32,
                f"{label} benign cookie")
        require(attempt.get("leak_ready_on_persistent_socket") is False,
                f"{label} leak denied")
        require(attempt.get("fire_error") is None and
                attempt.get("fire_consumer_request_fully_sent") is False,
                f"{label} no Fire")
        exchanges = attempt.get("exchanges") or []
        require([item.get("label") for item in exchanges] == ["producer", "consumer"],
                f"{label} only leak requests")
        identity = socket_identity(attempt.get("persistent_socket_initial"))
        require(identity[3] == ("127.0.0.1", 18213), f"{label} target socket")
        for exchange, name in zip(exchanges, ("producer", "consumer")):
            validate_same_socket_exchange(exchange, identity, name)
            require(exchange.get("status") == 200 and exchange.get("will_close") is False,
                    f"{label} reusable {name}")
        proof = attempt.get("proof_after") or {}
        require(proof.get("status") == 404 and attempt.get("proof_exact") is False,
                f"{label} proof denied")
        body_path = FIXED / f"attempt-{index}" / "proof-after.body.bin"
        body = body_path.read_bytes()
        require(b"404 Not Found" in body and b"E13" not in body,
                f"{label} saved denial body")
    return receipt


def validate_restart() -> dict[str, Any]:
    receipt = load_json(RESTART)
    require(receipt.get("container") == "p2s-phpmyadmin-functional-stock",
            "restart container")
    require(receipt.get("container_id_before") == receipt.get("container_id_after"),
            "restart container identity")
    require(receipt.get("image_before") == receipt.get("image_after") ==
            "sha256:7a707d31b3a197d8b3d7039eb7d28cd4625f8a3a72b33fc0dbe1a0a695c467e3",
            "restart image identity")
    require(receipt.get("compose_config_hash_before") ==
            receipt.get("compose_config_hash_after") ==
            "9c893de670ed99ec72c114d299d70aab8df7936467f909dac7c21a41cb092fa6",
            "restart Compose identity")
    require(receipt.get("database_container_restarted") is False, "database restart boundary")
    require((receipt.get("post_restart_health") or {}).get("status") == 200,
            "restart health")
    return receipt


def validate_matrix() -> dict[str, Any]:
    summary_path = MATRIX / "summary.json"
    require(sha256(summary_path) == MATRIX_SHA256, "matrix summary hash")
    summary = load_json(summary_path)
    require(summary.get("schema") == "q618-pma-keepalive-load-matrix-v1",
            "matrix schema")
    require(summary.get("status") == "pass", "matrix status")
    require(summary.get("target") == "http://127.0.0.1:18212", "matrix target")
    require(summary.get("chain_sha256") == SOURCE_HASHES["pma_keepalive_chain.py"],
            "matrix chain binding")
    require(summary.get("load_helper_sha256") == SOURCE_HASHES["http_load.py"],
            "matrix load binding")
    require(summary.get("tiers") == [1, 5] and summary.get("rounds") == 3,
            "matrix dimensions")
    require(summary.get("marker_prefix") == "F" and summary.get("interval_seconds") == 0.05,
            "matrix load profile")
    cases = summary.get("cases") or []
    require(len(cases) == 6, "matrix case count")
    require({(item.get("tier"), item.get("round")) for item in cases} ==
            {(tier, round_number) for tier in (1, 5) for round_number in range(1, 4)},
            "matrix case identity")

    totals = {1: 0, 5: 0}
    for case in cases:
        tier = int(case["tier"])
        round_number = int(case["round"])
        marker = f"F{tier}{round_number}"
        label = f"tier {tier} round {round_number}"
        require(case.get("marker") == marker and case.get("status") == "pass",
                f"{label} summary status")
        require(case.get("chain_exit_code") == 0 and case.get("chain_status") == "rce_proved",
                f"{label} chain exit")
        require(case.get("proof_fresh") is True and
                case.get("same_socket_all_four") is True and
                case.get("target_healthy_after") is True,
                f"{label} chain gates")
        require(case.get("load_exit_code") == 0 and case.get("load_transport_errors") == 0,
                f"{label} load exit")

        case_dir = MATRIX / f"tier-{tier:02d}-round-{round_number:02d}"
        chain_path = case_dir / "chain" / "receipt.json"
        require(sha256(chain_path) == case.get("chain_receipt_sha256"),
                f"{label} chain receipt hash")
        recorded = str(case.get("chain_receipt", "")).replace("\\", "/").lower()
        suffix = f"tier-{tier:02d}-round-{round_number:02d}/chain/receipt.json"
        require(recorded.endswith(suffix), f"{label} recorded receipt path")
        chain = validate_positive(
            chain_path,
            marker,
            case_dir / "chain" / "attempt-1" / "proof-after.body.bin",
        )

        load_path = case_dir / "load.ready.json"
        require(sha256(load_path) == case.get("load_final_sha256"),
                f"{label} final load hash")
        require((case_dir / "load.stdout.txt").read_bytes() == load_path.read_bytes(),
                f"{label} duplicated final load receipt")
        load = load_json(load_path)
        ready = load_json(case_dir / "load.ready.snapshot.json")
        require(ready == {
            "status": "ready",
            "pid": ready.get("pid"),
            "started_utc": load.get("started_utc"),
            "url": "http://127.0.0.1:18212",
            "target": "/",
            "method": "GET",
            "concurrency": tier,
            "interval_seconds": 0.05,
        }, f"{label} ready snapshot")
        require(isinstance(ready.get("pid"), int) and ready["pid"] > 0,
                f"{label} ready PID")
        require(load.get("status") == "complete" and load.get("stop_reason") == "stop_file",
                f"{label} load completion")
        require(load.get("concurrency") == tier and load.get("transport_errors") == 0,
                f"{label} load concurrency/errors")
        attempts = int(case["load_attempts"])
        require(attempts > 0 and load.get("attempts") == attempts,
                f"{label} load attempts")
        require(load.get("http_responses") == case.get("load_http_responses") == attempts,
                f"{label} responses")
        require(load.get("http_2xx") == case.get("load_http_2xx") == attempts,
                f"{label} 2xx responses")
        require(load.get("status_counts") == case.get("load_status_counts") == {"200": attempts},
                f"{label} status counts")
        require(load.get("request_rate_per_second") == case.get("load_request_rate_per_second")
                and load.get("request_rate_per_second", 0) > 0,
                f"{label} request rate")
        target = load.get("target") or {}
        require(target.get("url") == "http://127.0.0.1:18212" and
                target.get("path") == "/" and target.get("method") == "GET",
                f"{label} load target")
        require(load.get("started_utc") == case.get("load_started_utc") and
                load.get("ended_utc") == case.get("load_ended_utc"),
                f"{label} load timestamps")
        load_start = parse_time(load["started_utc"])
        load_end = parse_time(load["ended_utc"])
        chain_start = parse_time(chain["started_utc"])
        chain_end = parse_time(chain["ended_utc"])
        require(load_start < chain_start < chain_end < load_end,
                f"{label} load overlap")
        totals[tier] += attempts

    require(totals == {1: 250, 5: 1132}, "matrix aggregate responses")
    return {"summary": summary, "totals": totals}


def main() -> int:
    manifest = validate_manifest()
    for name, expected in SOURCE_HASHES.items():
        path = SOURCE_PATHS[name]
        require(sha256(path) == expected, f"source hash: {name}")
        require(manifest.get(relative(path)) == expected,
                f"manifest source hash: {name}")
    require(sha256(NO_LOAD / "receipt.json") == NO_LOAD_SHA256, "no-load receipt hash")
    no_load = validate_positive(
        NO_LOAD / "receipt.json",
        "C07",
        NO_LOAD / "attempt-1" / "proof-after.body.bin",
    )
    fixed = validate_fixed()
    restart = validate_restart()
    matrix = validate_matrix()
    verdict = {
        "verdict": "PMA_KEEPALIVE_STOCK_LIVE_LOAD_RCE_PASS",
        "scope": "exact phpMyAdmin 5.2.2 / PHP 8.4.26 Apache profile",
        "no_blockers": True,
        "same_socket_requests": 4,
        "no_load_marker": no_load["expected_body_text"],
        "load": {
            "tier_1": {"proofs": "3/3", "http_200": matrix["totals"][1]},
            "tier_5": {"proofs": "3/3", "http_200": matrix["totals"][5]},
            "transport_errors": 0,
        },
        "fixed_control": {
            "php": fixed["health_after"]["x_powered_by"],
            "attempts": len(fixed["attempts"]),
            "leaks": 0,
            "proof": False,
        },
        "target_image": restart["image_after"],
        "manifest_entries": len(manifest),
    }
    print(json.dumps(verdict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
