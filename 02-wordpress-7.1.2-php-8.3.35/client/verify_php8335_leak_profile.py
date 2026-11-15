#!/usr/bin/env python3
"""Offline gate for the official PHP 8.3.35 leak capability."""

import json
from pathlib import Path

import auto_profile_shell as auto


HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "official-php8335-leak-evidence"
PROFILE_ID = "php8335-official-wp712-prefork150-fanchor-v1"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rejects_cookie(profile, name):
    try:
        auto.derive_cookie((EVIDENCE / name).read_bytes(), profile)
    except auto.SelectionStopped:
        return True
    return False


def main():
    profiles = auto.load_registry(HERE / "auto_profiles_v2.json")
    profile = next(item for item in profiles if item["id"] == PROFILE_ID)

    require(profile["status"] == "READY", "overall profile status")
    require(profile["capabilities"] == {
        "leak": "READY", "terminal": "READY"}, "capabilities")
    require(profile in auto.profiles_for_mode(profiles, "safe"),
            "READY profile absent from safe mode")
    require(profile in auto.profiles_for_mode(profiles, "execute"),
            "READY profile absent from execute mode")

    positive = (EVIDENCE / "positive.cookie.bin").read_bytes()
    main, libphp, destructor, ar_data = auto.derive_cookie(positive, profile)
    require(main == 0x72E708000000, "main chunk")
    require(libphp == 0x72E709CA4000, "page-aligned module base")
    require(destructor == 0x72E70A142C50, "zval_ptr_dtor")
    require(ar_data == [0x72E7080836E8 + index * 0xA0
                        for index in range(7)], "arData sequence")

    require(rejects_cookie(profile, "fixed-8336.cookie.bin"),
            "fixed PHP 8.3.36 cookie accepted")
    require(rejects_cookie(profile, "no-progress.cookie.bin"),
            "no-progress cookie accepted")

    affected, _ = auto.fingerprint_match(profile, 200, {
        "server": "Apache/2.4.68 (Debian)",
        "x-powered-by": "PHP/8.3.35",
    })
    fixed, _ = auto.fingerprint_match(profile, 200, {
        "server": "Apache/2.4.69 (Debian)",
        "x-powered-by": "PHP/8.3.36",
    })
    fixed_php_only, _ = auto.fingerprint_match(profile, 200, {
        "server": "Apache/2.4.68 (Debian)",
        "x-powered-by": "PHP/8.3.36",
    })
    banner_candidate, candidate_evidence = auto.fingerprint_match(
        profile, 200, {"server": "Apache/2.4.68 (Debian)"})
    require(affected, "affected fingerprint")
    require(not fixed, "fixed fingerprint accepted")
    require(not fixed_php_only, "fixed PHP version accepted")
    require(banner_candidate, "expected passive candidate")
    require(any("active leak required" in item
                for item in candidate_evidence["reasons"]),
            "banner candidate did not require active leak")

    positive_receipt = json.loads(
        (EVIDENCE / "positive.receipt.json").read_text("utf-8"))
    fixed_receipt = json.loads(
        (EVIDENCE / "fixed-8336.receipt.json").read_text("utf-8"))
    no_progress_receipt = json.loads(
        (EVIDENCE / "no-progress.receipt.json").read_text("utf-8"))
    for name, receipt in (("positive", positive_receipt),
                          ("fixed", fixed_receipt),
                          ("no-progress", no_progress_receipt)):
        require(receipt["terminal_armed"] is False, name + " terminal")
        require(receipt["callbacks_possible"] is False, name + " callback")
        require(receipt["command_payload_present"] is False,
                name + " command")
    require(positive_receipt["a1"]["status"] ==
            "HTTP/1.0 500 Internal Server Error",
            "affected A1 status")
    require(positive_receipt["b1"]["status"] == "HTTP/1.1 200 OK",
            "affected B1 status")
    require(fixed_receipt["a1"]["status"] == "HTTP/1.1 200 OK",
            "fixed A1 must reject profile")

    result = {
        "verdict": "PHP8335_OFFICIAL_LEAK_CAPABILITY_PASS",
        "profile": PROFILE_ID,
        "selection_signature": profile["_selection_key"],
        "derived": {
            "main": f"0x{main:x}",
            "libphp": f"0x{libphp:x}",
            "zval_ptr_dtor": f"0x{destructor:x}",
            "hash_tables": len(ar_data),
        },
        "controls": {
            "php_8_3_36": "rejected",
            "no_progress": "rejected",
            "banner_only": "candidate_only_active_leak_required",
        },
        "terminal": "READY_SEPARATELY_VERIFIED",
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
