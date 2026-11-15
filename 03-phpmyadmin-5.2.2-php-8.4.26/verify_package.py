#!/usr/bin/env python3
"""Offline integrity and scope verifier for the exact phpMyAdmin package."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP = ROOT / "prior-art-php2shell-joas"
ENGINE = ROOT / "q618-stock-gate-20261024" / "thecybergeek-read-only" / "engine.py"

EXPECTED_ENGINE = "007985fec968b2cea78a7b2d96aeb42dbe3b387dfcb88ab542614c4f9d2ffa5c"
EXPECTED_GATE = "8a513462f38ba3dd6e9eb95aa88f4ec4064b58d196e986e6a26b33972f448cec"
EXPECTED_LAB = {
    "Dockerfile": "c2e45dc6d24091743874f8e40422ddcc646d207ad6bf748e63e4825e1eb1b01f",
    "docker-compose.yml": "2f83aea7464f3c840eeb0f34fb87f676287a38018c6e6da60b61d6eadac8cc15",
    "docker-compose.fixed.yml": "52fad2780b4a0d72c7c6b658a8515bc26412b74f1be5629e963e7d12ff1e4217",
    "config.inc.php": "3d4e8f7cab8cc72907e0ada59fd3f921ad6a5fd5d19227d3e305cee35d284aaf",
}

REQUIRED = [
    "README.md",
    "VIDEO-DEMO.md",
    "START-LAB.cmd",
    "START-LAB.ps1",
    "LISTEN.cmd",
    "LISTEN.ps1",
    "EXPLOIT.cmd",
    "EXPLOIT.ps1",
    "FIXED-CONTROL.cmd",
    "FIXED-CONTROL.ps1",
    "STOP-LAB.cmd",
    "STOP-LAB.ps1",
    "verify_package.py",
    "prior-art-php2shell-joas/stock_phpmyadmin_gate.py",
    "prior-art-php2shell-joas/stock_phpmyadmin_shell.py",
    "prior-art-php2shell-joas/stock_phpmyadmin_deface.py",
    "prior-art-php2shell-joas/demo-reset.ps1",
    "prior-art-php2shell-joas/demo-shell.ps1",
    "prior-art-php2shell-joas/PHPMYADMIN-LIVE-DEMO-RUNBOOK-20261025.md",
    "prior-art-php2shell-joas/STOCK-PHPMYADMIN-RCE-RECEIPT-20261025.md",
    "prior-art-php2shell-joas/evidence/phpmyadmin-stock-20261025/vulnerable-run.txt",
    "prior-art-php2shell-joas/evidence/phpmyadmin-stock-20261025/vulnerable-proof.txt",
    "prior-art-php2shell-joas/evidence/phpmyadmin-stock-20261025/fixed-run.txt",
    "prior-art-php2shell-joas/evidence/phpmyadmin-stock-20261025/SHA256SUMS",
    "prior-art-php2shell-joas/evidence/phpmyadmin-live-shell-20261025.txt",
    "prior-art-php2shell-joas/evidence/phpmyadmin-live-demo-SHA256SUMS",
    "prior-art-php2shell-joas/labs/phpmyadmin-functional-stock/Dockerfile",
    "prior-art-php2shell-joas/labs/phpmyadmin-functional-stock/docker-compose.yml",
    "prior-art-php2shell-joas/labs/phpmyadmin-functional-stock/docker-compose.fixed.yml",
    "prior-art-php2shell-joas/labs/phpmyadmin-functional-stock/config.inc.php",
    "q618-stock-gate-20261024/thecybergeek-read-only/engine.py",
]

FORBIDDEN_NAMES = {
    "pma_rce.py",
    "batch_test_pma.py",
    "verify_rce.py",
    "verify_rce_pma.py",
    "sweep_ht_offset.py",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify_checksum_manifest(path: Path, base: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})\s+(.+)", line)
        need(match is not None, f"invalid checksum line: {path.name}")
        wanted, relative = match.groups()
        item = (base / Path(relative.replace("/", "\\"))).resolve()
        need(item.is_file(), f"checksum target absent: {relative}")
        need(digest(item) == wanted, f"checksum mismatch: {relative}")


def main() -> int:
    for relative in REQUIRED:
        need((ROOT / relative).is_file(), f"required file absent: {relative}")

    for path in ROOT.rglob("*"):
        need(path.name not in FORBIDDEN_NAMES, f"scratch artifact included: {path.name}")
        need("scratchpad" not in {part.lower() for part in path.parts},
             f"scratch directory included: {path}")

    gate = APP / "stock_phpmyadmin_gate.py"
    need(digest(ENGINE) == EXPECTED_ENGINE, "pinned engine hash mismatch")
    need(digest(gate) == EXPECTED_GATE, "stock gate hash mismatch")
    gate_text = gate.read_text(encoding="utf-8")
    need('VENDOR = HERE.parent / "q618-stock-gate-20261024" / "thecybergeek-read-only"' in gate_text,
         "vendored engine path drift")
    need(f'EXPECTED_ENGINE_SHA256 = "{EXPECTED_ENGINE}"' in gate_text,
         "gate lost engine hash pin")
    need('parsed.hostname != "127.0.0.1"' in gate_text,
         "gate lost loopback restriction")
    need('"--ack-exact-profile"' in gate_text and "default=0x690D8" in gate_text,
         "gate lost exact-profile/table gates")

    lab = APP / "labs" / "phpmyadmin-functional-stock"
    for name, wanted in EXPECTED_LAB.items():
        need(digest(lab / name) == wanted, f"lab hash mismatch: {name}")

    dockerfile = (lab / "Dockerfile").read_text(encoding="utf-8")
    vulnerable = (lab / "docker-compose.yml").read_text(encoding="utf-8")
    fixed = (lab / "docker-compose.fixed.yml").read_text(encoding="utf-8")
    need("php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a" in dockerfile,
         "vulnerable PHP digest drift")
    need("8551c8bf3b166f232d5cf64bac877472e9d0cb8f2fe1858fab24f975e7d765b6" in dockerfile,
         "phpMyAdmin archive hash drift")
    need('"127.0.0.1:18212:80"' in vulnerable,
         "vulnerable service is not loopback-bound")
    need('"127.0.0.1:18213:80"' in fixed,
         "fixed service is not loopback-bound")
    need("php:8.4.27-apache@sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601" in fixed,
         "fixed PHP digest drift")
    mariadb = "mariadb:11@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15"
    need(mariadb in vulnerable and mariadb in fixed, "MariaDB digest drift")

    stock_manifest = APP / "evidence" / "phpmyadmin-stock-20261025" / "SHA256SUMS"
    verify_checksum_manifest(stock_manifest, stock_manifest.parent)
    live_manifest = APP / "evidence" / "phpmyadmin-live-demo-SHA256SUMS"
    verify_checksum_manifest(live_manifest, APP)

    receipt = (APP / "STOCK-PHPMYADMIN-RCE-RECEIPT-20261025.md").read_text(
        encoding="utf-8"
    )
    need("status\": \"rce_proved" in receipt and "status\": \"leak_failed" in receipt,
         "receipt lost positive/fixed verdicts")
    need("149 still-live blocker" in receipt and "www-data" in receipt,
         "receipt lost worker/consequence boundary")
    need("not a novel phpMyAdmin vulnerability" in receipt,
         "receipt lost provenance boundary")

    start = (ROOT / "START-LAB.ps1").read_text(encoding="utf-8")
    listener = (ROOT / "LISTEN.ps1").read_text(encoding="utf-8")
    exploit = (ROOT / "EXPLOIT.ps1").read_text(encoding="utf-8")
    fixed_control = (ROOT / "FIXED-CONTROL.ps1").read_text(encoding="utf-8")
    stop = (ROOT / "STOP-LAB.ps1").read_text(encoding="utf-8")
    need("127.0.0.1:18212" in start and "127.0.0.1:18213" in start and
         "8.4.26" in start and "8.4.27" in start,
         "start wrapper lost target/control gates")
    need("ncat" in listener.lower() and "4461" in listener,
         "listener wrapper drift")
    need("demo-shell.ps1" in exploit and "show_config_errors.php" in exploit and
         "148 blockers" in exploit,
         "exploit wrapper drift")
    need("18213/show_config_errors.php" in fixed_control and
         "FIXED_CONTROL_PASS" in fixed_control and
         '"status": "leak_failed"' in fixed_control,
         "fixed-control wrapper drift")
    need("down --volumes --remove-orphans" in stop,
         "stop wrapper lost package-owned cleanup")

    for path in ROOT.rglob("*"):
        if path.is_file():
            lower = path.name.lower()
            need(lower not in {"id_rsa", "id_ed25519", "known_hosts"},
                 f"private machine material included: {path.name}")
            need(path.suffix.lower() not in {".vmx", ".vmdk"},
                 f"private VM material included: {path.name}")

    print("VERIFIED_PHPMYADMIN_522_PHP8426_EXACT_PROFILE_PACKAGE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
