#!/usr/bin/env python3
"""Start and stop the isolated official WordPress PHP 8.3.35 video target."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


HERE = Path(__file__).resolve().parent
COMPOSE = HERE / "docker-compose.yml"
STATE = HERE / ".q618-video-state.json"
PROJECT = "q618-wp8335-video"
NETWORK = "q618-wp8335-video"
TARGET_CONTAINER = "q618-wp8335-target"
CLIENT_CONTAINER = "q618-wp8335-demo-client"
TARGET_URL = "http://127.0.0.1:18540/"
WORDPRESS_TITLE = "NADSEC PHP2Shell Lab"
ADMIN_USER = "q618admin"
ADMIN_PASSWORD = "q618-local-admin-password"


def run(arguments: list[str], *, timeout: int = 180,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            arguments, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required program not found: {arguments[0]}") from exc
    if check and completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or f"command failed: {arguments[0]}")
    return completed


def compose(*arguments: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return run([
        "docker", "compose", "--project-name", PROJECT,
        "-f", str(COMPOSE), *arguments,
    ], timeout=timeout)


def request(path: str = "/", *, data: dict[str, str] | None = None,
            timeout: int = 15) -> tuple[int, bytes]:
    url = urllib.parse.urljoin(TARGET_URL, path)
    encoded = None
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("ascii")
    req = urllib.request.Request(url, data=encoded)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_http(timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, body = request(timeout=5)
            if status in (200, 302, 500, 503) and body:
                return
        except (OSError, RuntimeError) as exc:
            last = exc
        time.sleep(1)
    raise RuntimeError(f"WordPress HTTP did not become ready: {last}")


def docker_exec(*arguments: str, timeout: int = 60) -> str:
    return run([
        "docker", "exec", TARGET_CONTAINER, *arguments,
    ], timeout=timeout).stdout


def restore_homepage() -> None:
    docker_exec(
        "sh", "-lc",
        "cp /usr/src/wordpress/index.php /var/www/html/index.php && "
        "chown www-data:www-data /var/www/html/index.php",
    )


def install_wordpress() -> str:
    status, body = request()
    if status == 200 and WORDPRESS_TITLE.encode() in body:
        return "already-installed"
    fields = {
        "weblog_title": WORDPRESS_TITLE,
        "user_name": ADMIN_USER,
        "admin_password": ADMIN_PASSWORD,
        "admin_password2": ADMIN_PASSWORD,
        "pw_weak": "1",
        "admin_email": "q618@example.invalid",
        "Submit": "Install WordPress",
        "language": "",
    }
    request("/wp-admin/install.php?step=2", data=fields, timeout=60)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status, body = request()
        if status == 200 and WORDPRESS_TITLE.encode() in body:
            return "installed"
        time.sleep(1)
    raise RuntimeError("WordPress installation did not complete")


def inspect_target() -> dict[str, object]:
    php_version = docker_exec("php", "-r", "echo PHP_VERSION;").strip()
    wordpress_version = docker_exec(
        "php", "-r",
        "include '/var/www/html/wp-includes/version.php'; echo $wp_version;",
    ).strip()
    settings = docker_exec(
        "php", "-r",
        "echo ini_get('memory_limit'),'|',ini_get('post_max_size'),'|',"
        "ini_get('upload_max_filesize');",
    ).strip().split("|")
    target_ip = run([
        "docker", "inspect", "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        TARGET_CONTAINER,
    ]).stdout.strip()
    if php_version != "8.3.35":
        raise RuntimeError(f"unexpected PHP version: {php_version}")
    if wordpress_version != "7.1.2":
        raise RuntimeError(f"unexpected WordPress version: {wordpress_version}")
    if settings[:2] != ["128M", "8M"]:
        raise RuntimeError(f"unexpected PHP limits: {'|'.join(settings)}")
    if not target_ip:
        raise RuntimeError("target container has no private IP")
    status, body = request()
    if status != 200 or WORDPRESS_TITLE.encode() not in body:
        raise RuntimeError("normal WordPress homepage check failed")
    return {
        "status": "READY",
        "target_url": TARGET_URL,
        "browser_host": "127.0.0.1",
        "browser_port": 18540,
        "target_ip": target_ip,
        "target_port": 80,
        "target_container": TARGET_CONTAINER,
        "docker_network": NETWORK,
        "compose_project": PROJECT,
        "php_version": php_version,
        "wordpress_version": wordpress_version,
        "memory_limit": settings[0],
        "post_max_size": settings[1],
        "upload_max_filesize": settings[2] if len(settings) > 2 else "",
        "public_listener": False,
    }


def start() -> None:
    run(["docker", "version"], timeout=30)
    compose("up", "-d", "--wait", timeout=300)
    wait_http()
    restore_homepage()
    install_wordpress()
    state = inspect_target()
    STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(f"TARGET_URL={state['target_url']}")
    print(f"TARGET_IP={state['target_ip']}")
    print(f"PHP={state['php_version']}")
    print(f"WORDPRESS={state['wordpress_version']}")
    print("STATUS=READY")


def stop(reset: bool) -> None:
    run(["docker", "rm", "-f", CLIENT_CONTAINER], timeout=30, check=False)
    arguments = ["down", "--remove-orphans"]
    if reset:
        arguments.append("--volumes")
    compose(*arguments, timeout=180)
    if STATE.exists():
        STATE.unlink()
    print(f"STATUS=STOPPED data_preserved={'false' if reset else 'true'}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "start":
            start()
        else:
            stop(args.reset)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
