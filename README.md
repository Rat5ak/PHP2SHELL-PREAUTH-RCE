# php2shell

Three reproductions of the PHP core CVE-2026-109618 / CVE-2026-109619 family.
Send one unauthenticated HTTP request, get a `www-data` shell. The exploit
reads the heap and `libphp` addresses straight out of the HTTP responses, so
you never hand it an address.

Each one runs against a pinned local target on loopback. None of these is a
new WordPress or phpMyAdmin bug, and they don't work against PHP in general.
You get the web server account, not root.

| | target | runnable from this repo |
|---|---|---|
| [01](01-wordpress-7.1.3-php-8.5.4/) | WordPress 7.1.3, PHP 8.5.4, Apache 2.4.52 `mod_php`, one worker | no, see below |
| [02](02-wordpress-7.1.2-php-8.3.35/) | `wordpress:7.1.2-php8.3-apache`, stock 150-worker prefork | yes, Docker |
| [03](03-phpmyadmin-5.2.2-php-8.4.26/) | phpMyAdmin 5.2.2, PHP 8.4.26, stock 150-worker prefork | yes, Docker |

## 01 WordPress 7.1.3 / PHP 8.5.4

Source only. It needs a recorded `libphp-8.5.4-web.so` and a one-worker
`apache2 -X` setup on a prepared Ubuntu 22.04 guest. Neither is in here, so
there's nothing to point it at.
[`exploit.py`](01-wordpress-7.1.3-php-8.5.4/exploit.py) is here to read.

[![PHP 8.5.4 / WordPress 7.1.3](https://img.youtube.com/vi/4fdF4740Ewg/maxresdefault.jpg)](https://youtu.be/4fdF4740Ewg)

4:18. Also in [`demo.mp4`](01-wordpress-7.1.3-php-8.5.4/demo.mp4).

## 02 WordPress 7.1.2 / PHP 8.3.35

Pinned official image, stock 128M / 8M limits, 150 prefork workers. The
exploit works out which worker to aim at from that count, then drops you on a
real callback shell.

```powershell
.\START-LAB.cmd
```

Open the URL it prints and check the WordPress homepage looks normal, then in
a second window:

```powershell
.\EXPLOIT.cmd
```

Type commands at the target prompt. Run `.\STOP-LAB.cmd` when you're done.
Every start puts the original `index.php` back.

Needs Docker Desktop on Linux containers.

[![WordPress 7.1.2 / PHP 8.3.35](https://img.youtube.com/vi/ln0rwy_Arjc/maxresdefault.jpg)](https://youtu.be/ln0rwy_Arjc)

1:21. Also in [`demo.mp4`](02-wordpress-7.1.2-php-8.3.35/demo.mp4).

## 03 phpMyAdmin 5.2.2 / PHP 8.4.26

Goes in through `/show_config_errors.php`, which phpMyAdmin ships without
auth. The `Host` header does the allocation. A PHP 8.4.27 target comes up next
to it as a control, and the same request gets nowhere against that one.

```powershell
.\START-LAB.cmd
.\LISTEN.cmd
.\EXPLOIT.cmd
```

Run `.\STOP-LAB.cmd` afterwards. `.\FIXED-CONTROL.cmd` runs the same thing
against 8.4.27.

Needs Docker Desktop on Linux containers, Python 3, and Ncat at
`C:\Program Files (x86)\Nmap\ncat.exe`. The runner won't touch anything that
isn't loopback. The first build pulls the pinned images and checks the
phpMyAdmin archive against its SHA-256.

[![phpMyAdmin 5.2.2 / PHP 8.4.26](https://img.youtube.com/vi/dNtQxA8WSxY/maxresdefault.jpg)](https://youtu.be/dNtQxA8WSxY)

3:56. Also in [`demo.mp4`](03-phpmyadmin-5.2.2-php-8.4.26/demo.mp4).

## Credit

The bugs themselves are php-src advisories
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
Not mine. The phpMyAdmin lab builds on public php2shell prior art, which is
kept under
[`prior-art-php2shell-joas/`](03-phpmyadmin-5.2.2-php-8.4.26/prior-art-php2shell-joas/)
with its own files.

## Don't be stupid

These bring up their own targets on loopback and the runners refuse anything
else. Run them on systems you own or have written permission to test.

---

> **Disclaimer:** This exploit code is provided for security research and
> educational purposes. Do not use it against systems you do not own or have
> explicit authorization to test. The author is not responsible for misuse.

*Daniel Wade - [GitHub](https://github.com/Rat5ak) · [Twitter/X](https://x.com/Nadsec11) · [Bluesky](https://bsky.app/profile/nadsec.online) · [Mastodon](https://cyberplace.social/@Nadsec) · [Medium](https://medium.com/@Nadsec) · [nadsec.online](https://nadsec.online)*
