# PHP 8.3.35 official WordPress local proof

This is the video/demo wrapper for the completed official-image proof:

- target: `wordpress:7.1.2-php8.3-apache`;
- PHP: 8.3.35, Apache `apache2handler`;
- target URL: `http://127.0.0.1:18540/`;
- target network: private Docker network `q618-wp8335-video`;
- shell identity: `www-data` inside `q618-wp8335-target`.

The exploit derives the required heap and libphp addresses from HTTP responses,
selects the exact proved profile, uses the stock 150-worker prefork count for
lane selection, and leaves the operator attached to the real callback shell.
No GDB, `/proc`, supplied runtime addresses, simulated prompt, automatic
`whoami`, or automatic defacement is used.

## Run

```powershell
.\START-LAB.cmd
```

Open the printed URL and verify the normal WordPress homepage. In a second
PowerShell window:

```powershell
.\EXPLOIT.cmd
```

Type commands normally after the target prompt appears. See
[`VIDEO-DEMO.md`](VIDEO-DEMO.md) for the recording sequence and the
manual `NADSEC / PWNED` homepage command.

After recording, use a separate terminal:

```powershell
.\STOP-LAB.cmd
```

Every start restores the original WordPress `index.php`. Use
`STOP-LAB.cmd -Reset` only when you also want to remove the package-owned
database and web volumes.

## Requirements

- Windows PowerShell or Command Prompt;
- Windows Python 3 for `START-LAB.cmd` and `STOP-LAB.cmd`;
- Docker Desktop with Linux containers;
- the Docker images referenced by the package already present locally.

The exploit itself runs inside the package's private Python container. Host
Python is used only by the small start/stop controller.

## Scope

The wrappers read the package-owned state file and operate only on the target
created by `START-LAB.cmd`. Chrome reaches it through loopback. The callback
and exploit traffic stay on the private Docker network. This package is for
the bundled local lab, not arbitrary IP addresses.
