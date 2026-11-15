$ErrorActionPreference = 'Stop'

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Gate = Join-Path $PackageRoot 'prior-art-php2shell-joas\stock_phpmyadmin_gate.py'
$Container = 'p2s-phpmyadmin-functional-fixed'

if (-not (Test-Path -LiteralPath $Gate -PathType Leaf)) {
    Write-Error 'The packaged fixed-control gate is missing.'
    exit 2
}

$Running = docker inspect --format '{{.State.Running}}' $Container 2>$null
if ($LASTEXITCODE -ne 0 -or $Running -ne 'true') {
    Write-Error 'The fixed PHP 8.4.27 target is not running. Run START-LAB.cmd first.'
    exit 2
}

$Python = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$Prefix = @()
if (-not $Python) {
    $Python = Get-Command py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    $Prefix = @('-3')
}
if (-not $Python) {
    Write-Error 'Windows Python 3 was not found on PATH.'
    exit 2
}

docker exec $Container rm -f /var/www/html/x30 *> $null
$Arguments = $Prefix + @(
    $Gate,
    '--url', 'http://127.0.0.1:18213/show_config_errors.php',
    '--host-header', 'x',
    '--blockers', '149',
    '--settle', '10',
    '--cmd', 'id>x30',
    '--fetch', '/x30',
    '--expect', 'uid=',
    '--leak-tries', '1',
    '--fire-tries', '1',
    '--timeout', '180',
    '--ack-exact-profile'
)

$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $Output = & $Python.Source @Arguments 2>&1
    $GateExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $PreviousErrorAction
}
$Output | ForEach-Object { Write-Host $_ }
$Text = $Output -join "`n"

if ($GateExit -eq 0) {
    Write-Error 'The fixed control unexpectedly reported execution.'
    exit 1
}
if ($Text -notmatch '"status": "leak_failed"' -or
    $Text -notmatch '"heap": "0x0"' -or
    $Text -notmatch '"libphp": "0x0"') {
    Write-Error 'The fixed target did not reproduce the pinned leak-denial receipt.'
    exit 1
}

docker exec $Container test ! -e /var/www/html/x30
if ($LASTEXITCODE -ne 0) {
    Write-Error 'The fixed target contains the forbidden proof file.'
    exit 1
}

$Page = curl.exe -fsS --max-time 10 http://127.0.0.1:18213/ 2>$null
if ($LASTEXITCODE -ne 0 -or -not ($Page -match 'loginform')) {
    Write-Error 'The fixed phpMyAdmin login page is not healthy.'
    exit 1
}

Write-Host 'FIXED_CONTROL_PASS' -ForegroundColor Green
