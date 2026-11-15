$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

docker compose -f labs\phpmyadmin-functional-stock\docker-compose.yml up -d --force-recreate
docker compose -f labs\phpmyadmin-functional-stock\docker-compose.fixed.yml up -d --force-recreate

$targets = @(
    @{ Name = "Vulnerable PHP 8.4.26"; Url = "http://127.0.0.1:18212/" },
    @{ Name = "Patched PHP 8.4.27"; Url = "http://127.0.0.1:18213/" }
)

foreach ($target in $targets) {
    $ready = $false
    foreach ($attempt in 1..40) {
        $body = curl.exe -fsS $target.Url 2>$null
        if ($LASTEXITCODE -eq 0 -and $body -match "loginform") {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw "$($target.Name) did not return the clean phpMyAdmin login page"
    }
    if ($body -match "NADSEC PWNED") {
        throw "$($target.Name) is not clean"
    }
    Write-Host "[READY] $($target.Name): $($target.Url)" -ForegroundColor Green
}

docker exec p2s-phpmyadmin-functional-stock sh -c "test ! -e /var/www/html/index.html && test ! -e /var/www/html/index.php.bak"
if ($LASTEXITCODE -ne 0) {
    throw "Vulnerable target still contains a demo artifact"
}

Write-Host "Both browser targets are clean and ready for recording." -ForegroundColor Cyan
