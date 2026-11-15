$ErrorActionPreference = 'Stop'

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Join-Path $PackageRoot 'prior-art-php2shell-joas\labs\phpmyadmin-functional-stock'
$VulnerableCompose = Join-Path $LabRoot 'docker-compose.yml'
$FixedCompose = Join-Path $LabRoot 'docker-compose.fixed.yml'

function Stop-WithError([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Compose([string]$ComposeFile, [string[]]$Arguments) {
    & docker compose -f $ComposeFile @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "docker compose failed for $ComposeFile"
    }
}

function Wait-CleanLogin([string]$Name, [string]$Url) {
    foreach ($Attempt in 1..120) {
        $Body = & curl.exe -fsS --max-time 5 $Url 2>$null
        if ($LASTEXITCODE -eq 0 -and $Body -match 'loginform') {
            if ($Body -match 'NADSEC|PWNED') {
                Stop-WithError "$Name still contains a demo marker"
            }
            return
        }
        Start-Sleep -Milliseconds 500
    }
    Stop-WithError "$Name did not return the clean phpMyAdmin login page"
}

foreach ($Required in @($VulnerableCompose, $FixedCompose, (Join-Path $LabRoot 'Dockerfile'), (Join-Path $LabRoot 'config.inc.php'))) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        Stop-WithError "required package file is missing: $Required"
    }
}

& docker version *> $null
if ($LASTEXITCODE -ne 0) {
    Stop-WithError 'Docker Desktop is unavailable'
}

Invoke-Compose $VulnerableCompose @('up', '-d', '--build', '--force-recreate', '--remove-orphans')
Invoke-Compose $FixedCompose @('up', '-d', '--build', '--force-recreate', '--remove-orphans')

$VulnerableUrl = 'http://127.0.0.1:18212/'
$FixedUrl = 'http://127.0.0.1:18213/'
Wait-CleanLogin 'Vulnerable PHP 8.4.26 target' $VulnerableUrl
Wait-CleanLogin 'Patched PHP 8.4.27 target' $FixedUrl

$VulnerablePort = (& docker port p2s-phpmyadmin-functional-stock '80/tcp' 2>$null | Select-Object -First 1)
$FixedPort = (& docker port p2s-phpmyadmin-functional-fixed '80/tcp' 2>$null | Select-Object -First 1)
if ($VulnerablePort -ne '127.0.0.1:18212' -or $FixedPort -ne '127.0.0.1:18213') {
    Stop-WithError "unexpected listener binding: vulnerable=$VulnerablePort fixed=$FixedPort"
}

foreach ($Container in @('p2s-phpmyadmin-functional-stock', 'p2s-phpmyadmin-functional-fixed')) {
    & docker exec $Container sh -lc 'test ! -e /var/www/html/index.html && test ! -e /var/www/html/index.php.bak && test ! -e /var/www/html/x26 && test ! -e /var/www/html/x29 && test ! -e /var/www/html/x30'
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "$Container contains a stale demonstration artifact"
    }
}

$VulnerablePhp = (& docker exec p2s-phpmyadmin-functional-stock php -r 'echo PHP_VERSION;').Trim()
$FixedPhp = (& docker exec p2s-phpmyadmin-functional-fixed php -r 'echo PHP_VERSION;').Trim()
if ($VulnerablePhp -ne '8.4.26' -or $FixedPhp -ne '8.4.27') {
    Stop-WithError "unexpected PHP versions: vulnerable=$VulnerablePhp fixed=$FixedPhp"
}

& docker exec p2s-phpmyadmin-functional-stock test -f /var/www/html/RELEASE-DATE-5.2.2
if ($LASTEXITCODE -ne 0) {
    Stop-WithError 'phpMyAdmin 5.2.2 identity file is missing'
}

Write-Host "VULNERABLE_URL=$VulnerableUrl"
Write-Host "FIXED_URL=$FixedUrl"
Write-Host 'PHPMYADMIN=5.2.2'
Write-Host "VULNERABLE_PHP=$VulnerablePhp"
Write-Host "FIXED_PHP=$FixedPhp"
Write-Host 'STATUS=READY'
