$ErrorActionPreference = 'Stop'

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Join-Path $PackageRoot 'prior-art-php2shell-joas\labs\phpmyadmin-functional-stock'
$VulnerableCompose = Join-Path $LabRoot 'docker-compose.yml'
$FixedCompose = Join-Path $LabRoot 'docker-compose.fixed.yml'

foreach ($ComposeFile in @($VulnerableCompose, $FixedCompose)) {
    if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
        Write-Host "ERROR: required package file is missing: $ComposeFile" -ForegroundColor Red
        exit 2
    }
    & docker compose -f $ComposeFile down --volumes --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: docker compose down failed for $ComposeFile" -ForegroundColor Red
        exit 1
    }
}

Write-Host 'STATUS=STOPPED'
