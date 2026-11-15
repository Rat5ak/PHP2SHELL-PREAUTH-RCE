$ErrorActionPreference = 'Stop'

$candidates = @()
$onPath = Get-Command ncat.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($onPath) {
    $candidates += $onPath.Source
}
if (${env:ProgramFiles(x86)}) {
    $candidates += Join-Path ${env:ProgramFiles(x86)} 'Nmap\ncat.exe'
}
if ($env:ProgramFiles) {
    $candidates += Join-Path $env:ProgramFiles 'Nmap\ncat.exe'
}

$ncat = $candidates |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
    Select-Object -First 1

if (-not $ncat) {
    Write-Error 'Ncat was not found on PATH or under Program Files\Nmap. Install Nmap/Ncat before recording.'
    exit 2
}

Write-Host 'listening 0.0.0.0:4461'
& $ncat -lvp 4461
exit $LASTEXITCODE
