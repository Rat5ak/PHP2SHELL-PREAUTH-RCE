param([switch]$Reset)

$ErrorActionPreference = 'Stop'
$package = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $package 'lab.py'

$python = Get-Command python.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1
$prefix = @()
if (-not $python) {
    $python = Get-Command py.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    $prefix = @('-3')
}
if (-not $python) {
    Write-Error 'Windows Python 3 was not found on PATH.'
    exit 2
}

$arguments = $prefix + @($runner, 'stop')
if ($Reset) { $arguments += '--reset' }
& $python.Source @arguments
exit $LASTEXITCODE
