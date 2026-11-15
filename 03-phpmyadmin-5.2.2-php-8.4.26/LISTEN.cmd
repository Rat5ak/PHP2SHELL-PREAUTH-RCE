@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if not exist "%~dp0LISTEN.ps1" (
    echo ERROR: LISTEN.ps1 is missing. Extract the complete package first.
    exit /b 2
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0LISTEN.ps1"
exit /b %ERRORLEVEL%
