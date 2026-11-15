@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if not exist "%~dp0START-LAB.ps1" (
    echo ERROR: Package files are missing. Extract the complete ZIP first.
    exit /b 2
)

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0START-LAB.ps1" %*
exit /b %ERRORLEVEL%
