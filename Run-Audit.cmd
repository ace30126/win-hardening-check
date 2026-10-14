@echo off
rem Double-click to run the read-only hardening audit (asks for admin rights).
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-HardeningAudit.ps1" -Elevate -Pause
