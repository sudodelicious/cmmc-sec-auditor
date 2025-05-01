@echo off
cd /d "%~dp0"
echo === CMMC Auditor Toolkit ===
powershell -ExecutionPolicy Bypass -File ".\run_audit.ps1"
pause
