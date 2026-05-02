@echo off
title PatchPilot AI — CVE Intelligence Dashboard
echo.
echo ============================================================
echo   PatchPilot AI — CVE Intelligence Dashboard
echo   http://localhost:8000
echo ============================================================
echo.

python app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to start. Ensure dependencies are installed:
    echo   pip install -r requirements.txt
    pause
)
