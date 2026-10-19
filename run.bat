@echo off
title AI Safety Summit - Entrance Check-in & Cloudflare Tunnel
cd /d "%~dp0"
echo ==============================================================
echo  AI Safety Summit 2026 - Entrance & Pass System
echo ==============================================================
echo.

if not exist ".env" (
    echo Missing .env configuration.
    echo Copy .env.example to .env and configure secrets and Cloudflare Access first.
    pause
    exit /b 1
)

findstr /r /c:"^CF_ACCESS_TEAM_DOMAIN=." ".env" >nul
if errorlevel 1 (
    echo Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD in .env before exposing the app.
    pause
    exit /b 1
)
findstr /r /c:"^CF_ACCESS_AUD=." ".env" >nul
if errorlevel 1 (
    echo Set CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD in .env before exposing the app.
    pause
    exit /b 1
)

if not exist delegates.db (
    echo Seeding delegates database...
    python seed.py
    if errorlevel 1 (
        echo Seeding failed. Check the configuration and delegates.csv.
        pause
        exit /b 1
    )
    echo.
)

where cloudflared >nul 2>nul
if errorlevel 1 (
    if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" (
        set "CLOUDFLARED=C:\Program Files (x86)\cloudflared\cloudflared.exe"
    ) else (
        echo cloudflared was not found. Install it or add it to PATH.
        pause
        exit /b 1
    )
) else (
    set "CLOUDFLARED=cloudflared"
)

if not exist "%USERPROFILE%\.cloudflared\config.yml" (
    echo Missing named-tunnel config: %USERPROFILE%\.cloudflared\config.yml
    echo Create a named Cloudflare Tunnel and configure its ingress first.
    pause
    exit /b 1
)

echo [1/2] Starting local FastAPI server on http://127.0.0.1:8000 ...
start "FastAPI Server" /min python -m uvicorn app:app --host 127.0.0.1 --port 8000

echo [2/2] Launching configured Cloudflare Tunnel...
echo.
echo ==============================================================
echo Cloudflare Access must protect the scanner and staff API paths.
echo ==============================================================
echo.
"%CLOUDFLARED%" tunnel run
pause
