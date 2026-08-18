@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

set "PYTHON_EXE=C:\Users\xgf\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PYTHON_EXE%" (
    set "PYTHON_EXE=python"
)

set "SCRIPT_DIR=%~dp0"
set "SCRIPT=%SCRIPT_DIR%cf_tri_net_detect.py"
set "CIDR_FILE=%SCRIPT_DIR%cidr.txt"

set "CIDR=%~1"
if "%CIDR%"=="" set "CIDR=172.64.229.0/22"

set "THREADS=%~2"
if "%THREADS%"=="" set "THREADS=100"

cd /d "%SCRIPT_DIR%"

echo ============================================
echo Cloudflare Scan
echo Threads: %THREADS%
echo Time: %date% %time%
echo ============================================
echo.

if exist "%CIDR_FILE%" (
    echo Using cidr.txt
    "%PYTHON_EXE%" "%SCRIPT%" --cidr-file "%CIDR_FILE%" --threads %THREADS% --ping-count 2 --csv-only --ip-txt --iptest --display 30
) else (
    echo Using CIDR: %CIDR%
    "%PYTHON_EXE%" "%SCRIPT%" %CIDR% --threads %THREADS% --ping-count 2 --csv-only --ip-txt --iptest --display 30
)

echo.
echo Done.
echo.

pause
