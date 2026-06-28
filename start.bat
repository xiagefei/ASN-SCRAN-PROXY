@echo off
chcp 65001 >nul
title ASN IP Scanner - Web UI
echo.
echo  ╔══════════════════════════════╗
echo  ║     ASN IP Scanner Web UI    ║
echo  ║   ASN - Cloudflare Scanner   ║
echo  ╚══════════════════════════════╝
echo.

:: 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python 未安装，请先安装 Python 3.8+
    echo     下载: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: 检查/安装依赖
echo [*] 检查依赖...
python -c "import flask" 2>nul
if %errorlevel% neq 0 (
    echo [*] 安装依赖...
    pip install -r "%~dp0requirements.txt"
)
python -c "import psutil" 2>nul
if %errorlevel% neq 0 (
    pip install psutil
)

:: 检查 verify.py 存在
if not exist "%~dp0verify.py" (
    echo [!] 未找到 verify.py，请确认项目完整性
    pause
    exit /b 1
)

echo [*] 启动 Web 服务...
echo.
echo  Open browser: http://127.0.0.1:5000
echo  Press Ctrl+C to stop
echo.

python "%~dp0webui.py"
pause
