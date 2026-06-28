#Requires -Version 5.1
$Host.UI.RawUI.WindowTitle = "ASN IP Scanner - Web UI"

Write-Host "╔══════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     ASN IP Scanner Web UI    ║" -ForegroundColor Cyan
Write-Host "║   ASN - Cloudflare Scanner   ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "[*] $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] Python 未安装，请先安装 Python 3.8+" -ForegroundColor Red
    Write-Host "    下载: https://www.python.org/downloads/" -ForegroundColor Yellow
    Read-Host "按回车退出"
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check/install dependencies
$deps = @("flask", "psutil")
foreach ($dep in $deps) {
    $check = python -c "import $dep" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[*] 安装 $dep ..." -ForegroundColor Yellow
        pip install $dep
    }
}

# Verify project files
if (-not (Test-Path "$scriptDir\verify.py")) {
    Write-Host "[!] 未找到 verify.py，请确认项目完整性" -ForegroundColor Red
    Read-Host "按回车退出"
    exit 1
}

Write-Host "[*] 启动 Web 服务..." -ForegroundColor Green
Write-Host ""
Write-Host "  Open browser: http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

python "$scriptDir\webui.py"
Read-Host "按回车退出"
