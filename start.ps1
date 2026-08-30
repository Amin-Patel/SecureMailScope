Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "          SecureMailScope Server Launcher" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $rootDir) { $rootDir = Get-Location }

Write-Host "[1/2] Starting FastAPI Backend on http://localhost:8001 ..." -ForegroundColor Green
$backendCmd = "cd `"$rootDir\backend`"; if (Test-Path `".\venv\Scripts\Activate.ps1`") { .\venv\Scripts\Activate.ps1 }; python main.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

Write-Host "[2/2] Starting Vite Frontend on http://localhost:5173 ..." -ForegroundColor Green
$frontendCmd = "cd `"$rootDir\frontend`"; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " Both servers have been launched in separate windows!" -ForegroundColor Green
Write-Host " - Backend API:    http://localhost:8001 (Docs: http://localhost:8001/docs)" -ForegroundColor Yellow
Write-Host " - Frontend App:   http://localhost:5173" -ForegroundColor Yellow
Write-Host "===================================================" -ForegroundColor Cyan
