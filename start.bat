@echo off
title SecureMailScope - Launcher
echo ===================================================
echo           SecureMailScope Server Launcher
echo ===================================================
echo.

cd /d "%~dp0"

echo [1/2] Starting FastAPI Backend on http://localhost:8001 ...
start "SecureMailScope - Backend (Port 8001)" cmd /k "cd /d "%~dp0backend" && (if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat)) && python main.py"

echo [2/2] Starting Vite Frontend on http://localhost:5173 ...
start "SecureMailScope - Frontend (Port 5173)" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ===================================================
echo  Both servers have been launched in new windows!
echo  - Backend API:    http://localhost:8001
echo    (API Docs:      http://localhost:8001/docs)
echo  - Frontend App:   http://localhost:5173
echo ===================================================
echo.
pause