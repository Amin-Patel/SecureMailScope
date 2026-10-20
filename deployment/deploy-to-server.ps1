#!/usr/bin/env pwsh
<#
.SYNOPSIS
Deploy SecureMailScope to thebigthree server via Tailscale SSH

.DESCRIPTION
This script deploys the SecureMailScope application to the remote server using Tailscale SSH.
It copies files, installs dependencies, and sets up the application.
#>

$ErrorActionPreference = "Stop"
$SERVER = "patel_aminn@thebigthree"
$REMOTE_DIR = "/home/patel_aminn/SecureMailScope"
$LOCAL_DIR = Split-Path -Parent $PSScriptRoot

Write-Host "🚀 SecureMailScope Deployment Script" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create remote directory
Write-Host "📁 Creating remote directory..." -ForegroundColor Yellow
tailscale ssh $SERVER "mkdir -p $REMOTE_DIR/{backend,frontend}"

# Step 2: Copy backend files
Write-Host "📦 Copying backend files..." -ForegroundColor Yellow
$backendFiles = @(
    "backend/main.py",
    "backend/requirements.txt",
    "backend/app",
    "backend/test-data"
)

foreach ($file in $backendFiles) {
    Write-Host "  Copying $file..." -ForegroundColor Gray
    $localFilePath = Join-Path $LOCAL_DIR $file
    if (Test-Path $localFilePath -PathType Container) {
        # Directory - use recursive copy
        tailscale ssh $SERVER "mkdir -p $REMOTE_DIR/$file"
        scp -r "$localFilePath/*" "${SERVER}:${REMOTE_DIR}/${file}/"
    } else {
        # File
        scp "$localFilePath" "${SERVER}:${REMOTE_DIR}/${file}"
    }
}

# Step 3: Copy frontend files
Write-Host "📦 Copying frontend files..." -ForegroundColor Yellow
$frontendFiles = @(
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/vite.config.js",
    "frontend/index.html",
    "frontend/src",
    "frontend/public"
)

foreach ($file in $frontendFiles) {
    Write-Host "  Copying $file..." -ForegroundColor Gray
    $localFilePath = Join-Path $LOCAL_DIR $file
    if (Test-Path $localFilePath -PathType Container) {
        tailscale ssh $SERVER "mkdir -p $REMOTE_DIR/$file"
        scp -r "$localFilePath/*" "${SERVER}:${REMOTE_DIR}/${file}/"
    } else {
        scp "$localFilePath" "${SERVER}:${REMOTE_DIR}/${file}"
    }
}

# Step 4: Copy environment files (if they exist)
Write-Host "🔐 Copying environment files..." -ForegroundColor Yellow
$backendEnv = Join-Path $LOCAL_DIR "backend/.env"
if (Test-Path $backendEnv) {
    scp $backendEnv "${SERVER}:${REMOTE_DIR}/backend/.env"
    Write-Host "  ✓ Backend .env copied" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Backend .env not found - you'll need to create it manually" -ForegroundColor Yellow
}

$frontendEnv = Join-Path $LOCAL_DIR "frontend/.env"
if (Test-Path $frontendEnv) {
    scp $frontendEnv "${SERVER}:${REMOTE_DIR}/frontend/.env"
    Write-Host "  ✓ Frontend .env copied" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Frontend .env not found - you'll need to create it manually" -ForegroundColor Yellow
}

# Step 5: Install Python dependencies
Write-Host "🐍 Installing Python dependencies..." -ForegroundColor Yellow
tailscale ssh $SERVER "cd $REMOTE_DIR/backend && python3 -m pip install --user -r requirements.txt"

# Step 6: Install Node.js dependencies
Write-Host "📦 Installing Node.js dependencies..." -ForegroundColor Yellow
tailscale ssh $SERVER "cd $REMOTE_DIR/frontend && npm install"

# Step 7: Build frontend
Write-Host "🏗️  Building frontend..." -ForegroundColor Yellow
tailscale ssh $SERVER "cd $REMOTE_DIR/frontend && npm run build"

Write-Host ""
Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Configure environment variables:" -ForegroundColor White
Write-Host "   tailscale ssh $SERVER" -ForegroundColor Gray
Write-Host "   nano $REMOTE_DIR/backend/.env" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Start the backend:" -ForegroundColor White
Write-Host "   cd $REMOTE_DIR/backend && python3 -m uvicorn main:app --host 0.0.0.0 --port 8001 &" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Start the frontend:" -ForegroundColor White
Write-Host "   cd $REMOTE_DIR/frontend && npm run preview -- --host 0.0.0.0 --port 5173 &" -ForegroundColor Gray
Write-Host ""
Write-Host "Access the application at:" -ForegroundColor Cyan
Write-Host "  Frontend: http://100.102.43.85:5173" -ForegroundColor White
Write-Host "  Backend:  http://100.102.43.85:8001" -ForegroundColor White
Write-Host ""
