@echo off
title Sentinel LLM Security Gateway
chcp 65001 > nul
cd /d "c:\Users\yusuf\Desktop\Yusuf\kod\proje3"

echo ========================================================
echo   🛡️ Sentinel LLM Security Gateway Baslatiliyor...
echo ========================================================

start "" http://localhost:8000

python -m uvicorn security_gateway:app --reload --port 8000
pause
