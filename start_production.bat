
@echo off
echo Starting AI Security Tester - Production Mode
echo =============================================

echo Starting Backend Services...
cd /d "%~dp0backend"
start "Main Platform API" python simple_async_main.py
timeout /t 3 /nobreak > nul
start "AI Orchestrator" python pentest_api.py
timeout /t 3 /nobreak > nul

echo Starting Frontend...
cd /d "%~dp0frontend"
start "Frontend" npm run dev

echo =============================================
echo AI Security Tester is running in Production Mode
echo Main Platform: http://localhost:3000
echo AI Orchestrator: http://localhost:3000/pentest
echo =============================================
pause
