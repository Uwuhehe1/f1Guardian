@echo off
setlocal
cd /d "%~dp0"

REM Prefer venv Python if present
set PY=%CD%\venv\Scripts\python.exe
if not exist "%PY%" set PY=python

echo [APP] Launching Flask app...
"%PY%" app.py
pause
