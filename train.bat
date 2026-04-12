@echo off
setlocal

REM — Go to this .bat's folder
cd /d "%~dp0"

REM — Prefer venv Python if present
set PY=%CD%\venv\Scripts\python.exe
if not exist "%PY%" set PY=python

REM — Training CSV we expect by default
set "TRAIN_CSV=%CD%\data\training.csv"

if not exist "%TRAIN_CSV%" (
  echo [ERROR] CSV not found: %TRAIN_CSV%
  echo         Put your dataset at data\training.csv or use the auto-detect script below.
  pause
  exit /b 1
)

echo [TRAIN] Using "%TRAIN_CSV%"
echo [TRAIN] Starting...
"%PY%" -c "import os; os.environ['TRAIN_CSV']=r'%TRAIN_CSV%'; import app; from app import train_and_save, ML_THRESHOLD, p; train_and_save(os.environ['TRAIN_CSV'], p('phish_model.joblib'), ML_THRESHOLD)"
if errorlevel 1 (
  echo [TRAIN] Failed.
  pause
  exit /b 1
)

echo [TRAIN] Done. Model saved as phish_model.joblib
pause
