@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

REM — Prefer venv Python if present
set PY=%CD%\venv\Scripts\python.exe
if not exist "%PY%" set PY=python

REM Candidates to try, in order
set "CAND_1=%CD%\data\training.csv"
set "CAND_2=%CD%\phishing_training_dataset_full.csv"
set "CAND_3=%CD%\phishing_training_dataset_1000.csv"

set "TRAIN_CSV="

for %%F in ("%CAND_1%" "%CAND_2%" "%CAND_3%") do (
  if exist %%~fF (
    set "TRAIN_CSV=%%~fF"
    goto :found
  )
)

echo [ERROR] No dataset found.
echo Looked for:
echo   %CAND_1%
echo   %CAND_2%
echo   %CAND_3%
echo Put your CSV in one of those paths (recommended: data\training.csv).
pause
exit /b 1

:found
echo [TRAIN] Using "!TRAIN_CSV!"
echo [TRAIN] Starting...
"%PY%" -c "import os; os.environ['TRAIN_CSV']=r'!TRAIN_CSV!'; import app; from app import train_and_save, ML_THRESHOLD, p; train_and_save(os.environ['TRAIN_CSV'], p('phish_model.joblib'), ML_THRESHOLD)"
if errorlevel 1 (
  echo [TRAIN] Failed.
  pause
  exit /b 1
)

echo [TRAIN] Done. Model saved as phish_model.joblib
pause
