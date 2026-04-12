@echo off
setlocal
cd /d "%~dp0"

echo [RUN] Step 1: Training model...
call "%~dp0\train_auto.bat"
if errorlevel 1 (
  echo [RUN] Training failed. Exiting.
  pause
  exit /b 1
)

echo [RUN] Step 2: Starting Flask app...
call "%~dp0\start_app.bat"
