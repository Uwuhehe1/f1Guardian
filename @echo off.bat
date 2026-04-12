@echo off
setlocal

rem 1) Start Flask
cd /d "C:\Users\Jullius\OneDrive\Desktop\application"
call ".\venv\Scripts\activate.bat"
start "FlaskServer" cmd /c python app.py

rem 2) Wait a bit for Flask to warm up
timeout /t 4 >nul

rem 3) Start Electron
cd /d "C:\Users\Jullius\OneDrive\Desktop\application\phish-client"
npm start

endlocal
