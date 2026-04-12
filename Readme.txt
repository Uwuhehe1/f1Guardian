# Phishing Detector

## Quick Start (Windows)
1) Install Python 3.11+
2) Unzip the project (e.g., C:\phish-detector)
3) Copy .env.example to .env (edit if needed)
4) Double-click run_app.bat
5) Open http://127.0.0.1:5000

## Sanity Checks
- GET /_health should return "ok"
- Test a safe email and a phishing email via the form

## Updating the Model
- Replace phishing_detector_model.pkl and model_meta.json with your new versions
- Restart the app
