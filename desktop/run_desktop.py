import threading, time, sys, os, webview

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0, ROOT)

from app import app  # adjust if app.py is inside app_web

def run_flask():
    app.run(host="127.0.0.1", port=7070, debug=False, use_reloader=False)

if __name__ == "__main__":
    t = threading.Thread(target=run_flask, daemon=True)
    t.start()
    time.sleep(1.0)
    webview.create_window("Phishing Detector", "http://127.0.0.1:7070", width=1200, height=800)
    webview.start()
