import os, sys, json, joblib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def bundle_path(*parts):
    base = getattr(sys, "_MEIPASS", ROOT)  # for PyInstaller exe
    return os.path.join(base, *parts)

MODEL_PATH = os.getenv("MODEL_PATH", bundle_path("models", "phishing_detector_model.pkl"))
META_PATH  = os.getenv("MODEL_META_PATH", bundle_path("models", "model_meta.json"))



_model = joblib.load(MODEL_PATH)
try:
    with open(META_PATH, "r", encoding="utf-8") as f:
        ML_THRESHOLD = float(json.load(f).get("ml_threshold", 0.60))
except Exception:
    ML_THRESHOLD = 0.60

def predict_ml_proba(text: str) -> float:
    return float(_model.predict_proba([text])[0][1])

def detect_with_scoring(email_text: str) -> dict:
    text = email_text.lower()
    ml_p = predict_ml_proba(text)
    reasons, risk = [], 0

    if "account suspended" in text or "verify your" in text:
        reasons.append("Matched phishing keyword"); risk += 25
    if ".ru" in text or ".cn" in text or ".xyz" in text:
        reasons.append("Suspicious TLD"); risk += 20
    if ".exe" in text or ".bat" in text:
        reasons.append("Suspicious attachment"); risk += 25

    if ml_p >= ML_THRESHOLD:
        reasons.append(f"ML probability high {ml_p:.2f}"); risk += 20
    else:
        reasons.append(f"ML probability low {ml_p:.2f}")

    if risk >= 55:
        return {"final_label": "Phishing", "detection_type": "TP",
                "ml_probability": ml_p, "risk_score": risk, "reasons": reasons}
    elif risk <= 25:
        return {"final_label": "Safe", "detection_type": "Safe",
                "ml_probability": ml_p, "risk_score": risk, "reasons": reasons}
    else:
        return {"final_label": "Safe", "detection_type": "FN",
                "ml_probability": ml_p, "risk_score": risk, "reasons": reasons}
