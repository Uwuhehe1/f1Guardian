from flask import (
    Flask, render_template, request, Response, redirect, url_for, session, g,
    jsonify, send_file, flash
)
import joblib
import json
import csv
import io
import re
import os
import ipaddress
import hashlib
import secrets
import socket
from difflib import SequenceMatcher
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse as _urlparse
from datetime import datetime, date, timedelta
from collections import defaultdict
from functools import wraps


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def p(*parts): return os.path.join(BASE_DIR, *parts)

os.makedirs(p('data'), exist_ok=True)

META_PATH     = os.getenv('MODEL_META_PATH', p('model_meta.json'))
LOG_FILE      = os.getenv('LOG_FILE', p('data', 'phishing_log.json'))
LINK_LOG_FILE = os.getenv('LINK_LOG_FILE', p('data', 'link_log.json'))
CACHE_FILE    = os.getenv('CACHE_FILE', p('data', 'email_cache.json'))
FEEDBACK_PATH = os.getenv('FEEDBACK_PATH', p('data', 'feedback_memory.json'))
USERS_FILE    = os.getenv('USERS_FILE', p('data', 'users.json'))
CONFIG_PATH   = os.getenv('CONFIG_PATH', p('data', 'app_config.json'))
TEMPLATES_DIR = p('templates')
STATIC_DIR    = p('static')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")
_PROCESS_START = datetime.now()


def _read_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return default

def _write_json(path, obj):
    os.makedirs(os.path.dirname(path) or BASE_DIR, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

DEFAULT_CONFIG = {
    "SAFE_RISK_THRESHOLD": int(os.getenv('SAFE_RISK_THRESHOLD', 10)),
    "REVIEW_RISK_THRESHOLD": int(os.getenv('REVIEW_RISK_THRESHOLD', 30)),
    "SUSP_RISK_THRESHOLD": int(os.getenv('SUSP_RISK_THRESHOLD', 60)),
    "STRONG_LINK_THRESHOLD": int(os.getenv('STRONG_LINK_THRESHOLD', 25)),
}

def is_known_phishing(url):
    try:
        with open("data/feedback_memory.json", "r", encoding="utf-8") as f:
            mem = json.load(f)

        url = url.lower()
        domain = url.split("/")[2] if "://" in url else ""

        if url in mem.get("urls", {}):
            return True

        if domain in mem.get("domains", {}):
            return True

    except Exception:
        pass

    return False

def load_app_config():
    cfg = DEFAULT_CONFIG.copy()
    on_disk = _read_json(CONFIG_PATH, {})
    if isinstance(on_disk, dict):
        for k, v in on_disk.items():
            if k in cfg:
                try: cfg[k] = int(v)
                except: pass
    return cfg

def save_app_config(cfg: dict) -> bool:
    try:
        _write_json(CONFIG_PATH, cfg)
        return True
    except Exception:
        return False

APP_CONFIG = load_app_config()
SAFE_RISK_THRESHOLD   = APP_CONFIG["SAFE_RISK_THRESHOLD"]
REVIEW_RISK_THRESHOLD = APP_CONFIG["REVIEW_RISK_THRESHOLD"]
SUSP_RISK_THRESHOLD   = APP_CONFIG["SUSP_RISK_THRESHOLD"]
STRONG_LINK_THRESHOLD = APP_CONFIG["STRONG_LINK_THRESHOLD"]

MODEL_PATH = os.getenv('MODEL_PATH', p('phish_model.joblib'))
LEGACY_PKL = p('phishing_detector_model.pkl')
TRAIN_CSV = os.getenv("TRAIN_CSV", p("data", "training.csv"))

def _load_threshold() -> float:
    try:
        with open(META_PATH, 'r', encoding='utf-8') as f:
            return float(json.load(f).get('ml_threshold', 0.50))
    except Exception:
        try:
            return float(os.getenv('MODEL_ML_THRESHOLD', 0.50))
        except Exception:
            return 0.50

ML_THRESHOLD = _load_threshold()


def resolve_model_path() -> str:
    env_path = os.getenv('MODEL_PATH')
    if env_path and os.path.exists(env_path):
        print(f"[MODEL] Using env MODEL_PATH: {env_path}")
        return env_path
    for cand in (MODEL_PATH, LEGACY_PKL):
        if os.path.exists(cand):
            print(f"[MODEL] Auto-detected model: {cand}")
            return cand
    print(f"[MODEL] No model found; will default to {MODEL_PATH}")
    return MODEL_PATH

MODEL_PATH = resolve_model_path()

def load_model():
    try:
        if os.path.exists(MODEL_PATH):
            print(f"[MODEL] Loading: {MODEL_PATH}")
            return joblib.load(MODEL_PATH)
        if os.path.exists(LEGACY_PKL):
            print(f"[MODEL] Loading legacy pickle: {LEGACY_PKL}")
            return joblib.load(LEGACY_PKL)
        raise FileNotFoundError("No model file found")
    except Exception as e:
        print(f"[MODEL-LOAD] Could not load model: {e}")
    class _MockModel:
        def predict_proba(self, X): 
            return [[1.0, 0.0] for _ in X]
    return _MockModel()

model = load_model()

URL_MODEL_PATH = os.getenv("URL_MODEL_PATH", p("models", "url_model.joblib"))

def load_url_model():
    try:
        if os.path.exists(URL_MODEL_PATH):
            print(f"[URL-MODEL] Loading: {URL_MODEL_PATH}")
            return joblib.load(URL_MODEL_PATH)
        print(f"[URL-MODEL] Not found: {URL_MODEL_PATH}")
    except Exception as e:
        print(f"[URL-MODEL] Could not load URL model: {e}")
    return None

url_model = load_url_model()


def save_meta(threshold: float):
    meta = {"ml_threshold": float(threshold), "saved_at": datetime.now().isoformat()}
    _write_json(META_PATH, meta)


def train_and_save(csv_path: str, out_model: str, threshold: float = None):
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Training CSV not found: {csv_path}")

    last_err = None
    df = None
    for opts in (
        dict(sep=',', engine='python', quotechar='"', escapechar='\\', on_bad_lines='skip'),
        dict(sep=';', engine='python', quotechar='"', escapechar='\\', on_bad_lines='skip'),
        dict(sep='\t', engine='python', on_bad_lines='skip'),
    ):
        try:
            df = pd.read_csv(csv_path, **opts)
            if df is not None: break
        except Exception as e:
            last_err = e
            df = None
    if df is None:
        try:
            df = pd.read_csv(csv_path, on_bad_lines='skip')
        except Exception as e:
            raise last_err or e

    cols_lower = [str(c).strip().lower() for c in df.columns]
    if not {'text', 'label'}.issubset(set(cols_lower)):
        if df.shape[1] < 2:
            raise ValueError("CSV must have at least two columns: text,label")
        df = df.iloc[:, :2]
        df.columns = ['text', 'label']
    else:
        colmap = {}
        for c in df.columns:
            lc = str(c).strip().lower()
            if lc == 'text':  colmap[c] = 'text'
            if lc == 'label': colmap[c] = 'label'
        df = df.rename(columns=colmap)

    df = df.dropna(subset=['text', 'label'])
    df['label'] = (
        df['label'].astype(str).str.strip().str.lower()
        .map({'1':1,'0':0,'phish':1,'phishing':1,'spam':1,'benign':0,'ham':0})
    )
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)
    if df.empty:
        raise ValueError("Training CSV produced an empty dataset after cleanup.")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_df=0.95)),
        ("clf", LogisticRegression(max_iter=500, class_weight="balanced"))
    ])
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    print("\n=== Training finished ===")
    print(classification_report(y_test, y_pred, digits=3))

    joblib.dump(pipe, out_model)
    print(f"✅ Saved model to {out_model}")
    if threshold is not None: save_meta(threshold)
    return pipe


cache_db = _read_json(CACHE_FILE, {})
def save_cache(): _write_json(CACHE_FILE, cache_db)

def _feedback_blank(): return {"texts": {}, "urls": {}, "domains": {}, "events": []}
feedback_mem = _read_json(FEEDBACK_PATH, _feedback_blank())
if not isinstance(feedback_mem, dict): feedback_mem = _feedback_blank()
for k in ("texts", "urls", "domains"): feedback_mem.setdefault(k, {})
feedback_mem.setdefault("events", [])
def save_feedback(): _write_json(FEEDBACK_PATH, feedback_mem)


def _normalize_user_db(db):
    if not isinstance(db, dict): db = {}
    db.setdefault("by_id", {})
    db.setdefault("by_email", {})
    db.setdefault("by_username", {})
    changed = False
    for uid, u in list(db["by_id"].items()):
        uname = (u.get("username") or "").strip().lower()
        if not uname:
            email = (u.get("email") or "").strip().lower()
            if "@" in email:
                uname = email.split("@")[0]
            if uname:
                u["username"] = uname
                changed = True
        if uname and db["by_username"].get(uname) != uid:
            db["by_username"][uname] = uid
            changed = True
        em = (u.get("email") or "").strip().lower()
        if em and db["by_email"].get(em) != uid:
            db["by_email"][em] = uid
            changed = True
    if changed: _write_json(USERS_FILE, db)
    return db

def _load_users(): return _normalize_user_db(_read_json(USERS_FILE, {}))
def _save_users(db): _write_json(USERS_FILE, _normalize_user_db(db))

def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def _new_user_password(password: str) -> Tuple[str, str]:
    salt = secrets.token_hex(16)
    return salt, _hash_password(password, salt)

def _verify_password(password: str, salt: str, password_hash: str) -> bool:
    return _hash_password(password, salt) == password_hash

def _find_user_by_id(uid: str):
    db = _load_users()
    return db["by_id"].get(uid)

def _find_user_by_email(email: str):
    db = _load_users()
    uid = db["by_email"].get((email or "").lower())
    return db["by_id"].get(uid) if uid else None

def _find_user_by_username(username: str):
    db = _load_users()
    uid = db["by_username"].get((username or "").lower())
    return db["by_id"].get(uid) if uid else None

def _find_user_by_login(login: str):
    login = (login or "").strip()
    if "@" in login: return _find_user_by_email(login)
    return _find_user_by_username(login)

def _post_login_redirect_for(user):
    nxt = session.pop("next", None) or request.args.get("next")
    if nxt: return nxt
    if user.get("role") == "admin": return url_for("admin_home")
    return url_for("index")

def _create_user(name: str, email: str, password: str, role: str = "user", username: str = None) -> Tuple[bool, dict]:
    name = (name or "").strip()
    email = (email or "").strip().lower()
    username = (username or "").strip().lower() or (email.split("@")[0] if "@" in email else "")
    if not name or not email or not password or not username:
        return False, {"error": "missing"}
    if not re.fullmatch(r"[a-z0-9_]{3,24}", username):
        return False, {"error": "bad_username"}
    db = _load_users()
    if email in db["by_email"]: return False, {"error": "email_exists"}
    if username in db["by_username"]: return False, {"error": "username_exists"}
    salt, pw_hash = _new_user_password(password)
    uid = secrets.token_hex(12)
    user = {
        "id": uid, "name": name, "email": email, "username": username,
        "role": role, "salt": salt, "password_hash": pw_hash,
        "created_at": datetime.now().isoformat(), "last_login": None
    }
    db["by_id"][uid] = user
    db["by_email"][email] = uid
    db["by_username"][username] = uid
    _save_users(db)
    return True, user

def _update_user_password(email: str, new_password: str) -> bool:
    db = _load_users()
    uid = db["by_email"].get((email or "").lower())
    if not uid: return False
    user = db["by_id"].get(uid)
    if not user: return False
    salt, pw_hash = _new_user_password(new_password)
    user["salt"] = salt
    user["password_hash"] = pw_hash
    _save_users(db)
    return True

# keep original signature used by admin reset route
def _update_user_password_by_id(uid: str, new_password: str) -> bool:
    db = _load_users()
    user = db["by_id"].get(uid)
    if not user: return False
    salt, pw_hash = _new_user_password(new_password)
    user["salt"] = salt
    user["password_hash"] = pw_hash
    _save_users(db)
    return True

def _set_last_login(uid: str):
    db = _load_users()
    u = db["by_id"].get(uid)
    if not u: return
    u["last_login"] = datetime.now().isoformat()
    _save_users(db)

def _seed_admin_if_needed():
    admin_email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    admin_pass  = os.getenv("ADMIN_PASSWORD") or ""
    admin_name  = os.getenv("ADMIN_NAME", "Administrator").strip() or "Administrator"
    if not admin_email or not admin_pass: return
    existing = _find_user_by_email(admin_email)
    if existing:
        if existing.get("role") != "admin":
            db = _load_users()
            db["by_id"][existing["id"]]["role"] = "admin"
            _save_users(db)
        return
    username = admin_email.split("@")[0]
    _create_user(admin_name, admin_email, admin_pass, role="admin", username=username)

_seed_admin_if_needed()

# ---- Protect Admin Accounts (UI cannot delete/reset these) ----
def _is_protected_admin(user: dict) -> bool:
    """True if this account should not be deleted or reset from the UI."""
    if not user:
        return False
    admin_email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    env_admin_user = (os.getenv("ADMIN_USER") or "admin").strip().lower()
    role = (user.get("role") or "").strip().lower()
    uname = (user.get("username") or "").strip().lower()
    email = (user.get("email") or "").strip().lower()
    return (
        role == "admin"
        or (admin_email and email == admin_email)
        or (env_admin_user and uname == env_admin_user)
    )

# Expose to Jinja templates
app.jinja_env.globals["_is_protected_admin"] = _is_protected_admin


PUBLIC_ENDPOINTS = {
    "auth_login", "auth_signup", "auth_logout", "_health", "static", "admin_login",
}

# ---------------- Admin access gate ----------------
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "password123")

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def _require_login_for_nonpublic():
    if request.path.endswith('/favicon.ico'): return
    endpoint = request.endpoint
    if endpoint in PUBLIC_ENDPOINTS or endpoint is None:
        return
    if request.path.startswith("/admin"):
        if session.get("admin_logged_in"): return
        return redirect(url_for("admin_login", next=request.path))
    uid = session.get("user_id")
    if not uid:
        session["next"] = request.full_path
        return redirect(url_for("auth_login"))
    u = _find_user_by_id(uid)
    if not u:
        session.pop("user_id", None)
        session["next"] = request.full_path
        return redirect(url_for("auth_login"))
    g.user = u


def _read_json_list(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    changed = False
    for e in data:
        if "detection_type" not in e or not e.get("detection_type"):
            e["detection_type"] = "TP" if e.get("phishing") else "Safe"
            changed = True
        # ✅ only TP or FN count as phishing-present
        desired_badge = e.get("detection_type", "Safe") in ("TP", "FN")
        if e.get("phishing") != desired_badge:
            e["phishing"] = desired_badge
            changed = True
    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    return data

def log_result(email_text: str, is_phishing: bool, detection_type="Safe",
               details=None, detection_reason=None):
    """Append one detection record to data/phishing_log.json and normalize flags."""
    phishing_flag = detection_type in ("TP", "FN", "Suspicious")
    entry = {
        "email": email_text,
        "phishing": phishing_flag,
        "detection_type": detection_type,
        "details": details or "",
        "detection_reason": detection_reason or "",
        "timestamp": datetime.now().isoformat(),
    }
    data = _read_json_list(LOG_FILE)
    data.append(entry)
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _safe_parse_ts(ts_str):
    if not ts_str: return None
    s = str(ts_str).strip()
    try: return datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception: pass
    for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ','%Y-%m-%dT%H:%M:%SZ','%Y-%m-%d %H:%M:%S','%Y-%m-%d'):
        try: return datetime.strptime(s, fmt)
        except Exception: continue
    return None

def _fmt_timedelta(td: timedelta) -> str:
    secs = int(td.total_seconds())
    days, secs = divmod(secs, 86400)
    hrs, secs = divmod(secs, 3600)
    mins, _ = divmod(secs, 60)
    parts = []
    if days: parts.append(f"{days} day{'s' if days!=1 else ''}")
    if hrs: parts.append(f"{hrs} hour{'s' if hrs!=1 else ''}")
    if mins and not days: parts.append(f"{mins} min")
    return ", ".join(parts) or "just now"


def admin_required_wrap(f):  # (kept for compatibility if referenced anywhere)
    return admin_required(f)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        login_value = (
            request.form.get("username")
            or request.form.get("login")
            or request.form.get("email")
            or ""
        ).strip()
        password = request.form.get("password") or ""

        if login_value.lower() == ADMIN_USER.lower() and password == ADMIN_PASS:
            session["admin_logged_in"] = True
            return redirect(request.args.get("next") or url_for("admin_home"))

        user = _find_user_by_login(login_value)
        if user and user.get("role") == "admin" and _verify_password(password, user["salt"], user["password_hash"]):
            session["user_id"] = user["id"]
            _set_last_login(user["id"])
            session["admin_logged_in"] = True
            return redirect(request.args.get("next") or url_for("admin_home"))

        error = "Invalid admin credentials."

    return render_template("admin_login.html", error=error)

@app.route("/admin/logout", endpoint="admin_logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("auth_login"))

def _admin_kpis_from_logs():
    raw = _read_json_list(LOG_FILE)
    total_scans = len(raw)
    today = date.today()
    today_scans = sum(1 for e in raw if (_safe_parse_ts(e.get('timestamp','')) or datetime.min).date() == today)
    phish_count = sum(1 for e in raw if e.get('phishing') is True)
    phish_rate = round((phish_count / total_scans) * 100, 2) if total_scans else 0.0
    tp_total = sum(1 for e in raw if e.get('detection_type') == 'TP')
    fn_total = sum(1 for e in raw if e.get('detection_type') == 'FN')
    denom = (tp_total + fn_total)
    accuracy = round((tp_total/denom)*100, 2) if denom else 100.0
    last_trained = "-"
    meta = _read_json(META_PATH, {})
    if isinstance(meta, dict) and meta.get("saved_at"):
        last_trained = meta["saved_at"].split('.')[0].replace('T',' ')
    model_version = "joblib"
    try:
        if os.path.exists(MODEL_PATH):
            model_version = f"mtime-{int(os.path.getmtime(MODEL_PATH))}"
    except: pass
    return {
        "total_scans": total_scans,
        "today_scans": today_scans,
        "phish_count": phish_count,
        "phish_rate": phish_rate,
        "accuracy": accuracy,
        "last_trained": last_trained,
        "model_version": model_version
    }

# ---- shared getter so list & detail use same slice/order
def _recent_items(n=10):
    data = _read_json_list(LOG_FILE)
    return list(reversed(data[-n:]))

def _list_recent_detections(n=8):
    items = _recent_items(n)
    rows = []
    for idx, e in enumerate(items):
        ts = _safe_parse_ts(e.get("timestamp","")) or datetime.now()
        dtype = e.get("detection_type","Safe")

        # ✅ unify label mapping
        if dtype in ("TP","FN"):
            ux_label = "phishing"
        elif dtype == "Suspicious":
            ux_label = "suspicious"
        elif dtype == "Review":
            ux_label = "review"
        else:
            ux_label = "safe"

        details = e.get("details","") or ""
        m = re.search(r'Risk Score:\s*(\d+)', details)
        risk_pct = 0
        if m:
            try: risk_pct = int(m.group(1))
            except: risk_pct = 0
        else:
            m2 = re.search(r'ML Probability:\s*([0-9.]+)', details)
            if m2:
                try: risk_pct = int(float(m2.group(1))*100)
                except: pass

        rows.append({
            "id": idx,
            "time": ts.strftime("%Y-%m-%d %H:%M"),
            "label": ux_label,
            "score": max(0, min(risk_pct, 100))/100.0,
            "preview": (e.get("email","") or "").replace("\n"," ")[:180]
        })
    return rows

@app.route("/admin")
@admin_required
def admin_home():
    msg = request.args.get("msg") or "Admin access confirmed."
    kpis = _admin_kpis_from_logs()
    users_db = _load_users()
    users_count = len(users_db.get("by_id", {}))
    admin_count = sum(1 for u in users_db.get("by_id", {}).values() if u.get("role") == "admin")
    active_today = sum(
        1 for u in users_db.get("by_id", {}).values()
        if u.get("last_login") and (_safe_parse_ts(u["last_login"]) or datetime.min).date() == date.today()
    )
    uptime_str = _fmt_timedelta(datetime.now() - _PROCESS_START)
    host = socket.gethostname()
    build_id = os.getenv("BUILD_ID", f"build-{datetime.now().strftime('%Y.%m.%d')}")

    template_name = "admin.html"
    try:
        if not os.path.exists(os.path.join(TEMPLATES_DIR, template_name)):
            template_name = "admin_home.html"
    except Exception:
        template_name = "admin_home.html"

    return render_template(
        template_name,
        admin_banner=msg,
        kpis=kpis,
        recent_detections=_list_recent_detections(10),
        users={"count": users_count, "active_today": active_today, "admins": admin_count},
        system={"uptime": uptime_str, "hostname": host, "build": build_id},
        now=datetime.utcnow()
    )

# ---------------- Admin Users (UI + actions) ----------------
@app.route("/admin/users", methods=["GET"], endpoint="admin_users")
@admin_required
def admin_users_list():
    db = _load_users()
    users = list(db.get("by_id", {}).values())
    try:
        return render_template("admin_users.html", users=users)
    except Exception:
        rows = []
        for u in users:
            if _is_protected_admin(u):
                actions_html = "<span class='badge bg-secondary'>protected</span>"
            else:
                actions_html = (
                    f"<form method='POST' action='/admin/users/{u['id']}/reset-password' class='d-inline'>"
                    f"<input class='form-control form-control-sm d-inline-block' style='width:180px' "
                    f"name='new_password' placeholder='New password' minlength='8' required>"
                    f"<button class='btn btn-sm btn-warning ms-2'>Reset PW</button></form>"
                    f"<form method='POST' action='/admin/users/{u['id']}/delete' class='d-inline ms-2' "
                    f"onsubmit=\"return confirm('Delete user {u.get('username','user')}? This cannot be undone.');\">"
                    f"<button class='btn btn-sm btn-danger'>Delete</button></form>"
                )
            rows.append(
                f"<tr>"
                f"<td>{u.get('name','')}</td>"
                f"<td>{u.get('username','')}</td>"
                f"<td>{u.get('email','')}</td>"
                f"<td>{u.get('role','')}</td>"
                f"<td>{u.get('last_login','—')}</td>"
                f"<td>{actions_html}</td>"
                f"</tr>"
            )
        html = (
            "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>"
            "<div class='container p-3'><h3>Users</h3>"
            "<a class='btn btn-success mb-3' href='/admin/users/create'>Add User</a>"
            "<table class='table table-striped'><thead><tr>"
            "<th>Name</th><th>Username</th><th>Email</th><th>Role</th><th>Last login</th><th>Actions</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
        )
        return app.response_class(html, mimetype="text/html")


@app.route("/admin/users/create", methods=["GET", "POST"], endpoint="admin_users_create")
@admin_required
def admin_users_create():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        username = (request.form.get("username") or "").strip().lower()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "user").strip().lower()

        if role not in ("user", "admin"):
            role = "user"

        ok, res = _create_user(name, email, password, role=role, username=username)
        if ok:
            return redirect(url_for("admin_users"))

        msg = (
            "Email already exists." if res.get("error") == "email_exists"
            else "Username already exists." if res.get("error") == "username_exists"
            else "Username must be 3–24 chars: a–z, 0–9, underscore." if res.get("error") == "bad_username"
            else "Please fill out all fields."
        )
        try:
            return render_template(
                "admin_user_new.html",
                error=msg,
                name=name,
                username=username,
                email=email,
                role=role
            )
        except Exception:
            return app.response_class(f"<p style='color:red'>{msg}</p>", mimetype="text/html")

    try:
        return render_template("admin_user_new.html")
    except Exception:
        html = (
            "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>"
            "<div class='container p-3'><h3>Add User</h3>"
            "<form method='POST' class='row g-3'>"
            "<div class='col-md-6'><label class='form-label'>Full Name</label><input class='form-control' name='name' required></div>"
            "<div class='col-md-6'><label class='form-label'>Username</label><input class='form-control' name='username' required minlength='3' maxlength='24'></div>"
            "<div class='col-md-6'><label class='form-label'>Email</label><input class='form-control' type='email' name='email' required></div>"
            "<div class='col-md-6'><label class='form-label'>Password</label><input class='form-control' type='password' name='password' required minlength='8'></div>"
            "<div class='col-md-4'><label class='form-label'>Role</label>"
            "<select class='form-select' name='role'><option value='user'>user</option><option value='admin'>admin</option></select></div>"
            "<div class='col-12'><button class='btn btn-success'>Create</button> "
            "<a class='btn btn-outline-secondary' href='/admin/users'>Cancel</a></div></form></div>"
        )
        return app.response_class(html, mimetype="text/html")


@app.route("/admin/users/<uid>/reset-password", methods=["POST"])
@admin_required
def admin_users_reset_password(uid):
    db = _load_users()
    target = db.get("by_id", {}).get(uid)
    if not target:
        return jsonify({"ok": False, "error": "User not found."}), 404

    if _is_protected_admin(target):
        flash("Protected admin accounts cannot be reset here.", "danger")
        return redirect(url_for("admin_users"))

    new_pw = request.form.get("new_password", "")
    if len(new_pw) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("admin_users"))

    _update_user_password_by_id(uid, new_pw)
    flash(f"Password for {target.get('username', 'user')} updated.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<uid>/delete", methods=["POST"])
@admin_required
def admin_users_delete(uid):
    db = _load_users()
    user = db.get("by_id", {}).get(uid)
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404

    if _is_protected_admin(user):
        flash("Protected admin accounts cannot be deleted.", "danger")
        return redirect(url_for("admin_users"))

    db["by_id"].pop(uid, None)
    db["by_email"].pop((user.get("email") or "").lower(), None)
    db["by_username"].pop((user.get("username") or "").lower(), None)
    _save_users(db)

    flash(f"User {user.get('username', uid)} deleted successfully.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/stats", endpoint="admin_stats")
@admin_required
def admin_stats():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        raw = []

    daily = {
        "TP": defaultdict(int),
        "FN": defaultdict(int),
        "Safe": defaultdict(int)
    }
    daily_phish = defaultdict(int)

    tp_total = fn_total = safe_total = 0
    phish_total = 0
    first_d = last_d = None

    for e in raw:
        if e.get("phishing") is True:
            phish_total += 1

        ts = _safe_parse_ts(e.get("timestamp", ""))
        if not ts:
            continue

        d = ts.date()
        first_d = d if first_d is None or d < first_d else first_d
        last_d = d if last_d is None or d > last_d else last_d

        if e.get("phishing") is True:
            daily_phish[d] += 1

        dtype = e.get("detection_type", "Safe")
        if dtype == "TP":
            daily["TP"][d] += 1
            tp_total += 1
        elif dtype == "FN":
            daily["FN"][d] += 1
            fn_total += 1
        else:
            daily["Safe"][d] += 1
            safe_total += 1

    if first_d is None:
        first_d = last_d = date.today()

    ninety_days_ago = date.today() - timedelta(days=89)
    if first_d < ninety_days_ago:
        first_d = ninety_days_ago

    labels, tp_counts, fn_counts, safe_counts, phish_counts = [], [], [], [], []
    cur = first_d
    while cur <= last_d:
        labels.append(cur.isoformat())
        tp_counts.append(daily["TP"].get(cur, 0))
        fn_counts.append(daily["FN"].get(cur, 0))
        safe_counts.append(daily["Safe"].get(cur, 0))
        phish_counts.append(daily_phish.get(cur, 0))
        cur += timedelta(days=1)

    return render_template(
        "statistics.html",
        dates=labels,
        tp_counts=tp_counts,
        fn_counts=fn_counts,
        safe_counts=safe_counts,
        phish_counts=phish_counts,
        tp_total=tp_total,
        fn_total=fn_total,
        safe_total=safe_total,
        phish_total=phish_total
    )


@app.route("/admin/history", endpoint="admin_history")
@admin_required
def admin_history():
    detections = _read_json_list(LOG_FILE)
    detections.reverse()
    for e in detections:
        e["email"] = make_readable_email(e.get("email", ""))
    return render_template("detection_history.html", detections=detections)


@app.route("/admin/link-history", endpoint="admin_link_history")
@admin_required
def admin_link_history():
    detections = _read_json_list(LINK_LOG_FILE)
    detections.reverse()
    return render_template("link_history.html", link_detections=detections)


@app.route("/admin/detection/<int:id>", endpoint="admin_view_detection")
@admin_required
def admin_view_detection(id: int):
    items = _recent_items(10)  # MUST match the list size on admin_home
    if 0 <= id < len(items):
        e = items[id]
    else:
        return app.response_class("<p>Detection not found.</p>", mimetype="text/html"), 404

    html = [
        "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>",
        "<div class='container py-3'>",
        "<a class='btn btn-secondary btn-sm mb-3' href='/admin'>Back</a>",
        "<div class='card shadow-sm'><div class='card-body'>",
        f"<h5 class='card-title'>Detection Detail</h5>",
        f"<div><strong>Timestamp:</strong> {e.get('timestamp', '-')}</div>",
        f"<div><strong>Type:</strong> {e.get('detection_type', '-')}</div>",
        f"<div><strong>Reason:</strong> {e.get('detection_reason', '-')}</div>",
        "<hr>",
        "<h6>Email (rendered):</h6>",
        f"<pre class='p-2 bg-light border rounded' style='white-space:pre-wrap'>{(e.get('email', '') or '')}</pre>",
        "<hr>",
        "<h6>Details:</h6>",
        f"<div>{e.get('details', '').replace('<br>', '<br/>')}</div>",
        "</div></div></div>"
    ]
    return app.response_class("".join(html), mimetype="text/html")


@app.route("/admin/logs/download", endpoint="download_logs")
@admin_required
def download_logs():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)
    return send_file(LOG_FILE, as_attachment=True, download_name="phishing_log.json")


@app.route("/admin/model/retrain", endpoint="trigger_model_retrain")
@admin_required
def trigger_model_retrain():
    train_csv = os.getenv("TRAIN_CSV", p("data", "training.csv"))
    try:
        train_and_save(train_csv, MODEL_PATH, threshold=ML_THRESHOLD)
        global model
        model = joblib.load(MODEL_PATH)
        msg = f"Model retrained from {os.path.basename(train_csv)}."
    except Exception as e:
        msg = f"Retrain failed: {e}"
    return redirect(url_for("admin_home", msg=msg))


@app.route("/admin/cache/clear", endpoint="clear_cache")
@admin_required
def clear_cache():
    cache_db.clear()
    save_cache()
    msg = "Cache cleared."
    return redirect(url_for("admin_home", msg=msg))

@app.route('/_debug/feedback_path')
def _debug_feedback_path():
    return FEEDBACK_PATH, 200, {'Content-Type': 'text/plain; charset=utf-8'}


DISALLOWED_SCHEMES = {'javascript:', 'data:', 'file:'}
SUSPICIOUS_PORTS = {
    '81','82','83','88','89','90','98','99','110','143','2082','2083','2222',
    '3000','3001','3306','3389','444','465','5432','5800','5900','6000','6666',
    '8000','8001','8008','8080','8081','8082','8083','8443','9000','9001','9999'
}
OPEN_REDIRECT_PARAM_HINTS = {
    'next','url','redirect','redir','dest','destination','redirect_uri','redirect_url','redirect_to',
    'goto','go','out','continue','cont','forward','to','u','r','target','link','return','returnurl',
    'returnto','service','relaystate','samlrequest','samlresponse','state','callback','cb','login_redirect',
    'openid.return_to','oauth_redirect','oauth_callback','client_return','client_redirect','nav','jump','path',
    'page','out_url','ext','exit','forward_url','ext_url','continueto'
}
OBFUSCATION_FIXES = [
    (r'hxxps?://', 'http://'),
    (r'httxps?://', 'http://'),
    (r'\[\.]', '.'),
    (r'\(\.\)', '.'),
    (r'\\\.', '.'),
    (r'\(dot\)', '.'),
    (r'\[dot\]', '.'),
    (r'\{dot\}', '.'),
    (r'd0t', '.'),
    (r'\[\/]', '/'),
    (r'\(\/\)', '/'),
    (r'\/', '/'),
    (r'\[at\]', '@'),
    (r'\(at\)', '@'),
    (r'\{at\}', '@'),
    (r'\s@\s', '@'),
    (r'fxp://', 'ftp://'),
    (r'fxps://', 'ftps://'),
    (r'＠', '@'),
    (r'。', '.'),
    (r'／', '/'),
    (r'：', ':'),
]
UNICODE_SNEAKY = [
    '\u200b', '\u200c', '\u200d', '\u2060', '\uFEFF', '\u202a','\u202b','\u202c','\u202d','\u202e',
    '\u2066','\u2067','\u2068','\u2069', '\u00AD','\u034F','\u061C','\u115F','\u1160','\u17B4','\u17B5','\u180E',
    '\u200e','\u200f','\u202f','\u205f','\u3000',
]
MALWARE_KEYWORDS = [
    '.exe','.bat','.scr','.pif','.cmd','.js','.vbs','.jar','.apk','.msi','.ps1','.reg','.lnk',
    '.hta','.wsf','.chm','.dll','trojan','worm','virus','backdoor','payload','ransomware','keylogger'
]
SUSPICIOUS_DOMAINS = [
    'bit.ly','tinyurl.com','xyz.ru','abc123.com','paypal-login.com','apple.verify.com',
    'google.secure-login.net','secure-facebook.com','secure-instagram.com',
    'login-microsoft.net','facebo0k.com','faceb0ok.com','y0utube.com','tikt0k.com'
]
HIGH_RISK_KEYWORDS = [
    'otp','verify account','account suspended','account locked',
    'unusual login','unauthorized access','confirm identity','verify identity',
    'secure it now','security alert','update payment','payment declined',
    'reset password','login now','click here immediately','bank details','wire transfer',
    'password reset','verify login','session expired','identity verification required',
    'update billing','billing issue','subscription expired','renew subscription',
    'credit card declined','paypal verification','gcash verification','bitcoin transfer',
    'limited time offer','urgent action required','permanent suspension','legal action','final reminder'
]
MEDIUM_RISK_KEYWORDS = [
    'urgent','immediate attention','time sensitive','limited time','act now','respond quickly',
    'offer ends soon','last chance','money transfer','cash reward','free prize','gift card',
    'discount voucher','verify email','confirm now','account notice','security verification',
    'subscription renewal','free trial','exclusive access','preferred customer','special bonus'
]
LOW_RISK_KEYWORDS = [
    'free','freebie','giveaway','bonus','reward','trial offer','exclusive free',
    'won','winner','winning entry','congratulations','selected winner','lucky draw','discount',
    'promo','voucher','coupon','offer code','flash sale','best deal','act fast','redeem','points balance'
]

PHISHING_KEYWORDS = HIGH_RISK_KEYWORDS + MEDIUM_RISK_KEYWORDS + LOW_RISK_KEYWORDS

OFFICIAL_DOMAINS = [
    'paypal.com','google.com','facebook.com','microsoft.com','apple.com','youtube.com','x.com','amazon.com','gcash.com'
]
SUSPICIOUS_TLDS = {
    # Common phishing-heavy
    'top', 'xyz', 'icu', 'cfd', 'sbs', 'gq', 'tk', 'ml', 'ga', 'cf',
    'work', 'click', 'link', 'fit', 'rest', 'country', 'stream',
    'download', 'racing', 'science', 'party', 'loan',

    # New cheap gTLDs abused
    'accountant', 'win', 'review', 'date', 'faith', 'bid', 'trade',
    'men', 'cam', 'buzz', 'asia', 'study', 'mom', 'bar', 'fun',
    'pics', 'photo', 'live', 'online', 'site', 'space', 'uno',
    'kim', 'wang', 'icu', 'zip', 'mov',

    # More suspicious
    'host', 'hosting', 'website', 'cloud', 'services', 'design',
    'shop', 'store', 'pw', 'info', 'biz', 'pro', 'cc', 'vc',
    'lol', 'pizza', 'red', 'blue', 'green', 'surf', 'skin',
    'yoga', 'gdn', 'rest', 'fit', 'ink', 'quest', 'cyou',

    # Region-specific but widely abused
    'ru', 'su', 'cn', 'asia', 'tk', 'gq', 'ml', 'ga', 'cf',
    'cm', 'ng', 'ke', 'tz', 'vn', 'in', 'bd', 'pk', 'hk',
    'ph', 'id', 'lk', 'np',

    # Crypto / finance bait
    'crypto', 'capital', 'money', 'finance', 'financial', 'loan',
    'bank', 'cash', 'fund', 'investments', 'forex', 'gold',
    'markets', 'trading', 'exchange',

    # Techy / baity
    'support', 'help', 'secure', 'security', 'verify', 'solutions',
    'systems', 'exchange', 'market', 'consulting', 'technology',
    'cloud', 'server', 'it', 'dev', 'digital', 'ai',

    # Extra catch-alls & brand-imitating
    'club', 'vip', 'monster', 'press', 'today', 'agency',
    'network', 'tube', 'world', 'expert', 'company',
    'email', 'group', 'media', 'plus', 'team', 'zone',
    'global', 'intl', 'services', 'biz', 'click',
    'work', 'tools', 'guru', 'tips', 'review', 'report',
    'life', 'care', 'health', 'doctor', 'clinic', 'pharmacy',
    'store', 'shop', 'sale', 'deal', 'discount', 'cheap',

    # Newer/odd ones abused recently
    'hair', 'beauty', 'skin', 'makeup', 'diet', 'food',
    'homes', 'house', 'realty', 'property', 'rent', 'loan',
    'tickets', 'travel', 'holiday', 'fly', 'jet', 'cruise',
    'game', 'bet', 'poker', 'casino', 'lotto', 'win',
    'love', 'dating', 'sex', 'adult', 'porn',

    # Weird / misleading TLDs
    'work', 'tools', 'rest', 'zone', 'guru', 'bio',
    'eco', 'eco', 'ngo', 'ong', 'protection',
    'army', 'navy', 'mil', 'gov', 'edu'  # (spoofing attempts)
}

URL_KEYWORDS = {'login','verify','update','secure','password','account','reset','confirm','bank','otp','gcash','pogo'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','cutt.ly','is.gd','rebrand.ly','lnkd.in'}
BRAND_KEYWORDS = {
    # Existing
    'allegro': 'allegro.pl',
    'allegrolokalnie': 'allegrolokalnie.pl',

    # Common financial targets
    'paypal': 'paypal.com',
    'gcash': 'gcash.com',
    'bdo': 'bdo.com.ph',
    'bpi': 'bpi.com.ph',
    'unionbank': 'unionbankph.com',
    'metrobank': 'metrobank.com.ph',
    'securitybank': 'securitybank.com',

    # Global banks / payments
    'hsbc': 'hsbc.com',
    'chase': 'chase.com',
    'boa': 'bankofamerica.com',
    'wellsfargo': 'wellsfargo.com',
    'citibank': 'citi.com',
    'revolut': 'revolut.com',

    # Big tech
    'google': 'google.com',
    'gmail': 'gmail.com',
    'facebook': 'facebook.com',
    'meta': 'meta.com',
    'instagram': 'instagram.com',
    'tiktok': 'tiktok.com',
    'youtube': 'youtube.com',
    'twitter': 'x.com',     # now X
    'microsoft': 'microsoft.com',
    'outlook': 'outlook.com',
    'office': 'office.com',
    'apple': 'apple.com',
    'icloud': 'icloud.com',
    'amazon': 'amazon.com',
    'netflix': 'netflix.com',

    # E-commerce
    'ebay': 'ebay.com',
    'lazada': 'lazada.com.ph',
    'shopee': 'shopee.ph',
    'zalora': 'zalora.com.ph',

    # Government / utilities (optional, depends on your context)
    'pagibig': 'pagibigfund.gov.ph',
    'sss': 'sss.gov.ph',
    'philhealth': 'philhealth.gov.ph',
    'meralco': 'meralco.com.ph',

    # Crypto / payment services
    'binance': 'binance.com',
    'coinbase': 'coinbase.com',
    'crypto': 'crypto.com'
}

safe_business_words = [
    "booking", "receipt", "fare", "paid", "passenger",
    "training", "contract", "recruitment", "batch", "schedule"
]

URL_KEYWORDS_POLISH = {
    'oferta','logowanie','weryfikacja','haslo','hasło','konto',
    'potwierdz','potwierdź','platnosc','płatność','przelew'
}

def deobfuscate_text(s: str) -> str:
    t = s
    for pat, rep in OBFUSCATION_FIXES:
        t = re.sub(pat, rep, t, flags=re.IGNORECASE)
    for ch in UNICODE_SNEAKY:
        t = t.replace(ch, '')
    return t

def obfuscation_present(s: str) -> bool:
    s = s or ""
    tokens = ['hxxp', '[.]', '(.)', '(dot)', '[dot]', '{dot}', '\/', '(\/)', '[at]', '(at)', '{at}']
    s_lower = s.lower()
    return any(tok in s_lower for tok in tokens)

def normalize_email_text(txt: str) -> str:
    if not txt: return txt
    return deobfuscate_text(txt).replace('**','').replace('__','')

def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def normalize_url(url: str) -> str:
    u = url.strip().strip(').,;\'"<>]')
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*:', u):
        u = 'http://' + u
    return u

def idn_to_ascii(host: str) -> str:
    try:
        out = []
        for label in host.split('.'):
            try: out.append(label.encode('idna').decode('ascii'))
            except Exception: out.append(label)
        return '.'.join(out)
    except Exception:
        return host

def extract_links(text: str):
    clean = normalize_email_text(text)
    rx = re.compile(
        r'((?:https?://|www\.)[^\s<>"\'\)\]]+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\')\]]*)?)'
    )
    candidates = rx.findall(clean)
    return [c for c in candidates if '.' in c and re.search(r'[a-zA-Z0-9]', c)]

def extract_domain(url: str) -> str:
    try:
        nurl = normalize_url(url)
        parsed = _urlparse(nurl)
        host = parsed.netloc.lower()
        if host.startswith('www.'): host = host[4:]
        if '@' in host: host = host.split('@', 1)[-1]
        if ':' in host: host = host.split(':', 1)[0]
        return idn_to_ascii(host)
    except Exception:
        return ''

def is_ip_link(url: str) -> bool:
    try:
        domain = extract_domain(url).split(':')[0]
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False

def is_similar(a: str, b: str) -> bool:
    return SequenceMatcher(None, a, b).ratio() > 0.85

def registered_domain(domain: str) -> str:
    parts = domain.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain

def count_percent_encoded(s: str) -> int:
    return len(re.findall(r'%[0-9a-fA-F]{2}', s))

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    from math import log2
    freq = {ch: s.count(ch) for ch in set(s)}
    return -sum((c/len(s))*log2(c/len(s)) for c in freq.values())

def has_non_ascii(s: str) -> bool:
    try:
        s.encode('ascii'); return False
    except UnicodeEncodeError:
        return True

def looks_like_punycode(domain: str) -> bool:
    return domain.startswith('xn--') or '.xn--' in domain

def excessive_subdomains(domain: str, limit: int = 3) -> bool:
    return domain.count('.') >= limit

def brand_mismatch(domain: str, url: str):
    rd = registered_domain(domain)
    hits = []
    lower_url = url.lower()
    for brand, official in BRAND_KEYWORDS.items():
        if brand in lower_url and rd != official:
            hits.append(brand)
    return hits

TRUSTED_DOMAINS = {
    
    "chatgpt.com",
    "openai.com",
    "google.com",
    "accounts.google.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "messenger.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "tiktok.com",
    "reddit.com",
    "netflix.com",
    "spotify.com",
    "twitch.tv",
    "vimeo.com",
    "gmail.com",
    "outlook.com",
    "office.com",
    "live.com",
    "yahoo.com",
    "zendesk.com",
    "slack.com",
    "zoom.us",
    "atlassian.com",
    "jira.com",
    "trello.com",
    "notion.so",
    "notion.site",
    "paypal.com",
    "stripe.com",
    "shopify.com",
    "ebay.com",
    "stackoverflow.com",
    "medium.com",
}


def is_trusted_domain(url: str) -> bool:
    try:
        parsed = _urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.split(":")[0].lower()  

        return any(
            domain == d or domain.endswith("." + d)
            for d in TRUSTED_DOMAINS
        )
    except Exception:
        return False


def analyze_url(url: str):
    # 🔒 ABSOLUTE PRIORITY: trusted domains
    if is_trusted_domain(url):
        return 0, ["trusted domain allowlist"]

    reasons = []
    nurl = normalize_url(url)

    try:
        parsed = _urlparse(nurl)
    except Exception:
        parsed = _urlparse("http://" + nurl)

    scheme = (parsed.scheme or "").lower() + ":"
    if scheme in DISALLOWED_SCHEMES:
        return 50, [f"disallowed scheme {scheme}"]

    d = extract_domain(nurl)
    rd = registered_domain(d)
    score = 0
    url_l = nurl.lower()

    # -------- Domain-level checks --------
    if any(bad in d for bad in SUSPICIOUS_DOMAINS):
        score += 30
        reasons.append("domain matches suspicious list")

    if rd in SHORTENERS:
        score += 12
        reasons.append("URL shortener")

    if is_ip_link(nurl):
        score += 25
        reasons.append("IP address in host")

    if any(is_similar(d, legit) and d != legit for legit in OFFICIAL_DOMAINS):
        score += 18
        reasons.append("lookalike to official domain")

    if looks_like_punycode(d):
        score += 40
        reasons.append("punycode in domain")
    elif has_non_ascii(d):
        score += 10
        reasons.append("non-ASCII chars in domain")

    # -------- TLD / structure --------
    tld = d.split(".")[-1] if "." in d else ""
    if tld in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"suspicious TLD .{tld}")

    if excessive_subdomains(d):
        score += 8
        reasons.append("excessive subdomains")

    host = parsed.netloc.lower()
    if ":" in host:
        port = host.rsplit(":", 1)[-1]
        if port.isdigit() and port in SUSPICIOUS_PORTS:
            score += 8
            reasons.append(f"suspicious port :{port}")

    host_and_path = parsed.netloc + parsed.path + ("?" + parsed.query if parsed.query else "")
    if "@" in host_and_path:
        score += 10
        reasons.append("'@' in URL")

    if count_percent_encoded(nurl) >= 3:
        score += 6
        reasons.append("heavy percent-encoding")

    if len(nurl) > 100:
        score += 4
        reasons.append("unusually long URL")

    # -------- Generic hosting / free hosting abuse --------
    HOSTING_RDS = {
        'web.app', 'pages.dev', 'firebaseapp.com', 'appspot.com',
        'blob.core.windows.net', 'azurewebsites.net', 'cloudfront.net',
        'googleapis.com', 'googleusercontent.com', '1drv.ms', 'sharepoint.com',
        'github.io', 'gitlab.io', 'bitbucket.io', 'codeberg.page',
        'sourceforge.net', 'devpost.com', 'repl.co', 'repl.run',
        'myshopify.com', 'wixsite.com', 'weebly.com', 'squarespace.com',
        'bigcartel.com', 'ecwid.com', 'storehippo.com', 'shopifyapps.com',
        'shop-pro.jp', 'base.ec', 'fc2.com',
        'notion.site', 'notion.so', 'xpages.co', 'surge.sh', 'netlify.app',
        'vercel.app', 'render.com', 'herokuapp.com', 'glitch.me',
        'strikingly.com', 'site123.me', 'jimdosite.com', '000webhostapp.com',
        'yolasite.com', 'ucoz.com', 'ucoz.net', 'bravenet.com',
        'altervista.org', 'tripod.com', 'angelfire.com', 'geocities.ws',
        'freewebs.com', 'homestead.com', 'fortiddns.com',
        'dynv6.net', 'duckdns.org', 'hopto.org', 'zapto.org', 'ddns.net',
        'freeddns.org', 'no-ip.com', 'sytes.net', 'servehttp.com',
        'ath.cx', 'is-a.dev', 'is-a.fun', 'is-an.app',
        'mediafire.com', 'mega.nz', 'anonfiles.com', 'ufile.io',
        'file.io', 'sendspace.com', 'zippyshare.com', 'krakenfiles.com',
        'pixeldrain.com', 'gofile.io', 'bayfiles.com', 'files.fm',
        'filetransfer.io', 'filemail.com', 'uploadfiles.io', 'wetransfer.com',
        'dropmb.com', 'mixdrop.co', 'easyupload.io',
        'pastebin.com', 'controlc.com', 'justpaste.it', 'hastebin.com',
        'pastelink.net', 'privatebin.net', 'paste.ee',
        'blogspot.com', 'wordpress.com', 'tumblr.com',
        'medium.com', 'ghost.io', 'substack.com',
        'livetemplate.me', '000webhost.com', 'awardspace.com',
        'byethost.com', '5gbfree.com', 'infinityfreeapp.com',
        'ic.cz', 'hostingerapp.com', 'freehosting.com', 'freehostia.com',
        '20m.com', 'angelfire.lycos.com', 'skyrock.com'
    }

    if rd in HOSTING_RDS:
        brands_in_url = [b for b in BRAND_KEYWORDS.keys() if b in url_l]
        brands_in_url = [b for b in brands_in_url if BRAND_KEYWORDS[b] != rd]
        if brands_in_url:
            score += 18
            reasons.append(
                f"brand bait on generic hosting ({rd}): {', '.join(sorted(set(brands_in_url)))}"
            )

    # -------- Keyword checks --------
    if any(k in url_l for k in URL_KEYWORDS):
        score += 10
        reasons.append("phishing keywords in path/query")

    if any(k in url_l for k in URL_KEYWORDS_POLISH):
        score += 10
        reasons.append("phishing keywords (PL) in path/query")

    # -------- Path checks --------
    ppath = parsed.path or ""
    if len(ppath) > 30 and shannon_entropy(ppath) > 3.5:
        score += 6
        reasons.append("high-entropy path")

    mism = brand_mismatch(d, nurl)
    if mism:
        score += 30
        reasons.append(f"brand/domain mismatch: {', '.join(mism)}")

    # -------- Query parameter checks --------
    q = {}
    if parsed.query:
        for kv in parsed.query.split("&"):
            if not kv:
                continue
            if "=" in kv:
                k, v = kv.split("=", 1)
            else:
                k, v = kv, ""
            q.setdefault(k.lower(), []).append(v)

    if q:
        CRED_PARAMS = {'email', 'e', 'user', 'username', 'login', 'id', 'password', 'pass', 'pwd', 'otp', 'token', 'code'}
        if any(k in CRED_PARAMS for k in q.keys()):
            score += 12
            hit = ", ".join(sorted(CRED_PARAMS.intersection(q.keys())))
            reasons.append(f"credential params in query: {hit}")

    if rd in OFFICIAL_DOMAINS and q:
        for k, vals in q.items():
            if k in OPEN_REDIRECT_PARAM_HINTS:
                for v in vals:
                    if v.startswith("http"):
                        try:
                            tgt = _urlparse(v)
                            thost = idn_to_ascii((tgt.netloc or "").lower())
                            trd = registered_domain(thost)
                            if trd and trd != rd:
                                score += 14
                                reasons.append(f"open-redirect param '{k}' to {trd}")
                                break
                        except Exception:
                            continue

    # -------- Suspicious extension checks --------
    SUSP_EXTS = (".php", ".asp", ".aspx", ".jsp", ".cgi")
    if any(ppath.lower().endswith(ext) for ext in SUSP_EXTS) and any(k in url_l for k in URL_KEYWORDS):
        score += 12
        reasons.append("login file extension with credential wording")

    if scheme == "http:" and any(k in url_l for k in URL_KEYWORDS):
        score += 6
        reasons.append("HTTP with credential keywords")

    # -------- Randomized subdomain / many brands --------
    try:
        labels = host.split("@")[-1].split(":")[0].split(".")
        if labels and labels[0] not in ("www", "m"):
            left = labels[0]
            if len(left) >= 12 and shannon_entropy(left) > 3.3:
                score += 8
                reasons.append("randomized subdomain label")
    except Exception:
        pass

    present_brands = sorted({b for b in BRAND_KEYWORDS.keys() if b in url_l})
    if len(present_brands) >= 2:
        score += 12
        reasons.append(f"multiple brand names in URL: {', '.join(present_brands[:4])}")

    return score, reasons


URL_MODEL_SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update",
    "account", "bank", "paypal", "gcash",
    "confirm", "reset", "signin"
]

def extract_url_ml_features(url: str):
    url = (url or "").lower().strip()
    parsed = _urlparse(url if url.startswith("http") else "http://" + url)

    features = [
        len(url),
        url.count("@"),
        url.count("-"),
        url.count("."),
        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
        int(url.startswith("https")),
        sum(word in url for word in URL_MODEL_SUSPICIOUS_WORDS),
    ]
    return features

def get_url_ml_probability(url: str) -> float:
    try:
        if url_model is None:
            return 0.0
        feats = extract_url_ml_features(url)
        return float(url_model.predict_proba([feats])[0][1])
    except Exception:
        return 0.0

CRITICAL_PATH_WORDS = {'login','signin','verify','revalidate','reset','recover','session','auth','credential','password','account'}

def extract_link_flags(email_text: str):
    urls = extract_links(email_text)
    has_suspicious_tld = False
    has_cred_path = False
    has_puny = False
    max_score = 0
    cred_hit_example = None
    for url in urls:
        score, _ = analyze_url(url)
        if score > max_score: max_score = score
        d = extract_domain(url)
        tld = d.split('.')[-1] if '.' in d else ''
        if tld in SUSPICIOUS_TLDS: has_suspicious_tld = True
        if looks_like_punycode(d): has_puny = True
        try:
            parsed = _urlparse(url if url.startswith('http') else 'http://' + url)
            pathq = (parsed.path or '') + ('?' + parsed.query if parsed.query else '')
        except Exception:
            pathq = url
        for w in CRITICAL_PATH_WORDS:
            if w in pathq.lower():
                has_cred_path = True
                if cred_hit_example is None: cred_hit_example = (url, w)
                break
    return has_suspicious_tld, has_cred_path, max_score, has_puny, cred_hit_example

def has_credential_harvest_link(email_text: str) -> bool:
    has_tld, has_cred_path, max_link_score, _has_puny, _ex = extract_link_flags(email_text)
    if max_link_score >= STRONG_LINK_THRESHOLD: return True
    if has_tld and has_cred_path: return True
    return False

def check_links(urls):
    total = 0
    details = []

    for url in urls:
        heuristic_score, heuristic_reasons = analyze_url(url)

        # ✅ PLACE IT HERE
        if is_trusted_domain(url):
            ml_prob = 0.0
            ml_score = 0
        else:
            ml_prob = get_url_ml_probability(url)
            ml_score = int(ml_prob * 40)

        score = heuristic_score + ml_score
        reasons = list(heuristic_reasons)

        if ml_prob >= 0.50 and not is_trusted_domain(url):
            reasons.append(f"URL ML flagged as phishing ({ml_prob:.2f})")

        if is_known_phishing(url) and not is_trusted_domain(url):
            score += 35
            reasons.append("known phishing URL/domain from memory")

        total += score

        if score > 0:
            details.append({
                "url": url,
                "score": score,
                "ml_probability": round(ml_prob, 3),
                "reasons": reasons
            })

    return total, details

def get_ml_probability(text: str) -> float:
    try:
        return float(model.predict_proba([text])[0][1])
    except Exception:
        return 0.0

def detect_phishing_content(email_text: str) -> dict:
    lower = normalize_email_text(email_text).lower()
    triggered_keywords = [kw for kw in PHISHING_KEYWORDS if kw in lower]
    urls = extract_links(email_text)
    suspicious_links = []
    for url in urls:
        sc, reasons = analyze_url(url)
        if sc > 0:
            suspicious_links.append((url, sc, reasons))
    ml_prob = get_ml_probability(lower)
    return {'triggered_keywords': triggered_keywords,'suspicious_links': suspicious_links,'ml_probability': ml_prob}

def calculate_risk_score(det, email_text):
    score = 0
    risk_factors = []
    lower = email_text.lower()

    safe_hits = [word for word in safe_business_words if word in lower]

    triggered_high = [kw for kw in HIGH_RISK_KEYWORDS if kw in lower]
    triggered_medium = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in lower]
    triggered_low = [kw for kw in LOW_RISK_KEYWORDS if kw in lower]

    keyword_score = len(triggered_high) * 20 + len(triggered_medium) * 10 + len(triggered_low) * 4
    keyword_score -= len(safe_hits) * 5

    if keyword_score < 0:
        keyword_score = 0

    all_kw = triggered_high + triggered_medium + triggered_low

    if keyword_score > 0:
        risk_factors.append(f"Keywords ({keyword_score} pts): " + ", ".join(all_kw[:5]))
        score += keyword_score

    if safe_hits:
        risk_factors.append(f"Safe context (-{len(safe_hits) * 5} pts): " + ", ".join(safe_hits[:5]))

    link_score = sum(link_sc for (_u, link_sc, _r) in det['suspicious_links'])
    if link_score > 0:
        risk_factors.append(f"Suspicious links ({link_score} pts): {len(det['suspicious_links'])} found")
        score += link_score

    ml_score = int(det['ml_probability'] * 40)
    if ml_score >= 15:
        risk_factors.append(f"ML prediction ({ml_score} pts): {det['ml_probability']:.2f} confidence")
        score += ml_score

    kw_counts = {
        'high': len(triggered_high),
        'medium': len(triggered_medium),
        'low': len(triggered_low),
        'link_max': max([sc for (_u, sc, _r) in det['suspicious_links']], default=0)
    }

    return score, risk_factors, kw_counts

def _insert_missing_spaces(s: str) -> str:
    if not s: return s
    t = s
    t = re.sub(r'([.,!?;:])([A-Za-z0-9])', r'\1 \2', t)
    t = re.sub(r'([.!?])([A-Z])', r'\1 \2', t)
    t = re.sub(r'([a-z])([A-Z])', r'\1 \2', t)
    t = re.sub(r'[ \t]{3,}', ' ', t)
    return t

def make_readable_email(raw: str) -> str:
    if not raw: return ""
    lines = raw.splitlines()
    pretty = []
    for ln in lines:
        ln = deobfuscate_text(ln)
        ln = _insert_missing_spaces(ln)
        pretty.append(ln)
    return "\n".join(pretty)

def _remember_feedback(email_text: str):
    ts = datetime.now().isoformat()
    h = content_hash(email_text)
    feedback_mem["texts"][h] = {"text": email_text[:5000], "timestamp": ts}
    urls = extract_links(email_text)
    for u in urls:
        feedback_mem["urls"][u] = ts
        d = extract_domain(u)
        rd = registered_domain(d) if d else ""
        if rd:
            feedback_mem["domains"][rd] = ts
    save_feedback()

def record_user_mark_event(email_text: str, user: str = "anonymous", note: str = "Manual True Positive"):
    ts = datetime.now().isoformat()
    h = content_hash(email_text)
    event = {"timestamp": ts,"user": user,"hash": h,"note": note,"email": email_text}
    feedback_mem.setdefault("events", []).append(event)
    _remember_feedback(email_text)
    save_feedback()
    return event

def _matches_feedback(email_text: str):
    reasons = []
    h = content_hash(email_text)
    if h in feedback_mem.get("texts", {}):
        reasons.append("Previously marked as phishing (manual)")
    urls = extract_links(email_text)
    for u in urls:
        if u in feedback_mem.get("urls", {}):
            reasons.append(f"URL previously user-marked: {u}")
        d = extract_domain(u)
        rd = registered_domain(d) if d else ""
        if rd and rd in feedback_mem.get("domains", {}):
            reasons.append(f"Domain previously user-marked: {rd}")
    cached = cache_db.get(h)
    if cached:
        dr = (cached.get("detection_reason") or "").lower()
        if dr.startswith("manual true positive"):
            if "Previously marked as phishing (manual)" not in reasons:
                reasons.append("Previously marked as phishing (manual)")
    return (len(reasons) > 0), reasons

def build_signal_explanations(
    email_text: str, has_tld: bool, has_cred_path: bool, max_link_score: int, has_puny: bool, cred_example,
    hdr_mismatch: bool, hdr_reply_susp: bool, hdr_from: Optional[str], hdr_reply: Optional[str],
    high_kws: List[str], med_kws: List[str], mal_hits: List[str]
) -> str:
    urls = extract_links(email_text)
    tlds = []
    for u in urls:
        d = extract_domain(u)
        if d:
            tld = d.split('.')[-1] if '.' in d else ''
            if tld: tlds.append(tld)
    max_item = None
    for u in urls:
        s, reasons = analyze_url(u)
        if s == max_link_score:
            max_item = (u, reasons)
            break
    parts = []
    if has_tld:
        risky = [t for t in tlds if t in SUSPICIOUS_TLDS]
        parts.append(f"<li><code>suspicious_tld=True</code>: found high-risk TLD(s) {', '.join(sorted(set(risky)))}.</li>")
    else:
        seen = ", ".join(sorted(set(tlds))) if tlds else "—"
        parts.append(f"<li><code>suspicious_tld=False</code>: TLDs seen [{seen}] are not in high-risk list.</li>")
    if has_cred_path:
        if cred_example:
            url, hit = cred_example
            parts.append(f"<li><code>cred_path=True</code>: URL contains credential word “{hit}”: <code>{url}</code>.</li>")
        else:
            parts.append("<li><code>cred_path=True</code>: credential-related word observed in a URL path/query.</li>")
    else:
        parts.append("<li><code>cred_path=False</code>: no credential-related words in URL paths.</li>")
    if max_link_score > 0 and max_item:
        m_url, m_reasons = max_item
        why = "; ".join(m_reasons[:3]) if m_reasons else "mixed heuristics"
        parts.append(f"<li><code>max_link_score={max_link_score}</code>: strongest URL <code>{m_url}</code> — {why}.</li>")
    else:
        parts.append("<li><code>max_link_score=0</code>: no risky URL features detected.</li>")
    parts.append("<li><code>punycode=True</code>: at least one domain uses IDN/punycode (e.g. “xn--”).</li>" if has_puny
                 else "<li><code>punycode=False</code>: all domains are ASCII; no punycode labels detected.</li>")
    parts.append("<li><code>obfuscation=True</code>: obfuscation like <code>hxxp</code> / <code>[.]</code> / slashes detected.</li>" if obfuscation_present(email_text)
                 else "<li><code>obfuscation=False</code>: links appear in plain form.</li>")
    parts.append(f"<li><code>high_kw=True</code>: high-risk keywords — {', '.join(high_kws[:5])}.</li>" if high_kws
                 else "<li><code>high_kw=False</code>: no high-risk keywords.</li>")
    parts.append(f"<li><code>medium_kw=True</code>: medium-risk terms — {', '.join(med_kws[:5])}.</li>" if med_kws
                 else "<li><code>medium_kw=False</code>: no medium-risk terms.</li>")
    parts.append(f"<li><code>malware_kw=True</code>: malware indicators — {', '.join(mal_hits[:6])}.</li>" if mal_hits
                 else "<li><code>malware_kw=False</code>: no malware indicators detected.</li>")
    return "<ul>" + "\n".join(parts) + "</ul>"

def detect_with_scoring(email_text):
    email_text = normalize_email_text(email_text)

    links = extract_links(email_text)

    max_link_score = 0
    for link in links:
        score, _ = analyze_url(link)
        if score > max_link_score:
            max_link_score = score

    lower = email_text.lower()
    safe_hits = [word for word in safe_business_words if word in lower]

    high_kws = [kw for kw in HIGH_RISK_KEYWORDS if kw in lower]
    med_kws = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in lower]
    mal_hits = [kw for kw in MALWARE_KEYWORDS if kw in lower]

    has_cred_path = any(x in lower for x in ["login", "verify", "password", "account"])
    has_tld = any(tld in lower for tld in SUSPICIOUS_TLDS)
    has_puny = "xn--" in lower

    try:
        ml_prob = float(model.predict_proba([email_text])[0][1])
    except Exception:
        ml_prob = 0.0

    risk_score = (
        len(high_kws) * 20 +
        len(med_kws) * 10 +
        (30 if mal_hits else 0) +
        max_link_score
    )

    hard_tp = bool(mal_hits) or (has_cred_path and max_link_score >= STRONG_LINK_THRESHOLD)

    if hard_tp:
        detection_type = "TP"
        risk_color = "red"
        result = "True Positive: Phishing detected."
        detection_reason = "Hard rule triggered"
        warning = True
    else:
        never_safe = []

        if has_cred_path:
            never_safe.append("credential path")
        if has_tld:
            never_safe.append("suspicious TLD")
        if max_link_score >= STRONG_LINK_THRESHOLD:
            never_safe.append(f"high link score {max_link_score}")
        if has_puny:
            never_safe.append("punycode domain")
        if obfuscation_present(email_text):
            never_safe.append("obfuscation present")

        if mal_hits:
            detection_type = "TP"
            risk_color = "red"
            result = "True Positive: Malware detected."
            detection_reason = ", ".join(mal_hits)
            warning = True

        elif has_cred_path and max_link_score >= STRONG_LINK_THRESHOLD:
            detection_type = "TP"
            risk_color = "red"
            result = "True Positive: Credential phishing detected."
            detection_reason = "Credential path + strong link"
            warning = True

        elif never_safe and not safe_hits:
            detection_type = "Suspicious"
            risk_color = "orange"
            result = "Suspicious indicators found."
            detection_reason = ", ".join(never_safe)
            warning = False

        elif ml_prob < ML_THRESHOLD and (high_kws or max_link_score > 0):
            detection_type = "FN"
            risk_color = "orange"
            result = "False Negative: ML missed phishing."
            detection_reason = f"ML={ml_prob:.2f} below threshold"
            warning = False

        else:
            detection_type = "Safe"
            risk_color = "green"
            result = "Safe email."
            detection_reason = "No threats detected"
            warning = False

    details = f"<strong>Risk Score: {risk_score}</strong><br>"
    details += f"ML Probability: {ml_prob:.3f}<br>"

    return {
    "tp": detection_type == "TP",
    "detection_type": detection_type,
    "warning": warning,
    "risk_color": risk_color,
    "result": result,
    "detection_reason": detection_reason,
    "details": details
}

    det = detect_phishing_content(email_text)
    ml_prob = det['ml_probability']
    normalized_text = normalize_email_text(email_text)
    lower = normalized_text.lower()
    risk_score, risk_factors, kwc = calculate_risk_score(det, normalized_text)

    high_kws = [kw for kw in HIGH_RISK_KEYWORDS if kw in lower]
    med_kws  = [kw for kw in MEDIUM_RISK_KEYWORDS if kw in lower]
    mal_hits = [kw for kw in MALWARE_KEYWORDS if kw in lower]

    has_tld, has_cred_path, max_link_score, has_puny, cred_example = extract_link_flags(normalized_text)

    
    if risk_score >= 70 and ml_prob < ML_THRESHOLD:
        detection_type = "TP"
        risk_color = 'red'
        result = "True Positive: Extremely high-risk indicators found (risk score override)."
        detection_reason = f"Risk score {risk_score} >= 70, ML {ml_prob:.2f} < {ML_THRESHOLD:.2f}"
        details = f"<strong>Risk Score: {risk_score}</strong><br>"
        details += f"ML Probability: {ml_prob:.3f} (threshold {ML_THRESHOLD:.2f})<br>"
        if det['suspicious_links']:
            details += "<br><strong>Suspicious Links:</strong><br>"
            for (url, sc, _re) in det['suspicious_links'][:3]:
                details += f"• {url} (score: {sc})<br>"
        details += "<br><strong>Signals (why each is True/False):</strong>"
        details += build_signal_explanations(
            email_text, has_tld, has_cred_path, max_link_score, has_puny, None,
            False, False, None, None, high_kws, med_kws, mal_hits
        )
        return {
            'tp': True,'detection_type': detection_type,'warning': True,'risk_color': risk_color,
            'result': result,'detection_reason': detection_reason,'details': details
        }

    
    if hard_tp:
        detection_type = "TP"
    risk_color = 'red' if risk_score >= SUSP_RISK_THRESHOLD else 'orange'
    result = f"True Positive: Phishing detected ({'; '.join(tp_reasons)})."
    detection_reason = "; ".join(tp_reasons) + (" + malware indicators" if mal_hits else "")
    warning = True

    if has_cred_path:
        never_safe.append("credential path")
    if has_tld:
        never_safe.append("suspicious TLD")
    if max_link_score >= STRONG_LINK_THRESHOLD:
        never_safe.append(f"high link score {max_link_score}")
    if mal_hits:
        never_safe.append("malware indicator")
    if has_puny:
        never_safe.append("punycode domain")
    if obfuscation_present(email_text):
        never_safe.append("obfuscation present")

    if mal_hits:
        detection_type = "TP"
        risk_color = 'red'
        result = "True Positive: Malware indicator detected."
        detection_reason = "Malware keywords/extension in email"
        warning = True

    elif has_cred_path and (has_tld or max_link_score >= STRONG_LINK_THRESHOLD or has_puny):
        detection_type = "TP"
        risk_color = 'red'
        result = "True Positive: Credential-harvest link indicators."
        detection_reason = "Credential path + suspicious link"
        warning = True

    elif never_safe:
        detection_type = "Suspicious"
        risk_color = 'orange'
        result = "Suspicious: Risk indicators present (ML below threshold)."
        detection_reason = "Floor rule: " + ", ".join(never_safe)
        warning = False

    elif ml_prob < ML_THRESHOLD and any([high_kws, has_tld, max_link_score >= STRONG_LINK_THRESHOLD]):
        detection_type = "FN"
        risk_color = 'orange' if risk_score < SUSP_RISK_THRESHOLD else 'red'
        result = "False Negative: Strong phishing signals present but ML stayed below threshold."
        detection_reason = (
            f"Signals: high_kw={bool(high_kws)}, susp_tld={has_tld}, "
            f"malware_kw={bool(mal_hits)}, max_link={max_link_score}; "
            f"ML {ml_prob:.2f} < {ML_THRESHOLD:.2f}"
        )
        warning = False
        

        if risk_score >= SUSP_RISK_THRESHOLD:
            detection_type = "Suspicious"
            risk_color = 'red'
            result = "Suspicious: High risk indicators found (ML below threshold)."
            detection_reason = "High risk, but ML below threshold"

        elif risk_score >= REVIEW_RISK_THRESHOLD or minimum_band == "Review":
            detection_type = "Suspicious" if risk_score >= REVIEW_RISK_THRESHOLD else "Review"
            risk_color = 'orange' if detection_type == "Suspicious" else 'yellow'
            result = (
                "Suspicious: Moderate risk indicators (ML below threshold)."
                if detection_type == "Suspicious"
                else "Low risk indicators detected — review carefully."
            )
            detection_reason = (
                "Moderate risk, but ML below threshold"
                if detection_type == "Suspicious"
                else "Keyword/TLD floor to Review"
            )

        elif risk_score >= SAFE_RISK_THRESHOLD:
            detection_type = "Review"
            risk_color = 'yellow'
            result = "Low risk indicators detected — review carefully."
            detection_reason = "Low risk indicators present"

        else:
            detection_type = "Safe"
            risk_color = 'green'
            result = "No significant phishing indicators detected."
            detection_reason = "No significant risk factors"

        warning = False
    else:
        minimum_band = "Review" if (high_kws or med_kws or has_tld) else "Safe"

        if risk_score >= SUSP_RISK_THRESHOLD:
            detection_type = "Suspicious"
            risk_color = 'red'
            result = "Suspicious: High risk indicators found (ML below threshold)."
            detection_reason = "High risk, but ML below threshold"

        elif risk_score >= REVIEW_RISK_THRESHOLD or minimum_band == "Review":
            detection_type = "Suspicious" if risk_score >= REVIEW_RISK_THRESHOLD else "Review"
            risk_color = 'orange' if detection_type == "Suspicious" else 'yellow'
            result = (
                "Suspicious: Moderate risk indicators (ML below threshold)."
                if detection_type == "Suspicious"
                else "Low risk indicators detected — review carefully."
            )
            detection_reason = (
                "Moderate risk, but ML below threshold"
                if detection_type == "Suspicious"
                else "Keyword/TLD floor to Review"
            )

        elif risk_score >= SAFE_RISK_THRESHOLD:
            detection_type = "Review"
            risk_color = 'yellow'
            result = "Low risk indicators detected — review carefully."
            detection_reason = "Low risk indicators present"

        else:
            detection_type = "Safe"
            risk_color = 'green'
            result = "No significant phishing indicators detected."
            detection_reason = "No significant risk factors"

        warning = False


        if risk_score >= SUSP_RISK_THRESHOLD:
            detection_type = "Suspicious"
            risk_color = 'red'
            result = "Suspicious: High risk indicators found (ML below threshold)."
            detection_reason = "High risk, but ML below threshold"

        elif risk_score >= REVIEW_RISK_THRESHOLD or minimum_band == "Review":
            detection_type = "Suspicious" if risk_score >= REVIEW_RISK_THRESHOLD else "Review"
            risk_color = 'orange' if detection_type == "Suspicious" else 'yellow'
            result = (
                "Suspicious: Moderate risk indicators (ML below threshold)."
                if detection_type == "Suspicious"
                else "Low risk indicators detected — review carefully."
            )
            detection_reason = (
                "Moderate risk, but ML below threshold"
                if detection_type == "Suspicious"
                else "Keyword/TLD floor to Review"
            )

        elif risk_score >= SAFE_RISK_THRESHOLD:
            detection_type = "Review"
            risk_color = 'yellow'
            result = "Low risk indicators detected — review carefully."
            detection_reason = "Low risk indicators present"

        else:
            detection_type = "Safe"
            risk_color = 'green'
            result = "No significant phishing indicators detected."
            detection_reason = "No significant risk factors"

        warning = False
    
    if detection_type == "TP" and risk_score < SAFE_RISK_THRESHOLD and not any([
        has_cred_path, has_tld, has_puny, max_link_score >= STRONG_LINK_THRESHOLD,
        high_kws, mal_hits
    ]):
        detection_type = "Review"
        risk_color = "yellow"
        result = "Reclassified to Review: ML TP without heuristic support."

    details = f"<strong>Risk Score: {risk_score}</strong><br>"
    details += f"ML Probability: {ml_prob:.3f} (threshold {ML_THRESHOLD:.2f})<br>"
    if risk_factors:
        details += "<br><strong>Risk Factors:</strong><br>"
        for f in risk_factors:
            details += f"• {f}<br>"
    if det['suspicious_links']:
        details += "<br><strong>Suspicious Links:</strong><br>"
        for (url, sc, _re) in det['suspicious_links'][:3]:
            details += f"• {url} (score: {sc})<br>"
    details += "<br><strong>Signals (why each is True/False):</strong>"
    details += build_signal_explanations(
        email_text, has_tld, has_cred_path, max_link_score, has_puny, None,
        False, False, None, None, high_kws, med_kws, mal_hits
    )
    return {
        'tp': (detection_type == "TP"),
        'detection_type': detection_type,
        'warning': warning,
        'risk_color': risk_color,
        'result': result,
        'detection_reason': detection_reason,
        'details': details
    }

VALID_DTYPES = {"TP", "Suspicious", "FN", "Review", "Safe"}

def count_by_period() -> dict:
    data = _read_json_list(LOG_FILE)
    now = datetime.now()
    daily = weekly = yearly = 0
    for entry in data:
        if not entry.get('phishing'):
            continue
        ts = _safe_parse_ts(entry.get('timestamp', ''))
        if not ts:
            continue
        if ts.date() == now.date():
            daily += 1
        if ts.isocalendar()[1] == now.isocalendar()[1] and ts.year == now.year:
            weekly += 1
        if ts.year == now.year:
            yearly += 1
    return {'daily': daily, 'weekly': weekly, 'yearly': yearly}


@app.route("/auth/login", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def auth_login():
    error = None
    login_value = ""
    if request.method == "POST":
        login_value = (request.form.get("login") or request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        user = _find_user_by_login(login_value)
        if not user or not _verify_password(password, user["salt"], user["password_hash"]):
            error = "Invalid credentials."
        else:
            session["user_id"] = user["id"]
            _set_last_login(user["id"])
            if user.get("role") == "admin":
                session["admin_logged_in"] = True
            nxt = session.pop("next", None) or request.args.get("next") or url_for("index")
            return redirect(nxt)
    return render_template("auth_login.html", error=error, email=login_value)

@app.route("/auth/signup", methods=["GET", "POST"])
@app.route("/signup", methods=["GET", "POST"])
def auth_signup():
    error = None
    name = email = username = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok, res = _create_user(name, email, password, username=username)
        if ok:
            session["user_id"] = res["id"]
            return redirect(url_for("auth_profile"))
        else:
            if res.get("error") == "email_exists":
                error = "An account with this email already exists."
            elif res.get("error") == "username_exists":
                error = "Username is already taken."
            elif res.get("error") == "bad_username":
                error = "Username must be 3–24 chars: a–z, 0–9, underscore."
            else:
                error = "Please fill out all fields."
    return render_template("auth_signup.html", error=error, name=name, email=email, username=username)

@app.route("/auth/logout")
def auth_logout():
    session.pop("user_id", None)
    session.pop("admin_logged_in", None)
    return redirect(url_for("auth_login"))

@app.route("/auth/profile")
def auth_profile():
    u = g.get("user") or _find_user_by_id(session.get("user_id", "")) or {}
    return render_template("auth_profile.html", user=u)

@app.route("/account/password", methods=["GET", "POST"])
def account_change_password():
    u = g.get("user")
    error = success = None
    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not _verify_password(old_pw, u["salt"], u["password_hash"]):
            error = "Current password is incorrect."
        elif len(new_pw) < 8:
            error = "New password must be at least 8 characters."
        elif new_pw != confirm:
            error = "New password and confirmation do not match."
        else:
            _update_user_password(u["email"], new_pw)
            success = "Password updated successfully."
    return render_template("account_password.html", error=error, success=success)


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    details = ''
    detection_reason = ''
    email_text = ''
    risk_color = 'green'
    if request.method == 'POST':
        email_text = normalize_email_text(request.form.get('email_text', '').strip())
        if not email_text:
            result = 'Please enter email content.'
        else:
            detection_result = detect_with_scoring(email_text)
            result = detection_result['result']
            details = detection_result['details']
            detection_reason = detection_result['detection_reason']
            risk_color = detection_result['risk_color']
            detection_type = detection_result['detection_type']

            log_result(email_text, detection_result['tp'], detection_type, details, detection_reason)
            key = content_hash(email_text)
            cache_db[key] = {
                'result': result,
                'details': details,
                'warning': detection_result['tp'],
                'risk': risk_color,
                'detection_type': detection_type,
                'detection_reason': detection_reason,
                'cache_version': 'explain_signals_v1'
            }
            save_cache()
    stats = count_by_period()
    display_email_text = make_readable_email(email_text) if email_text else ""
    return render_template(
        'index.html',
        email_text=display_email_text, result=result, details=details,
        warning=(risk_color in ('orange','red')), risk=risk_color, stats=stats, detection_reason=detection_reason
    )

@app.route('/feedback', methods=['POST'])
def feedback():
    email_text = request.form['email_text']
    email_text = normalize_email_text(email_text or '').strip()
    if not email_text:
        return redirect(url_for('index'))
    key = content_hash(email_text)
    cache_db[key] = {
        'result': 'Manually marked as phishing.',
        'details': 'Manually marked by user.',
        'warning': True,
        'risk': 'red',
        'detection_type': 'TP',
        'detection_reason': 'Manual True Positive'
    }
    save_cache()
    record_user_mark_event(email_text, user=g.user["email"] if g.get("user") else "anonymous")

    data = _read_json_list(LOG_FILE)
    data.append({
        "email": email_text,
        "phishing": True,
        "detection_type": "TP",
        "details": "Manually marked by user.",
        "detection_reason": "Manual True Positive",
        "timestamp": datetime.now().isoformat(),
    })
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return redirect(url_for('index'))

@app.route('/mark-as-phishing', methods=['POST'])
def mark_as_phishing():
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        email_text = payload.get('email_text', '')
    else:
        email_text = request.form.get('email_text', '')
    email_text = normalize_email_text(email_text or '').strip()
    if not email_text:
        return jsonify({"ok": False, "error": "email_text is required"}), 400
    key = content_hash(email_text)
    cache_db[key] = {
        'result': 'Manually marked as phishing.',
        'details': 'Manually marked by user (API).',
        'warning': True,
        'risk': 'red',
        'detection_type': 'TP',
        'detection_reason': 'Manual True Positive'
    }
    save_cache()
    event = record_user_mark_event(email_text, user=g.user["email"] if g.get("user") else "anonymous", note="Manual True Positive (API)")
    data = _read_json_list(LOG_FILE)
    data.append({
        "email": email_text,
        "phishing": True,
        "detection_type": "TP",
        "details": "Manually marked by user (API).",
        "detection_reason": "Manual True Positive",
        "timestamp": datetime.now().isoformat(),
    })
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return jsonify({"ok": True, "saved": event})

@app.route('/history')
def history():
    detections = _read_json_list(LOG_FILE)
    detections.reverse()
    for e in detections:
        e['email'] = make_readable_email(e.get('email', ''))
    return render_template('detection_history.html', detections=detections)

@app.route('/statistics')
def statistics():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        raw = []
    daily = {'TP': defaultdict(int), 'FN': defaultdict(int), 'Safe': defaultdict(int)}
    daily_phish = defaultdict(int)
    tp_total = fn_total = safe_total = 0
    phish_total = 0
    first_d = last_d = None
    for e in raw:
        if e.get('phishing') is True:
            phish_total += 1
        ts = _safe_parse_ts(e.get('timestamp', ''))
        if not ts: continue
        d = ts.date()
        first_d = d if first_d is None or d < first_d else first_d
        last_d  = d if last_d  is None or d > last_d  else last_d
        if e.get('phishing') is True:
            daily_phish[d] += 1
        dtype = e.get('detection_type', 'Safe')
        if dtype == 'TP':   daily['TP'][d] += 1; tp_total += 1
        elif dtype == 'FN': daily['FN'][d] += 1; fn_total += 1
        else:               daily['Safe'][d] += 1; safe_total += 1
    if first_d is None: first_d = last_d = date.today()
    ninety_days_ago = date.today() - timedelta(days=89)
    if first_d < ninety_days_ago: first_d = ninety_days_ago
    labels, tp_counts, fn_counts, safe_counts, phish_counts = [], [], [], [], []
    cur = first_d
    while cur <= last_d:
        labels.append(cur.isoformat())
        tp_counts.append(daily['TP'].get(cur, 0))
        fn_counts.append(daily['FN'].get(cur, 0))
        safe_counts.append(daily['Safe'].get(cur, 0))
        phish_counts.append(daily_phish.get(cur, 0))
        cur += timedelta(days=1)
    return render_template(
        'statistics.html',
        dates=labels, tp_counts=tp_counts, fn_counts=fn_counts, safe_counts=safe_counts, phish_counts=phish_counts,
        tp_total=tp_total, fn_total=fn_total, safe_total=safe_total, phish_total=phish_total
    )

@app.route('/statistics_data.json')
def statistics_data_json():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        raw = []
    daily = {'TP': defaultdict(int), 'FN': defaultdict(int), 'Safe': defaultdict(int)}
    tp_total = fn_total = safe_total = 0
    first_d = last_d = None
    for e in raw:
        ts = _safe_parse_ts(e.get('timestamp', ''))
        if not ts: continue
        d = ts.date()
        first_d = d if first_d is None or d < first_d else first_d
        last_d  = d if last_d  is None or d > last_d  else last_d
        dtype = e.get('detection_type', 'Safe')
        if dtype == 'TP':   daily['TP'][d] += 1; tp_total += 1
        elif dtype == 'FN': daily['FN'][d] += 1; fn_total += 1
        else:               daily['Safe'][d] += 1; safe_total += 1
    if first_d is None: first_d = last_d = date.today()
    ninety_days_ago = date.today() - timedelta(days=89)
    if first_d < ninety_days_ago: first_d = ninety_days_ago
    labels, tp_counts, fn_counts, safe_counts = [], [], [], []
    cur = first_d
    while cur <= last_d:
        labels.append(cur.isoformat())
        tp_counts.append(daily['TP'].get(cur, 0))
        fn_counts.append(daily['FN'].get(cur, 0))
        safe_counts.append(daily['Safe'].get(cur, 0))
        cur += timedelta(days=1)
    payload = {
        "dates": labels, "tp_counts": tp_counts, "fn_counts": fn_counts, "safe_counts": safe_counts,
        "tp_total": tp_total, "fn_total": fn_total, "safe_total": safe_total, "sample_size": len(raw)
    }
    return app.response_class(
        response=json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        mimetype='application/json'
    )

@app.route('/export_page')
def export_page():
    return render_template('export_data.html')

@app.route('/export', endpoint="export_data")
def export_data():
    data = _read_json_list(LOG_FILE)
    out = io.StringIO()
    wr = csv.writer(out)
    wr.writerow(['Email', 'Phishing', 'Detection Type', 'Detection Reason', 'Risk Score', 'Details', 'Timestamp'])
    for entry in data:
        details = entry.get('details', '') or ""
        risk_score = "N/A"
        if "Risk Score:" in details:
            m = re.search(r'Risk Score:\s*(\d+)', details)
            if m: risk_score = m.group(1)
        wr.writerow([
            entry.get('email', '').replace('\r', ' ').replace('\n', ' '),
            entry.get('phishing', '-'),
            entry.get('detection_type', '-'),
            entry.get('detection_reason', '-'),
            risk_score,
            details.replace('<br>', '; ').replace('<strong>', '').replace('</strong>', ''),
            entry.get('timestamp', '-')
        ])
    response = Response(out.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=phishing_data_export.csv'
    return response

@app.route('/link_checker', methods=['GET', 'POST'])
def link_checker():
    linktext = ''
    result = None
    risk_color = 'green'
    per_url = []
    if request.method == 'POST':
        linktext = request.form.get('linktext', '')
        urls = extract_links(linktext)
        total_score, details = check_links(urls)
        per_url = details
        if total_score <= 0:
            result = 'No suspicious links detected.'; risk_color = 'green'
        elif total_score < 25:
            result = 'One or more low-risk indicators found.'; risk_color = 'yellow'
        elif total_score < 60:
            result = 'Suspicious links detected!'; risk_color = 'orange'
        else:
            result = 'Multiple high-risk indicators found!'; risk_color = 'red'
        # store raw submission for history
        entry = {"link_text": linktext, "suspicious": total_score > 0, "link_score": total_score,
                 "timestamp": datetime.now().isoformat()}
        data = _read_json_list(LINK_LOG_FILE)
        data.append(entry)
        with open(LINK_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    return render_template('link_checker.html', linktext=linktext, result=result, risk=risk_color, per_url=per_url)

@app.route('/link_history')
def link_history():
    detections = _read_json_list(LINK_LOG_FILE); detections.reverse()
    return render_template('link_history.html', link_detections=detections)

@app.route('/_health')
def _health():
    return "OK", 200


if __name__ == "__main__":
    app.run(debug=True)
