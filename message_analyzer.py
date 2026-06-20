"""
message_analyzer.py
Backend logic for suspicious email/SMS/text message analysis.
Loaded by server.py — do NOT run directly.
"""

import os
import re
import json
import pickle
import sqlite3
import datetime

# ─────────────────────────────────────────────
# PATHS  (same folder as server.py)
# ─────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
NB_PATH   = os.path.join(BASE_DIR, "msg_nb_model.pkl")
RF_PATH   = os.path.join(BASE_DIR, "msg_rf_model.pkl")
REP_PATH  = os.path.join(BASE_DIR, "msg_model_report.json")
DB_PATH   = os.path.join(BASE_DIR, "scan_history.db")

# ─────────────────────────────────────────────
# LOAD MODELS
# ─────────────────────────────────────────────
def load_models():
    models = {}
    if os.path.exists(NB_PATH):
        with open(NB_PATH, "rb") as f:
            models["Naive Bayes"] = pickle.load(f)
        print("✅ NB message model loaded")
    else:
        print("⚠️  msg_nb_model.pkl not found — run train_message_models.py first")

    if os.path.exists(RF_PATH):
        with open(RF_PATH, "rb") as f:
            models["Random Forest"] = pickle.load(f)
        print("✅ RF message model loaded")
    else:
        print("⚠️  msg_rf_model.pkl not found — run train_message_models.py first")

    return models

MSG_MODELS = load_models()

# ─────────────────────────────────────────────
# DB SETUP
# ─────────────────────────────────────────────
def init_message_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS message_scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            message     TEXT,
            msg_type    TEXT,
            nb_verdict  TEXT,
            nb_conf     REAL,
            rf_verdict  TEXT,
            rf_conf     REAL,
            final_verdict TEXT,
            risk_score  REAL,
            flags       TEXT,
            timestamp   TEXT
        )
    """)
    conn.commit()
    conn.close()

init_message_db()

# ─────────────────────────────────────────────
# PREPROCESSING (must match train script)
# ─────────────────────────────────────────────
def preprocess(text):
    text = text.lower()
    text = re.sub(r'http\S+', ' URL ', text)
    text = re.sub(r'\d{10,}', ' PHONE ', text)
    text = re.sub(r'[^\w\s]', ' ', text)
    return text

# ─────────────────────────────────────────────
# RULE-BASED RED FLAGS
# ─────────────────────────────────────────────
PHISHING_PATTERNS = [
    (r'http[s]?://[^\s]+',                  "Contains URL"),
    (r'bit\.ly|tinyurl|t\.co|goo\.gl',       "Shortened URL detected"),
    (r'\b(urgent|immediate|immediately)\b',  "Urgency language"),
    (r'\b(won|winner|prize|reward|gift card)\b', "Prize/reward claim"),
    (r'\b(verify|confirm|validate)\b.*\b(account|identity|details|payment)\b', "Verification request"),
    (r'\b(suspend|block|limit|close|cancel)\b.*\b(account|card)\b', "Account threat"),
    (r'\b(click|tap|visit)\b.*\b(link|here|now|below)\b', "Call-to-action link"),
    (r'\bfree\b.*\b(iphone|gift|prize|money|cash)\b', "Free item claim"),
    (r'\b(bank|paypal|netflix|amazon|apple|google|microsoft|irs|hmrc|dhl|fedex)\b.*\b(alert|notice|warning|secure|verify)\b', "Brand impersonation"),
    (r'\b(password|credential|login|signin)\b.*\b(expire|reset|update|change)\b', "Password threat"),
    (r'\$\d+|\£\d+|€\d+',                    "Monetary amount mentioned"),
    (r'\b(arrest|legal action|penalty|lawsuit|fine)\b', "Legal threat"),
    (r'\b(limited time|24 hours|expires|deadline|act now|don\'t wait)\b', "Time pressure"),
    (r'\b(earn|income|salary|invest)\b.*\b(\$\d+|£\d+|\d+ per|per day|per week)\b', "Unrealistic earnings"),
    (r'[A-Z]{5,}',                            "Excessive capitalization"),
]

def extract_flags(text):
    flags = []
    for pattern, description in PHISHING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flags.append(description)
    return flags

# ─────────────────────────────────────────────
# RISK SCORE  (0–100)
# ─────────────────────────────────────────────
def compute_risk_score(nb_prob, rf_prob, flags):
    model_weight = 0.70
    flag_weight  = 0.30
    model_score  = ((nb_prob + rf_prob) / 2) * 100
    flag_score   = min(len(flags) * 12, 100)
    return round(model_weight * model_score + flag_weight * flag_score, 1)

# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────
def analyze_message(message: str, msg_type: str = "email") -> dict:
    if not MSG_MODELS:
        return {"error": "Models not loaded. Run train_message_models.py first."}

    clean = preprocess(message)
    flags = extract_flags(message)
    results = {}

    for name, model in MSG_MODELS.items():
        proba   = model.predict_proba([clean])[0]
        label   = int(model.predict([clean])[0])
        verdict = "Suspicious" if label == 1 else "Legitimate"
        conf    = round(float(proba[label]) * 100, 1)
        results[name] = {"verdict": verdict, "confidence": conf,
                         "spam_prob": round(float(proba[1]) * 100, 1)}

    nb = results.get("Naive Bayes", {})
    rf = results.get("Random Forest", {})

    nb_prob = nb.get("spam_prob", 0) / 100
    rf_prob = rf.get("spam_prob", 0) / 100
    risk    = compute_risk_score(nb_prob, rf_prob, flags)

    # Ensemble final verdict (majority + flags)
    votes_suspicious = sum(1 for r in results.values() if r["verdict"] == "Suspicious")
    if votes_suspicious == len(results):
        final = "Suspicious"
    elif votes_suspicious == 0 and len(flags) < 2:
        final = "Legitimate"
    elif risk >= 55:
        final = "Suspicious"
    else:
        final = "Legitimate"

    # Persist to DB
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO message_scan_history
              (message, msg_type, nb_verdict, nb_conf, rf_verdict, rf_conf,
               final_verdict, risk_score, flags, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            message[:500], msg_type,
            nb.get("verdict", "N/A"), nb.get("confidence", 0),
            rf.get("verdict", "N/A"), rf.get("confidence", 0),
            final, risk,
            json.dumps(flags), timestamp
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB write error: {e}")

    return {
        "message":      message[:200] + ("..." if len(message) > 200 else ""),
        "msg_type":     msg_type,
        "models":       results,
        "flags":        flags,
        "risk_score":   risk,
        "final_verdict": final,
        "timestamp":    timestamp
    }

# ─────────────────────────────────────────────
# HISTORY FETCH
# ─────────────────────────────────────────────
def get_message_history(limit: int = 50) -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM message_scan_history
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        history = []
        for r in rows:
            item = dict(r)
            item["flags"] = json.loads(item.get("flags", "[]"))
            history.append(item)
        return history
    except Exception as e:
        print(f"DB read error: {e}")
        return []

# ─────────────────────────────────────────────
# MODEL REPORT
# ─────────────────────────────────────────────
def get_model_report() -> dict:
    if os.path.exists(REP_PATH):
        with open(REP_PATH) as f:
            return json.load(f)
    return {"error": "Report not found. Run train_message_models.py first."}