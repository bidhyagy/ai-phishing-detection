import os
import pickle
import re
import sqlite3
import pandas as pd
from difflib import SequenceMatcher
from flask import Flask, request, jsonify, render_template
from message_analyzer import analyze_message, get_message_history, get_model_report

app = Flask(__name__)

DB_PATH = r"C:\Users\user\OneDrive\Desktop\Ai based phisphing detection\scan_history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if table exists with old layout schema
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        # Check if column layout contains scan_type
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'scan_type' not in columns:
            print("⚠️ Outdated database schema detected. Rebuilding table structures...")
            cursor.execute('DROP TABLE IF EXISTS scans')
            conn.commit()

    # Unified table schema tracking both URL and text scans seamlessly
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT DEFAULT 'url',
            input_data TEXT NOT NULL,
            result TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print(f"💾 SQLite Target Set & Verified: {DB_PATH}")

# Core database synchronization run
init_db()

with open('model.pkl', 'rb') as file:
    model = pickle.load(file)
print("✅ Model loaded successfully!")

if os.path.exists('phishing.csv'):
    df_temp = pd.read_csv('phishing.csv')
    feature_names = list(df_temp.drop(columns=['Index', 'class']).columns)
    print(f"✅ Loaded exact 30 feature schema from phishing.csv!")
else:
    feature_names = [
        'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
        'SubDomain', 'HTTPS', 'DomainRegLen', 'Favicon', 'Port', 'HTTPS_token',
        'RequestURL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email',
        'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWindow',
        'Iframe', 'age_of_domain', 'DNSRecording', 'web_traffic', 'PageRank',
        'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
    ]
    print("⚠️ Using default 30-feature fallback schema.")


known_brands = [
    'facebook', 'google', 'paypal', 'amazon', 'netflix',
    'instagram', 'twitter', 'youtube', 'linkedin', 'microsoft',
    'apple', 'whatsapp', 'snapchat', 'tiktok', 'gmail',
    'yahoo', 'ebay', 'dropbox', 'spotify', 'reddit',
    'wellsfargo', 'citibank', 'barclays', 'hsbc'
]

def check_brand_impersonation(url):
    url_lower = url.lower().strip()
    domain_part = url_lower.split('://')[-1].split('/')[0]
    domain_name = domain_part.split('.')[0]
    for brand in known_brands:
        similarity = SequenceMatcher(None, domain_name, brand).ratio()
        if similarity > 0.60 and domain_name != brand:
            print(f"🚨 FAKE BRAND: '{domain_name}' looks like '{brand}' (score: {similarity:.2f})")
            return True
    return False


def extract_30_features(url):
    features = {}
    url_lower = url.lower().strip()
    domain_part = url_lower.split('://')[-1].split('/')[0]
    domain_name = domain_part.split('.')[0]

    for name in feature_names:
        features[name] = 1

    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, domain_part):
        features['UsingIP'] = -1

    if len(url_lower) > 75:
        features['LongURL'] = -1
    elif 54 <= len(url_lower) <= 75:
        features['LongURL'] = 0

    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd']
    if any(srv in domain_part for srv in shorteners):
        features['ShortURL'] = -1

    if '@' in url_lower:
        features['Symbol@'] = -1

    if url_lower.rfind('//') > 7:
        features['Redirecting//'] = -1

    if '-' in domain_part:
        features['PrefixSuffix-'] = -1

    dots_in_domain = domain_part.count('.')
    if dots_in_domain == 2:
        features['SubDomain'] = 0
    elif dots_in_domain > 2:
        features['SubDomain'] = -1

    if not url_lower.startswith('https'):
        features['HTTPS'] = -1

    if 'https' in domain_part:
        features['HTTPS_token'] = -1

    suspicious_words = [
        'login', 'verify', 'secure', 'update', 'bank', 'free',
        'prize', 'winner', 'account', 'confirm', 'password',
        'signin', 'wallet', 'alert', 'urgent', 'suspend',
        'recover', 'unlock', 'bonus', 'gift'
    ]
    if any(word in url_lower for word in suspicious_words):
        features['SFH'] = -1

    special_chars = ['%', '=', '&', '$', '#']
    special_count = sum(url_lower.count(c) for c in special_chars)
    if special_count > 3:
        features['RequestURL'] = -1

    if re.search(r':\d{4,5}', domain_part):
        features['Port'] = -1

    if re.search(r'\.(php|html|asp)\.(php|html|asp)', url_lower):
        features['Redirect'] = -1

    digit_count = sum(c.isdigit() for c in domain_name)
    if digit_count > 3:
        features['DomainRegLen'] = -1

    vowels = sum(1 for c in domain_name if c in 'aeiou')
    if len(domain_name) > 5 and vowels == 0:
        features['DNSRecording'] = -1

    if 'mailto:' in url_lower:
        features['Submitting_to_email'] = -1

    if any(word in url_lower for word in ['popup', 'onclick', 'onmouse']):
        features['popUpWindow'] = -1

    return pd.DataFrame([features], columns=feature_names)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            return jsonify({'error': 'Please provide a valid URL.'}), 400

        # Brand check first
        if check_brand_impersonation(url):
            input_df = extract_30_features(url)
            features_dict = input_df.iloc[0].to_dict()
            features_dict['Abnormal_URL'] = -1

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (scan_type, input_data, result, score) VALUES (?, ?, ?, ?)", 
                ("url", url, "Phishing Website", 100)
            )
            conn.commit()
            conn.close()
            print(f"🚨 BRAND IMPERSONATION: {url}")

            return jsonify({
                'url': url,
                'prediction': 'Phishing Website',
                'status': -1,
                'features_matrix': features_dict,
                'phish_probability': 1.0,
                'legit_probability': 0.0
            })

        # Normal model prediction
        input_df = extract_30_features(url)
        features_dict = input_df.iloc[0].to_dict()

        probabilities = model.predict_proba(input_df)
        phish_probability = float(probabilities[0][0])
        legit_probability = float(1 - phish_probability)

        print("\n--- AI SENSITIVITY GATEWAY ---")
        print(f"Phishing Probability Score: {phish_probability * 100:.2f}%")

        if phish_probability > 0.15:
            prediction = -1
            result_string = "Phishing Website"
            print("🚨 Flagging as Phishing Website")
        else:
            prediction = 1
            result_string = "Legitimate Website"
            print("✅ Flagging as Legitimate Website")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (scan_type, input_data, result, score) VALUES (?, ?, ?, ?)", 
            ("url", url, result_string, int(phish_probability * 100))
        )
        conn.commit()
        conn.close()
        print(f"📁 Logged: {url}")
        print("------------------------------\n")

        return jsonify({
            'url': url,
            'prediction': result_string,
            'status': int(prediction),
            'features_matrix': features_dict,
            'phish_probability': round(phish_probability, 4),
            'legit_probability': round(legit_probability, 4)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history', methods=['GET'])
def get_raw_url_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT input_data, result, timestamp FROM scans WHERE scan_type='url' ORDER BY id DESC LIMIT 10")
        rows = cursor.fetchall()
        conn.close()

        history_list = []
        for row in rows:
            history_list.append({
                'url': row[0],
                'verdict': row[1],
                'timestamp': row[2]
            })
        return jsonify(history_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/message-analyzer")
def message_analyzer_page():
    return render_template("message_analyzer.html")


@app.route("/analyze-message", methods=["POST"])
def analyze_message_route():
    try:
        data = request.get_json()
        message = data.get("message", "").strip()
        msg_type = data.get("msg_type", "email")
        if not message:
            return jsonify({"error": "No message provided"}), 400
        
        # Analyze using local package engine
        analysis_res = analyze_message(message, msg_type)
        
        # Log message data directly inside unified database layout
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (scan_type, input_data, result, score) VALUES (?, ?, ?, ?)",
            (msg_type, message, analysis_res.get('final_verdict', 'Unknown'), analysis_res.get('risk_score', 0))
        )
        conn.commit()
        conn.close()
        
        return jsonify(analysis_res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/message-history")
def message_history_route():
    return jsonify({
        "history": get_message_history(50),
        "report":  get_model_report()
    })


@app.route('/api/history', methods=['GET'])
def get_recent_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Fetches unified structural elements cleanly mapping configuration
        cursor.execute("SELECT scan_type, input_data, result, score, timestamp FROM scans ORDER BY id DESC LIMIT 10")
        rows = cursor.fetchall()
        
        history_list = []
        for row in rows:
            history_list.append({
                'type': row[0],
                'input': row[1],
                'result': row[2],
                'score': row[3],
                'time': row[4]
            })
        return jsonify(history_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    print("🚀 Booting up backend automation server...")
    app.run(debug=True, port=5000)