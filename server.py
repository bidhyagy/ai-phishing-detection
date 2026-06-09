import os
import pickle
import re
import sqlite3
import pandas as pd
from difflib import SequenceMatcher
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

DB_PATH = r"C:\Users\user\OneDrive\Desktop\Ai based phisphing detection\scan_history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print(f"💾 SQLite Target Set & Verified: {DB_PATH}")

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
            cursor.execute("INSERT INTO scans (url, verdict) VALUES (?, ?)", (url, "Phishing Website"))
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
        cursor.execute("INSERT INTO scans (url, verdict) VALUES (?, ?)", (url, result_string))
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
def get_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT url, verdict, timestamp FROM scans ORDER BY id DESC LIMIT 10")
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


if __name__ == '__main__':
    print("🚀 Booting up backend automation server...")
    app.run(debug=True, port=5000)