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
 
# ============================================================
# WORLD CUP 2026 PHISHING INTELLIGENCE DATABASE
# Sources: FBI IC3 PSA260527, Group-IB, Cyble, FortiGuard Labs,
#          CybelAngel, Recorded Future, Bitdefender — June 2026
# ============================================================
 
WORLDCUP_PHISHING_DOMAINS = [
    "fifa.city", "fiffa.com", "fifa.help", "fifa.pink",
    "fifa.moe", "fifa.buzz", "fifa-web.co", "fifa-com.xyz",
    "fifa-online.com", "fifa-ticket.live", "jobs-fifa.com",
    "ww-fifa.com", "fifaticket2026vip.com",
    "fifaworldcup-careers.com", "usavisaworldcup.com",
    "fifaworldcup2026.net", "worldcup2026tickets.com",
    "worldcup-ticket.org", "worldcup2026.live",
    "2026worldcuptickets.com", "fifacup2026.com",
    "worldcup2026streaming.com", "worldcupstream2026.live",
    "worldcup2026visa.com", "worldcup-tickets.net",
    "fifalogin2026.com", "fifasupport2026.com",
    "worldcup2026fanpass.com", "fifafanzone2026.net",
    "fifajobs2026.com", "worldcupjobs2026.com",
    "fifarecruitment2026.com", "worldcupcareers.net",
    "worldcuplivestream.net", "watchfifa2026.com",
    "freeworldcup2026.com", "fifastream2026.live",
    "worldcuplive2026.tv", "fifafreetv.com",
    "fifashop2026.com", "officialfifastore2026.com",
    "worldcupkits2026.com", "fifamerch2026.net",
]
 
WORLDCUP_PHISHING_EMAIL_KEYWORDS = [
    "fifa-", "-fifa", "worldcup2026", "fifaticket",
    "worldcup-ticket", "fifaworldcup", "2026ticket",
    "wc2026", "fifajobs", "jobs-fifa", "usavisaworldcup",
    "fifalogin", "fifasupport", "worldcupstream", "fifastream",
    "worldcuplive", "fifashop", "worldcupkits", "fifamerch",
    "fifarecruitment", "worldcupvisa", "fifafan",
]
 
DISPOSABLE_EMAIL_DOMAINS = [
    "tempmail.com", "guerrillamail.com", "mailinator.com",
    "throwam.com", "yopmail.com", "sharklasers.com",
    "trashmail.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "spamgourmet.com", "getairmail.com",
    "temp-mail.org", "throwaway.email", "getnada.com",
    "mailnull.com", "spamgourmet.org", "trashmail.io",
    "10minutemail.com", "burnermail.io", "tempr.email",
    "discard.email", "mailnesia.com", "spamex.com",
]
 
SUSPICIOUS_PHISHING_TLDS = [
    ".xyz", ".live", ".city", ".buzz", ".moe", ".pink",
    ".top", ".club", ".icu", ".gq", ".ml", ".cf", ".ga",
    ".tk", ".pw", ".ws", ".cc", ".tv",
]
 
LEGITIMATE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "proton.me", "protonmail.com", "live.com",
    "msn.com", "aol.com", "mail.com",
    "fifa.com", "fifa.org",
]
 
# ============================================================
# GOVERNMENT DOMAIN INTELLIGENCE
# Real .gov / official government TLDs by country
# ============================================================
 
GOVERNMENT_TLDS = [
    ".gov", ".gov.np", ".gov.in", ".gov.uk", ".gov.au",
    ".gov.ca", ".gov.nz", ".gov.sg", ".gov.za", ".gov.pk",
    ".gov.bd", ".gov.ph", ".gov.my", ".gov.ng", ".gov.gh",
    ".gov.ke", ".gov.br", ".gov.ar", ".gov.mx", ".gov.co",
    ".mil", ".govt.nz", ".gob.mx", ".gob.ar", ".gob.es",
    ".gouv.fr", ".bund.de", ".gc.ca",
]
 
# Known fake/phishing government-impersonating domains
FAKE_GOV_DOMAINS = [
    "irs-refund.com", "irs-gov.net", "irs.gov-refund.com",
    "gov-stimulus.com", "gov-benefits.net", "usagov-support.com",
    "passport-gov.net", "visa-gov-apply.com", "immigration-gov.net",
    "tax-gov-refund.com", "socialsecurity-gov.com", "medicare-gov.net",
    "benefits-gov-apply.com", "stimulus-gov.net", "uscis-gov.org",
    "gov-uk-verify.com", "hmrc-gov.net", "hmrc-refund.com",
    "dvla-gov.co.uk", "nhs-gov.net", "ukgov-support.com",
    "npgov.xyz", "nepal-gov.com", "moha-gov.net",
    "epassport-gov.com", "passport-renewal-gov.com",
]
 
GOV_PHISHING_KEYWORDS = [
    "irs-", "-irs", "gov-refund", "gov-stimulus", "gov-benefits",
    "tax-refund-gov", "passport-gov", "visa-gov", "immigration-gov",
    "socialsecurity-gov", "medicare-gov", "stimulus-gov",
    "hmrc-", "-hmrc", "gov-uk-", "nhs-gov", "dvla-gov",
    "gov-verify", "gov-login", "gov-portal", "gov-apply",
    "official-gov", "e-gov-", "egov-portal",
]
 
# ============================================================
# OFFICE / CORPORATE / BUSINESS DOMAIN INTELLIGENCE
# ============================================================
 
LEGITIMATE_OFFICE_DOMAINS = [
    "office.com", "microsoft.com", "office365.com",
    "sharepoint.com", "teams.microsoft.com", "onedrive.com",
    "live.com", "outlook.com", "exchange.microsoft.com",
    "google.com", "workspace.google.com", "docs.google.com",
    "dropbox.com", "box.com", "slack.com", "zoom.us",
    "salesforce.com", "hubspot.com", "zendesk.com",
    "atlassian.com", "jira.com", "confluence.com",
    "notion.so", "asana.com", "trello.com",
]
 
FAKE_OFFICE_DOMAINS = [
    "office365-login.com", "office-365.net", "office365.xyz",
    "microsoft-office.net", "ms-office365.com", "office-login.net",
    "office365support.com", "microsoft365-login.com",
    "office-365-login.com", "microsoftonline-login.com",
    "outlook-verify.com", "outlook-login.net", "outlook365.xyz",
    "teams-microsoft.net", "ms-teams-login.com", "teamsmeet.net",
    "sharepoint-login.com", "onedrive-verify.com",
    "google-workspace.net", "googleoffice.com", "googledocs-login.com",
    "dropbox-verify.com", "dropbox-login.net", "boxcloud-login.com",
    "zoom-meeting.net", "zoom-verify.com", "zoommeet.xyz",
    "slack-login.net", "slackteams.com", "slack-verify.com",
]
 
OFFICE_PHISHING_KEYWORDS = [
    "office365-", "-office365", "ms-office", "office-login",
    "microsoft-verify", "microsoftonline-", "outlook-login",
    "outlook-verify", "teams-login", "sharepoint-login",
    "onedrive-verify", "google-workspace-", "googledocs-login",
    "dropbox-verify", "zoom-verify", "slack-verify",
    "office-support", "office-help", "365-login",
    "office-reset", "office-update", "office-secure",
]
 
OFFICE_BRANDS = [
    "office", "office365", "microsoft", "outlook", "teams",
    "sharepoint", "onedrive", "google", "workspace", "dropbox",
    "zoom", "slack", "salesforce", "hubspot",
]
 
# ============================================================
# EDUCATION DOMAIN INTELLIGENCE
# ============================================================
 
EDUCATION_TLDS = [
    ".edu", ".edu.np", ".edu.in", ".edu.au", ".edu.pk",
    ".edu.bd", ".edu.sg", ".edu.my", ".edu.ph", ".edu.gh",
    ".edu.ng", ".edu.za", ".edu.br", ".edu.ar", ".edu.mx",
    ".ac.uk", ".ac.in", ".ac.nz", ".ac.za", ".ac.jp",
    ".ac.ke", ".school", ".university",
]
 
FAKE_EDU_DOMAINS = [
    "harvard-edu.com", "mit-edu.net", "oxford-edu.com",
    "cambridge-edu.net", "stanford-edu.com", "yale-edu.net",
    "columbia-edu.com", "university-login.net", "edu-portal.com",
    "student-edu.net", "scholarship-edu.com", "edu-grant.net",
    "college-login.com", "university-verify.net",
    "edu-login-portal.com", "campus-edu.net",
    "student-portal-edu.com", "edu-scholarship-apply.com",
    "university-scholarship.net", "college-grant-apply.com",
    "tribhuvan-edu.com", "tu-edu.net", "pu-edu.com",
    "ku-edu.net", "pokhara-university.net",
]
 
EDU_PHISHING_KEYWORDS = [
    "student-portal-", "edu-login", "university-verify",
    "college-login", "edu-grant", "scholarship-apply",
    "campus-login", "edu-support", "student-verify",
    "alumni-login", "faculty-portal", "edu-reset",
    "university-scholarship", "college-scholarship",
    "edu-financial-aid", "tuition-refund",
]
 
EDU_BRANDS = [
    "harvard", "mit", "oxford", "cambridge", "stanford",
    "yale", "columbia", "princeton", "cornell", "chicago",
    "tribhuvan", "kathmandu", "pokhara", "purwanchal",
]
 
 
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
 
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    table_exists = cursor.fetchone()
 
    if table_exists:
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'scan_type' not in columns:
            print("⚠️ Outdated database schema detected. Rebuilding table structures...")
            cursor.execute('DROP TABLE IF EXISTS scans')
            conn.commit()
 
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
    'wellsfargo', 'citibank', 'barclays', 'hsbc',
    'fifa', 'worldcup', 'fifaworldcup',
    'office', 'outlook', 'teams', 'sharepoint', 'onedrive',
    'zoom', 'slack', 'salesforce',
    'harvard', 'oxford', 'cambridge', 'stanford',
    'irs', 'hmrc', 'medicare', 'socialsecurity',
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
 
 
# ============================================================
# DOMAIN CATEGORY CLASSIFIER
# Returns category label + trust level for any domain
# ============================================================
 
def classify_domain_category(domain: str) -> dict:
    """
    Identifies the category of an email domain:
    government, education, office/corporate, worldcup, disposable, or general.
    Also detects fake/phishing impersonations of each category.
    """
    domain_lower = domain.lower().strip()
    domain_base = domain_lower.split('.')[0]
 
    category = "General"
    category_icon = "🌐"
    is_fake = False
    category_flags = []
    category_score = 0.0
 
    # ── GOVERNMENT ──────────────────────────────────────────
    real_gov = any(domain_lower.endswith(tld) for tld in GOVERNMENT_TLDS)
    fake_gov_direct = domain_lower in FAKE_GOV_DOMAINS
    fake_gov_keyword = any(kw in domain_lower for kw in GOV_PHISHING_KEYWORDS)
    gov_brand_spoof = False
    gov_spoof_brands = ['irs', 'hmrc', 'medicare', 'socialsecurity', 'passport', 'immigration', 'visa']
    for brand in gov_spoof_brands:
        sim = SequenceMatcher(None, domain_base, brand).ratio()
        if sim > 0.65 and domain_base != brand:
            gov_brand_spoof = True
            category_flags.append(f"🏛️ Government brand spoof: '{domain_base}' mimics '{brand}' ({sim:.0%})")
            category_score += 0.75
            break
 
    if real_gov:
        category = "Government"
        category_icon = "🏛️"
        category_flags.append(f"🏛️ Verified government domain TLD")
    elif fake_gov_direct or fake_gov_keyword or gov_brand_spoof:
        category = "Government"
        category_icon = "🏛️"
        is_fake = True
        if fake_gov_direct:
            category_flags.append(f"🚨 Confirmed fake government domain")
            category_score += 1.0
        if fake_gov_keyword:
            matched = [kw for kw in GOV_PHISHING_KEYWORDS if kw in domain_lower]
            category_flags.append(f"🚨 Government phishing keyword: '{matched[0]}'")
            category_score += 0.70
 
    # ── EDUCATION ───────────────────────────────────────────
    real_edu = any(domain_lower.endswith(tld) for tld in EDUCATION_TLDS)
    fake_edu_direct = domain_lower in FAKE_EDU_DOMAINS
    fake_edu_keyword = any(kw in domain_lower for kw in EDU_PHISHING_KEYWORDS)
    edu_brand_spoof = False
    for brand in EDU_BRANDS:
        sim = SequenceMatcher(None, domain_base, brand).ratio()
        if sim > 0.70 and domain_base != brand:
            edu_brand_spoof = True
            category_flags.append(f"🎓 Education brand spoof: '{domain_base}' mimics '{brand}' ({sim:.0%})")
            category_score += 0.75
            break
 
    if real_edu:
        category = "Education"
        category_icon = "🎓"
        category_flags.append(f"🎓 Verified educational institution TLD")
    elif fake_edu_direct or fake_edu_keyword or edu_brand_spoof:
        category = "Education"
        category_icon = "🎓"
        is_fake = True
        if fake_edu_direct:
            category_flags.append(f"🚨 Confirmed fake education domain")
            category_score += 1.0
        if fake_edu_keyword:
            matched = [kw for kw in EDU_PHISHING_KEYWORDS if kw in domain_lower]
            category_flags.append(f"🚨 Education phishing keyword: '{matched[0]}'")
            category_score += 0.65
 
    # ── OFFICE / CORPORATE ──────────────────────────────────
    real_office = domain_lower in LEGITIMATE_OFFICE_DOMAINS
    fake_office_direct = domain_lower in FAKE_OFFICE_DOMAINS
    fake_office_keyword = any(kw in domain_lower for kw in OFFICE_PHISHING_KEYWORDS)
    office_brand_spoof = False
    for brand in OFFICE_BRANDS:
        sim = SequenceMatcher(None, domain_base, brand).ratio()
        if sim > 0.70 and domain_base != brand:
            office_brand_spoof = True
            category_flags.append(f"💼 Office brand spoof: '{domain_base}' mimics '{brand}' ({sim:.0%})")
            category_score += 0.75
            break
 
    if real_office:
        category = "Office/Corporate"
        category_icon = "💼"
        category_flags.append(f"💼 Verified office/corporate platform")
    elif fake_office_direct or fake_office_keyword or office_brand_spoof:
        category = "Office/Corporate"
        category_icon = "💼"
        is_fake = True
        if fake_office_direct:
            category_flags.append(f"🚨 Confirmed fake office/corporate domain")
            category_score += 1.0
        if fake_office_keyword:
            matched = [kw for kw in OFFICE_PHISHING_KEYWORDS if kw in domain_lower]
            category_flags.append(f"🚨 Office phishing keyword: '{matched[0]}'")
            category_score += 0.65
 
    # ── WORLD CUP ───────────────────────────────────────────
    wc_direct = domain_lower in WORLDCUP_PHISHING_DOMAINS
    wc_keyword = any(kw in domain_lower for kw in WORLDCUP_PHISHING_EMAIL_KEYWORDS)
 
    if wc_direct or wc_keyword:
        category = "World Cup 2026"
        category_icon = "⚽"
        is_fake = True
        if wc_direct:
            category_flags.append(f"⚽ Confirmed World Cup 2026 phishing domain")
            category_score += 1.0
        if wc_keyword:
            matched = [kw for kw in WORLDCUP_PHISHING_EMAIL_KEYWORDS if kw in domain_lower]
            category_flags.append(f"⚽ World Cup phishing keyword: '{matched[0]}'")
            category_score += 0.65
 
    return {
        "category": category,
        "category_icon": category_icon,
        "is_fake_category": is_fake,
        "category_flags": category_flags,
        "category_score": round(min(category_score, 1.0), 4),
    }
 
 
# ============================================================
# EMAIL DOMAIN ANALYSIS ENGINE
# ============================================================
 
def check_email_domain(email: str) -> dict:
    result = {
        "email": email,
        "domain": "",
        "is_suspicious": False,
        "risk_level": "Low",
        "score": 0.0,
        "flags": [],
        "worldcup_related": False,
        "verdict": "Clean Email Domain",
        # New category fields
        "domain_category": "General",
        "domain_category_icon": "🌐",
        "is_fake_category": False,
    }
 
    if not email or "@" not in email:
        result["is_suspicious"] = True
        result["flags"].append("Invalid email format — missing @")
        result["score"] = 1.0
        result["risk_level"] = "Critical"
        result["verdict"] = "Invalid / Malformed Email"
        return result
 
    parts = email.lower().strip().rsplit("@", 1)
    local_part = parts[0]
    domain = parts[1]
    result["domain"] = domain
 
    # ── Classify domain category first ──────────────────────
    cat_info = classify_domain_category(domain)
    result["domain_category"] = cat_info["category"]
    result["domain_category_icon"] = cat_info["category_icon"]
    result["is_fake_category"] = cat_info["is_fake_category"]
    result["flags"].extend(cat_info["category_flags"])
    result["score"] += cat_info["category_score"]
 
    if cat_info["category"] == "World Cup 2026":
        result["worldcup_related"] = True
 
    # ── Whitelist — skip further checks for trusted domains ──
    if domain in LEGITIMATE_EMAIL_DOMAINS and not cat_info["is_fake_category"]:
        result["verdict"] = "Trusted Email Provider"
        result["domain_category"] = "General"
        result["domain_category_icon"] = "🌐"
        return result
 
    # ── Trusted real government domain ──────────────────────
    if cat_info["category"] == "Government" and not cat_info["is_fake_category"]:
        result["verdict"] = "Verified Government Email Domain"
        result["risk_level"] = "Low"
        return result
 
    # ── Trusted real education domain ───────────────────────
    if cat_info["category"] == "Education" and not cat_info["is_fake_category"]:
        result["verdict"] = "Verified Educational Institution Domain"
        result["risk_level"] = "Low"
        return result
 
    # ── Trusted real office/corporate domain ────────────────
    if cat_info["category"] == "Office/Corporate" and not cat_info["is_fake_category"]:
        result["verdict"] = "Verified Office / Corporate Platform"
        result["risk_level"] = "Low"
        return result
 
    # 1. Disposable / temp email provider
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        result["is_suspicious"] = True
        result["flags"].append(f"Disposable/temp email provider: {domain}")
        result["score"] += 0.70
 
    # 2. Direct World Cup phishing domain blacklist match
    if domain in WORLDCUP_PHISHING_DOMAINS:
        result["is_suspicious"] = True
        result["worldcup_related"] = True
        result["flags"].append(f"⚽ CONFIRMED World Cup 2026 phishing domain: {domain}")
        result["score"] += 1.0
 
    # 3. World Cup keyword pattern in domain
    for kw in WORLDCUP_PHISHING_EMAIL_KEYWORDS:
        if kw in domain:
            result["is_suspicious"] = True
            result["worldcup_related"] = True
            result["flags"].append(f"⚽ World Cup phishing keyword in domain: '{kw}'")
            result["score"] += 0.65
            break
 
    # 4. Suspicious TLD + event keyword combo
    event_keywords = ["fifa", "worldcup", "ticket", "wc2026", "stream", "fan", "soccer",
                      "gov", "government", "official", "edu", "education", "university",
                      "office", "microsoft", "outlook", "support"]
    for tld in SUSPICIOUS_PHISHING_TLDS:
        if domain.endswith(tld):
            result["flags"].append(f"Suspicious TLD detected: {tld}")
            result["score"] += 0.30
            if any(kw in domain for kw in event_keywords):
                result["flags"].append(f"Suspicious TLD + impersonation keyword combo: {domain}")
                result["score"] += 0.35
                if any(kw in domain for kw in ["fifa", "worldcup", "wc2026"]):
                    result["worldcup_related"] = True
            break
 
    # 5. Brand impersonation (fuzzy match)
    for brand in known_brands:
        domain_base = domain.split('.')[0]
        similarity = SequenceMatcher(None, domain_base, brand).ratio()
        if similarity > 0.65 and domain_base != brand:
            result["is_suspicious"] = True
            result["flags"].append(f"Brand impersonation: '{domain_base}' mimics '{brand}' ({similarity:.0%} match)")
            result["score"] += 0.75
            if brand in ['fifa', 'worldcup', 'fifaworldcup']:
                result["worldcup_related"] = True
            break
 
    # 6. Excessive hyphens
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        result["flags"].append(f"Multiple hyphens in domain ({hyphen_count}) — common in fake sites")
        result["score"] += 0.25
 
    # 7. Very long domain name
    domain_name_part = domain.split('.')[0]
    if len(domain_name_part) > 20:
        result["flags"].append(f"Unusually long domain name ({len(domain_name_part)} chars)")
        result["score"] += 0.20
 
    # 8. High digit count in username (bulk-generated accounts)
    digit_count = sum(c.isdigit() for c in local_part)
    if digit_count > 4:
        result["flags"].append(f"High digit count in username ({digit_count} digits) — possible auto-generated")
        result["score"] += 0.15
 
    # 9. Suspicious local-part keywords
    suspicious_local_keywords = [
        "noreply", "no-reply", "donotreply", "support-", "verify",
        "secure", "alert", "account", "update", "billing",
        "fifa", "worldcup", "ticket", "winner", "prize",
        "gov", "government", "tax", "refund", "irs", "hmrc",
        "edu", "scholarship", "grant", "financial-aid",
        "office365", "microsoft", "helpdesk", "it-support",
    ]
    for kw in suspicious_local_keywords:
        if kw in local_part:
            result["flags"].append(f"Suspicious keyword in email username: '{kw}'")
            result["score"] += 0.20
            break
 
    # ── Cap score and assign risk level ─────────────────────
    result["score"] = round(min(result["score"], 1.0), 4)
 
    if result["score"] >= 0.80:
        result["risk_level"] = "Critical"
        result["is_suspicious"] = True
        result["verdict"] = "High-Risk Phishing Email Domain"
    elif result["score"] >= 0.50:
        result["risk_level"] = "High"
        result["is_suspicious"] = True
        result["verdict"] = "Suspicious Email Domain"
    elif result["score"] >= 0.25:
        result["risk_level"] = "Medium"
        result["is_suspicious"] = True
        result["verdict"] = "Potentially Suspicious Domain"
    elif result["score"] > 0:
        result["risk_level"] = "Low"
        result["verdict"] = "Minor Risk Signals Detected"
    else:
        result["verdict"] = "Clean Email Domain"
 
    # ── Append category context to verdict ──────────────────
    if result["is_fake_category"]:
        cat_label = cat_info["category"]
        cat_icon = cat_info["category_icon"]
        result["verdict"] = f"{cat_icon} FAKE {cat_label} Impersonation — {result['verdict']}"
 
    if result["worldcup_related"] and "World Cup" not in result["verdict"]:
        result["verdict"] = f"⚽ {result['verdict']} — World Cup 2026 Phishing Campaign"
 
    print(f"📧 Email Domain Check | {email} → {result['verdict']} (score: {result['score']}) [{result['domain_category']}]")
    return result
 
 
# ============================================================
# FLASK ROUTES
# ============================================================
 
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
 
 
@app.route('/check-email', methods=['POST'])
def check_email_route():
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
 
        if not email:
            return jsonify({'error': 'Please provide an email address.'}), 400
 
        result = check_email_domain(email)
 
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (scan_type, input_data, result, score) VALUES (?, ?, ?, ?)",
            ("email", email, result['verdict'], int(result['score'] * 100))
        )
        conn.commit()
        conn.close()
 
        return jsonify(result)
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
 
        analysis_res = analyze_message(message, msg_type)
 
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
        "report": get_model_report()
    })
 
 
@app.route('/api/history', methods=['GET'])
def get_recent_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
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
 
 
@app.route('/api/worldcup-threats', methods=['GET'])
def get_worldcup_threats():
    return jsonify({
        "total_domains": len(set(WORLDCUP_PHISHING_DOMAINS)),
        "phishing_domains": sorted(set(WORLDCUP_PHISHING_DOMAINS)),
        "email_keywords": WORLDCUP_PHISHING_EMAIL_KEYWORDS,
        "disposable_providers": DISPOSABLE_EMAIL_DOMAINS,
        "source": "FBI IC3 PSA260527, Group-IB, Cyble, FortiGuard Labs, CybelAngel — June 2026",
        "tournament_window": "June 11 – July 19, 2026"
    })
 
 
if __name__ == '__main__':
    print("🚀 Booting up backend automation server...")
    print("⚽ World Cup 2026 phishing intelligence loaded:")
    print(f"   → {len(set(WORLDCUP_PHISHING_DOMAINS))} known malicious domains")
    print(f"   → {len(DISPOSABLE_EMAIL_DOMAINS)} disposable email providers")
    print(f"   → {len(WORLDCUP_PHISHING_EMAIL_KEYWORDS)} phishing keyword patterns")
    print(f"   → {len(FAKE_GOV_DOMAINS)} fake government domains")
    print(f"   → {len(FAKE_EDU_DOMAINS)} fake education domains")
    print(f"   → {len(FAKE_OFFICE_DOMAINS)} fake office/corporate domains")
    app.run(debug=True, port=5000)