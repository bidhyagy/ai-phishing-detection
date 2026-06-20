"""
train_message_models.py
Trains and compares two classifiers for suspicious message detection:
  1. Multinomial Naive Bayes
  2. Random Forest

Run once before starting server.py:
    python train_message_models.py

Outputs:
    msg_nb_model.pkl      - Naive Bayes pipeline
    msg_rf_model.pkl      - Random Forest pipeline
    msg_model_report.json - Comparison metrics
"""

import os
import json
import pickle
import re
import numpy as np

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

# ─────────────────────────────────────────────
# 1. BUILT-IN TRAINING DATA
#    (covers SMS spam, phishing emails, smishing)
# ─────────────────────────────────────────────
TRAINING_DATA = [
    # ── SPAM / PHISHING (label = 1) ──────────────────────────────────────
    ("URGENT: Your account has been compromised. Click here immediately to verify: http://bit.ly/secure123", 1),
    ("Congratulations! You've won a $1000 gift card. Claim now: http://prize-winner.xyz/claim", 1),
    ("Your bank account will be suspended. Verify your details: http://banklogin.suspicious.com", 1),
    ("FREE entry! Text WIN to 83738 to claim your prize worth £500!", 1),
    ("ALERT: Suspicious login detected. Reset password NOW: http://fakebank.net/reset", 1),
    ("You have been selected for a FREE iPhone 15. Visit: http://free-iphone.scam.biz", 1),
    ("Dear customer, your PayPal is limited. Confirm identity: http://paypal-verify.xyz", 1),
    ("SBI Bank: Your account is blocked. Update KYC: http://sbi-kyc-update.net/login", 1),
    ("Your Amazon order is on hold. Verify payment: http://amazon-support.phish.co", 1),
    ("IRS: Final notice. Pay overdue tax of $890 to avoid arrest: http://irs-tax.fake.org", 1),
    ("WINNER! As a valued network customer you have been selected to receive a £900 prize reward!", 1),
    ("Urgent action required: Your Netflix subscription failed. Update billing: http://netflix-update.scam", 1),
    ("You owe a delivery fee. Pay £1.99 to release your parcel: http://royalmail-delivery.xyz", 1),
    ("Get rich quick! Work from home and earn $5000/week. No experience needed!", 1),
    ("Your loan has been approved! Claim $10,000 now. No credit check: http://quickloan.scam", 1),
    ("SMS: You're a winner! Our records show ur number won £2000 bonus caller prize", 1),
    ("Click this link to verify your identity or your account will be closed in 24 hours", 1),
    ("Exclusive deal: Lose 30 pounds in 30 days! Limited offer: http://weightloss.scam.biz", 1),
    ("Your Google account was accessed from unknown device. Secure it: http://google-security.fake", 1),
    ("DHL: Parcel delivery failed. Reschedule: http://dhl-delivery.phish.net/reschedule", 1),
    ("HSBC: We've noticed unusual activity. Verify now or account closes: http://hsbc-secure.fake", 1),
    ("Claim your government COVID relief fund of $1400 here: http://covid-relief.scam.gov.fake", 1),
    ("You have 1 unread voicemail. Listen now: http://voicemail-notification.phish.com", 1),
    ("Your credit score is ready! See your full report free: http://creditcheck.scam/report", 1),
    ("Crypto investment opportunity! Double your Bitcoin in 24 hours: http://crypto-invest.scam", 1),
    ("Your password expires today. Update immediately: http://microsoft-login.phish.net", 1),
    ("FREE RINGTONES! To unsubscribe send STOP to 83122. £3/wk unless cancelled", 1),
    ("As a subscriber, ur awarded a £200 bonus reward. Call 08712400603 now to claim", 1),
    ("Reminder: Your account verification is pending. Act now to avoid suspension", 1),
    ("Tax refund of £542.76 is pending. Complete form: http://hmrc-refund.scam.uk", 1),
    ("Your debit card is blocked. Call 0800-FAKE to unblock or visit http://card-unblock.xyz", 1),
    ("Congratulations you have been chosen to participate in our weekly draw. Text CLAIM to 90210", 1),
    ("IMPORTANT: Unusual signin to your Apple ID. Verify immediately: http://apple-id.phish.com", 1),
    ("Your Instagram account will be disabled for violating policies. Appeal: http://insta-appeal.fake", 1),
    ("You've earned reward points! Redeem $250 in cash: http://rewards-redeem.scam.net", 1),
    ("Job offer: Work from home, earn $500/day. Apply: http://easy-jobs.scam/apply", 1),
    ("Warning: Malware detected on your device! Call tech support: 1-800-FAKE-HELP", 1),
    ("Your electricity bill is overdue. Avoid disconnection: http://electricity-pay.scam", 1),
    ("You qualify for a personal loan up to $50,000. Apply in 2 minutes: http://loan-fast.xyz", 1),
    ("Security alert: Someone tried to log into your account from Russia. Verify: http://secure.fake", 1),

    # ── LEGITIMATE (label = 0) ────────────────────────────────────────────
    ("Hi! Are we still on for lunch tomorrow at 1pm?", 0),
    ("Your Amazon order has shipped and will arrive by Friday.", 0),
    ("Don't forget the team meeting at 3pm today in conference room B.", 0),
    ("Happy birthday! Hope you have a wonderful day!", 0),
    ("Your appointment is confirmed for Monday June 20 at 10:30am.", 0),
    ("Can you pick up some groceries on your way home? We need milk and eggs.", 0),
    ("The project report is due next Wednesday. Let me know if you need help.", 0),
    ("Hey, are you coming to the party this Saturday?", 0),
    ("Your flight BA2490 departs at 14:35 from Terminal 5. Gate closes at 14:05.", 0),
    ("Monthly bank statement for April is now available in your online banking.", 0),
    ("Reminder: your prescription is ready to collect at the pharmacy.", 0),
    ("Thanks for your order! Your receipt is attached.", 0),
    ("The library book you reserved is now available for pickup.", 0),
    ("Hi, this is Dr. Smith's office confirming your appointment tomorrow at 2pm.", 0),
    ("Your package was delivered to your front door at 3:42pm.", 0),
    ("School is closed tomorrow due to a staff training day.", 0),
    ("Your electricity bill of £87.50 is due on 15th June. Pay via your usual method.", 0),
    ("Can we reschedule our call to Thursday? I have a conflict on Wednesday.", 0),
    ("The new software update is available. Install at your convenience.", 0),
    ("Just a reminder to submit your timesheet by end of day Friday.", 0),
    ("Hi, I'll be 10 minutes late to the meeting, sorry!", 0),
    ("Your test results are normal. No further action needed.", 0),
    ("Your Netflix subscription renews on June 25 for £15.99.", 0),
    ("We've received your complaint and will respond within 5 business days.", 0),
    ("Good morning! Today's weather will be sunny with a high of 24°C.", 0),
    ("Your car service is booked for July 3rd at 9am at AutoCare garage.", 0),
    ("Please review and sign the attached document before the meeting.", 0),
    ("The quarterly review meeting is scheduled for next Tuesday at 11am.", 0),
    ("Hi, just checking in. How are you feeling after the operation?", 0),
    ("Your salary has been deposited into your account.", 0),
    ("Dinner tonight at 7? I'm thinking Italian.", 0),
    ("Your Council Tax direct debit of £145 will be collected on 1st July.", 0),
    ("The gym class you booked starts at 6:30pm, please arrive 5 minutes early.", 0),
    ("We're delighted to confirm your job application has been received.", 0),
    ("Your Wi-Fi router has been configured. Default password is on the back.", 0),
    ("Can you send me the notes from yesterday's lecture when you get a chance?", 0),
    ("Your insurance renewal is due in 30 days. We'll send details by post.", 0),
    ("Lovely to see you at the reunion! Here are the photos from the event.", 0),
    ("The road closure on Main Street will end by 6pm today.", 0),
    ("Thank you for volunteering at the food bank last weekend!", 0),
]

# ─────────────────────────────────────────────
# 2. FEATURE EXTRACTION HELPERS
# ─────────────────────────────────────────────
def preprocess(text):
    text = text.lower()
    text = re.sub(r'http\S+', ' URL ', text)
    text = re.sub(r'\d{10,}', ' PHONE ', text)
    text = re.sub(r'[^\w\s]', ' ', text)
    return text

# ─────────────────────────────────────────────
# 3. PREPARE DATA
# ─────────────────────────────────────────────
texts, labels = zip(*TRAINING_DATA)
texts = [preprocess(t) for t in texts]
labels = list(labels)

X_train, X_test, y_train, y_test = train_test_split(
    texts, labels, test_size=0.2, random_state=42, stratify=labels
)

print(f"Training samples : {len(X_train)}")
print(f"Test samples     : {len(X_test)}")
print(f"Spam in train    : {sum(y_train)}")
print(f"Legit in train   : {len(y_train) - sum(y_train)}")
print()

# ─────────────────────────────────────────────
# 4. BUILD PIPELINES
# ─────────────────────────────────────────────
tfidf = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    sublinear_tf=True
)

nb_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
    ('clf',   MultinomialNB(alpha=0.1))
])

rf_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
    ('clf',   RandomForestClassifier(n_estimators=200, max_depth=20,
                                      random_state=42, n_jobs=-1))
])

# ─────────────────────────────────────────────
# 5. TRAIN
# ─────────────────────────────────────────────
print("Training Naive Bayes ...")
nb_pipeline.fit(X_train, y_train)

print("Training Random Forest ...")
rf_pipeline.fit(X_train, y_train)

# ─────────────────────────────────────────────
# 6. EVALUATE
# ─────────────────────────────────────────────
def evaluate(name, model, X_tr, y_tr, X_te, y_te):
    y_pred = model.predict(X_te)
    cv     = cross_val_score(model, X_tr, y_tr, cv=5, scoring='f1')
    cm     = confusion_matrix(y_te, y_pred).tolist()
    report = classification_report(y_te, y_pred, target_names=['Legitimate', 'Suspicious'], output_dict=True)

    metrics = {
        "model":     name,
        "accuracy":  round(accuracy_score(y_te, y_pred) * 100, 2),
        "precision": round(precision_score(y_te, y_pred) * 100, 2),
        "recall":    round(recall_score(y_te, y_pred) * 100, 2),
        "f1":        round(f1_score(y_te, y_pred) * 100, 2),
        "cv_f1_mean": round(cv.mean() * 100, 2),
        "cv_f1_std":  round(cv.std()  * 100, 2),
        "confusion_matrix": cm,
        "class_report": {
            "legitimate": {
                "precision": round(report['Legitimate']['precision'] * 100, 2),
                "recall":    round(report['Legitimate']['recall']    * 100, 2),
                "f1":        round(report['Legitimate']['f1-score']  * 100, 2),
            },
            "suspicious": {
                "precision": round(report['Suspicious']['precision'] * 100, 2),
                "recall":    round(report['Suspicious']['recall']    * 100, 2),
                "f1":        round(report['Suspicious']['f1-score']  * 100, 2),
            }
        }
    }
    print(f"\n{'='*45}")
    print(f"  {name}")
    print(f"{'='*45}")
    print(f"  Accuracy  : {metrics['accuracy']}%")
    print(f"  Precision : {metrics['precision']}%")
    print(f"  Recall    : {metrics['recall']}%")
    print(f"  F1 Score  : {metrics['f1']}%")
    print(f"  CV F1     : {metrics['cv_f1_mean']}% ± {metrics['cv_f1_std']}%")
    print(f"  Confusion Matrix:")
    print(f"    [[TN={cm[0][0]}, FP={cm[0][1]}],")
    print(f"     [FN={cm[1][0]}, TP={cm[1][1]}]]")
    return metrics

nb_metrics = evaluate("Naive Bayes",    nb_pipeline, X_train, y_train, X_test, y_test)
rf_metrics = evaluate("Random Forest",  rf_pipeline, X_train, y_train, X_test, y_test)

# ─────────────────────────────────────────────
# 7. SAVE MODELS
# ─────────────────────────────────────────────
with open("msg_nb_model.pkl", "wb") as f:
    pickle.dump(nb_pipeline, f)

with open("msg_rf_model.pkl", "wb") as f:
    pickle.dump(rf_pipeline, f)

# ─────────────────────────────────────────────
# 8. SAVE REPORT
# ─────────────────────────────────────────────
report = {
    "models": [nb_metrics, rf_metrics],
    "winner": nb_metrics["model"] if nb_metrics["f1"] >= rf_metrics["f1"] else rf_metrics["model"],
    "training_samples": len(X_train),
    "test_samples": len(X_test)
}

with open("msg_model_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("\n")
print("✅  msg_nb_model.pkl      saved")
print("✅  msg_rf_model.pkl      saved")
print("✅  msg_model_report.json saved")
print(f"\n🏆  Better model by F1: {report['winner']}")