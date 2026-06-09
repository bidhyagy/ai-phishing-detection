import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

print("📊 Reading phishing.csv...")
df = pd.read_csv('phishing.csv')

# Isolate the 30 features by dropping Index and class
X = df.drop(columns=['Index', 'class'])
y = df['class']

print(f"🧠 Training a fresh Random Forest Classifier on all {len(X.columns)} features...")
# We use a shallow depth to prevent overfitting so it responds nicely to manual rules
model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
model.fit(X, y)

# Overwrite the old broken model.pkl file entirely
with open('model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("💾 SUCCESS! New 30-feature model overwritten onto 'model.pkl'!")