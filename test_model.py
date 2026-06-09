import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

# 1. Load the 32-column dataset
print("📊 Loading phishing.csv...")
df = pd.read_csv('phishing.csv')

# 2. Separate Features (X) and Target Label (y)
# We drop 'Index' because it's just a row number, and 'class' because it's the answer key
X = df.drop(columns=['Index', 'class'])  
y = df['class']                          # This is the target (-1 for phishing, 1 for legitimate)

# Save the exact feature names in order so our extractor can use them later
feature_names = list(X.columns)
print(f"✅ Found {len(feature_names)} features for training.")

# 3. Split data into Training set (80%) and Test set (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Initialize and Train the Random Forest Model
print("🧠 Training the 30-feature Random Forest model... Please wait...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Calculate and print Accuracy
accuracy = model.score(X_test, y_test)
print(f"🎯 Model Training Complete! Accuracy on test data: {accuracy * 100:.2f}%")

# 6. Save the newly trained model back to model.pkl
with open('model.pkl', 'wb') as file:
    pickle.dump(model, file)
print("💾 Saved new 30-feature model as 'model.pkl' successfully!")

# 7. Also save the exact feature names list so we don't lose the order
with open('feature_names.pkl', 'wb') as file:
    pickle.dump(feature_names, file)
print("💾 Saved feature order list as 'feature_names.pkl'")
