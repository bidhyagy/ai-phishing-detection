import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

df = pd.read_csv('phishing.csv')
X = df.drop(columns=['Index', 'class'])
y = df['class']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print(f"Accuracy: {accuracy_score(y_test, model.predict(X_test))*100:.2f}%")

pickle.dump(model, open('model.pkl','wb'))
pickle.dump(list(X.columns), open('features.pkl','wb'))
print("Done! Run: python server.py")
