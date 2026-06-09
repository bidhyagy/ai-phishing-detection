import pandas as pd

df = pd.read_csv('phishing.csv')
print("Total number of columns:", len(df.columns))
print("\nFirst 2 rows of the dataset:")
print(df.head(2))