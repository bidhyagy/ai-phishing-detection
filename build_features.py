import pandas as pd
import re
import os

# Check both possible datasets visible in your sidebar
possible_files = ['phishing.csv', 'dataset.csv']
target_file = None

for file_name in possible_files:
    if os.path.exists(file_name):
        target_file = file_name
        break

if target_file is None:
    print("❌ Error: Could not find 'phishing.csv' or 'dataset.csv' in this folder!")
    print("Files found in your directory:", os.listdir('.'))
    exit()

print(f"🔄 Target detected: '{target_file}'. Upgrading columns now...")

try:
    df = pd.read_csv(target_file)
    
    # Fix case differences (e.g. 'URL' vs 'url')
    df.columns = [col.lower() for col in df.columns]
    
    if 'url' not in df.columns:
        print(f"❌ Error: 'url' column missing in {target_file}!")
        print("Columns present:", list(df.columns))
        exit()

    print("🧠 Engineering the 5 ML features...")
    df['count_dashes'] = df['url'].apply(lambda x: str(x).count('-'))
    df['count_dots'] = df['url'].apply(lambda x: str(x).count('.'))
    df['has_https'] = df['url'].apply(lambda x: 1 if str(x).lower().startswith('https') else -1)
    
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    df['has_ip'] = df['url'].apply(lambda x: 1 if re.search(ip_pattern, str(x)) else -1)
    
    df['url_length'] = df['url'].apply(lambda x: len(str(x)))

    # Save over the file with the brand-new structural columns!
    df.to_csv(target_file, index=False)
    print(f"✅ Success! '{target_file}' now perfectly matches your AI model's dimensions.")
    print(df.head(2))

except Exception as e:
    print(f"❌ Structural shift failed: {e}")