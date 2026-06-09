import sqlite3
 
conn = sqlite3.connect('phishing_history.db')
cursor = conn.cursor()
 
cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        url TEXT,
        prediction TEXT
    )
''')
 
conn.commit()
conn.close()
 
print("✅ SQLite Database initialized! 'phishing_history.db' is ready.")
 
