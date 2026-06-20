import sqlite3

# Connect to your history database
conn = sqlite3.connect('scan_history.db')
cursor = conn.cursor()

# Fetch all rows from your history table
# (Note: Change 'scans' to whatever your history table name is if different)
try:
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    
    print("\n--- SCAN HISTORY LOG ---")
    for row in rows:
        print(row)
except sqlite3.OperationalError as e:
    print(f"Error reading table: {e}. Check your table name in server.py!")

conn.close()