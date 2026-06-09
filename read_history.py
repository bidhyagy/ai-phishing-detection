import sqlite3

# This points directly to the database file shown in your screenshot
DB_PATH = r"C:\Users\user\OneDrive\Desktop\Ai based phisphing detection\scan_history.db"

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Fetch all logged scans
    cursor.execute("SELECT * FROM scans;")
    rows = cursor.fetchall()
    
    print("\n📊 === LIVE SQLITE SCAN HISTORY LEDGER ===")
    if not rows:
        print("Empty database. No scans logged yet.")
    else:
        for row in rows:
            print(f"ID: {row[0]} | Link: {row[1]} | Result: {row[2]} | Time: {row[3]}")
    print("==========================================\n")
    
    conn.close()
except Exception as e:
    print(f"❌ Error reading database: {e}")