
import sqlite3

from config import DB_PATH

conn = sqlite3.connect(str(DB_PATH))

rows = conn.execute("""
    SELECT ground_truth
    FROM api_logs
    WHERE traffic_source = 'attack_simulator'
      AND request_id IS NOT NULL
      AND TRIM(request_id) != ''
    ORDER BY id DESC
    LIMIT 32
""").fetchall()

labels = [row[0] for row in rows]

print("Latest benchmark events:", len(labels))
print("Benign events (0):", labels.count(0))
print("Attack events (1):", labels.count(1))

conn.close()
