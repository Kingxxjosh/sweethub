import sqlite3

# Connect to the database file
conn = sqlite3.connect('videos.db')
cursor = conn.cursor()

# Show latest 20 videos
cursor.execute("SELECT id, title, filename, created_at FROM video ORDER BY id DESC LIMIT 20")
videos = cursor.fetchall()

print("\n📺 Latest Videos in Database:\n")
for vid in videos:
    print(f"ID: {vid[0]} | Title: {vid[1]} | File: {vid[2]} | Date: {vid[3]}")

conn.close()
