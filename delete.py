import sqlite3

# Connect to the database
conn = sqlite3.connect("sweet.db")
cursor = conn.cursor()

# Delete all videos from the database
cursor.execute("DELETE FROM videos")

# Commit and close
conn.commit()
conn.close()

print("🗑️ All videos deleted successfully.")
