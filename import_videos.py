import os
import sqlite3
from pathlib import Path

# === CONFIGURATION ===
VIDEO_FOLDER = "static/uploads"
USERNAME = "admin"
CATEGORY_LIST = ["Amateur", "Teen", "Mature", "Lesbian", "Solo", "Ebony", "Hardcore", "Public"]
VERSION = "HD"
COUNTRY = "us"

# === CONNECT TO DATABASE ===
db = sqlite3.connect("sweet.db")
cursor = db.cursor()

# === GET ALL .MP4 VIDEOS ===
video_files = [f for f in os.listdir(VIDEO_FOLDER) if f.endswith(".mp4")]
print(f"✅ Found {len(video_files)} video files in '{VIDEO_FOLDER}'")

# === AVOID DUPLICATES ===
cursor.execute("SELECT filename FROM videos")
existing_files = set(row[0] for row in cursor.fetchall())

new_count = 0

for i, filename in enumerate(video_files):
    if filename in existing_files:
        print(f"⚠️ Skipping duplicate: {filename}")
        continue

    raw_title = Path(filename).stem
    title = raw_title.replace("_", " ").replace("-", " ").strip().capitalize()
    category = CATEGORY_LIST[i % len(CATEGORY_LIST)]

    # Insert into DB
    cursor.execute("""
        INSERT INTO videos (
            title, filename, thumbnail, category, version, country,
            views, likes, is_premium, username, embed_code
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, NULL)
    """, (title, filename, None, category, VERSION, COUNTRY, USERNAME))

    new_count += 1

# === FINALIZE ===
db.commit()
db.close()

print(f"✅ Successfully imported {new_count} new videos.")
