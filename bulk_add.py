import os
import uuid
from app import db, app, Video

# Define category to assign to all videos
CATEGORY = "Amateur"  # You can change to "Lesbian", "Teen", etc.
VERSION = "Full HD"
COUNTRY = "USA"
USERNAME = "admin"

# Path to your uploaded videos
VIDEO_FOLDER = "static/uploads"

# Only import mp4 files
video_files = [f for f in os.listdir(VIDEO_FOLDER) if f.endswith(".mp4")]

with app.app_context():
    for filename in video_files:
        # Skip if already exists
        existing = Video.query.filter_by(filename=filename).first()
        if existing:
            continue

        new_video = Video(
            title=os.path.splitext(filename)[0],
            filename=filename,
            thumbnail=None,
            category=CATEGORY,
            version=VERSION,
            country=COUNTRY,
            tags="",
            embed_code=None,
            is_premium=False,
            views=0,
            likes=0,
            username=USERNAME
        )
        db.session.add(new_video)

    db.session.commit()
    print("✅ All videos added with category:", CATEGORY)
