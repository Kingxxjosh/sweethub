import os
from app import db, app, Video

# Video meta info
CATEGORY = "Amateur"
VERSION = "Full HD"
COUNTRY = "USA"
USERNAME = "admin"

VIDEO_FOLDER = "static/uploads"

# Only get mp4 files
video_files = [f for f in os.listdir(VIDEO_FOLDER) if f.endswith(".mp4")]

with app.app_context():
    # ✅ Step 1: Clear all existing videos
    deleted_count = Video.query.delete()
    db.session.commit()
    print(f"🗑️  Deleted {deleted_count} old videos.")

    # ✅ Step 2: Re-import from folder
    for filename in video_files:
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
    print(f"✅ Imported {len(video_files)} videos from: {VIDEO_FOLDER}")
