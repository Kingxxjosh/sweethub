import os
from moviepy.editor import VideoFileClip
from app import db, app, Video  # Ensure correct import path

UPLOAD_FOLDER = 'static/uploads'
THUMB_FOLDER = 'static/thumbnails'

os.makedirs(THUMB_FOLDER, exist_ok=True)

with app.app_context():
    videos = Video.query.all()
    for video in videos:
        if not video.video_url:
            print(f"⚠️ Skipping video {video.id} - No video_url.")
            continue

        video_path = os.path.join(UPLOAD_FOLDER, video.video_url)
        thumb_path = os.path.join(THUMB_FOLDER, f"{video.id}.jpg")

        if os.path.exists(thumb_path):
            print(f"ℹ️ Thumbnail already exists for {video.filename}")
            continue

        if not os.path.exists(video_path):
            print(f"❌ Video file not found for {video.filename} at {video_path}")
            continue

        try:
            clip = VideoFileClip(video_path)
            middle = clip.duration / 2
            clip.save_frame(thumb_path, t=middle)
            clip.close()

            video.thumbnail_url = f"thumbnails/{video.id}.jpg"
            db.session.commit()
            print(f"✅ Thumbnail created for {video.filename} -> {thumb_path}")
        except Exception as e:
            print(f"❌ Failed to process {video.filename}: {e}")
