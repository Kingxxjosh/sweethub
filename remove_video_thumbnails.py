import os
import random
import uuid
from app import app, videos  # your in-memory list
from datetime import datetime

# Safe default values
CATEGORIES = [
    'Amateur', 'Teen', 'Mature', 'Couple', 'Lesbian', 'Solo', 'Outdoor',
    'BDSM', 'MILF', 'Ebony', 'Anal', 'Asian', 'BBW', 'Blonde', 'Blowjob',
    'Brunette', 'Creampie', 'Double Penetration', 'Facial', 'Feet', 'Fetish',
    'Gangbang', 'Hardcore', 'Interracial', 'Latina', 'Massage', 'POV',
    'Public', 'Threesome', 'Toys'
]
VERSIONS = ['HD', '4K', 'SD']
COUNTRIES = ["🇺🇸", "🇳🇬", "🇬🇧", "🇯🇵", "🇫🇷", "🇧🇷", "🇿🇦"]
USERNAME = "admin"  # Owner of the videos
VIDEO_FOLDER = "static/uploads"

# Find all mp4 videos in the folder
video_files = [f for f in os.listdir(VIDEO_FOLDER) if f.endswith('.mp4')]

added = 0

for filename in video_files:
    # Skip if already imported
    if any(v['filename'] == filename for v in videos):
        continue

    # Randomly assign category/version/country
    category = random.choice(CATEGORIES)
    version = random.choice(VERSIONS)
    country = random.choice(COUNTRIES)

    videos.append({
        'id': str(uuid.uuid4()),
        'title': os.path.splitext(filename)[0].replace('_', ' ').title(),
        'filename': filename,
        'thumbnail': None,
        'category': category,
        'version': version,
        'country': country,
        'tags': '',
        'embed_code': None,
        'is_premium': False,
        'views': 0,
        'likes': 0,
        'username': USERNAME
    })

    added += 1

print(f"✅ Successfully added {added} new videos to the homepage.")
