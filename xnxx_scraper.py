import os
import requests
from bs4 import BeautifulSoup
import yt_dlp

DOWNLOAD_FOLDER = r'C:\Users\USER\Batch'
BASE_URL = 'https://www.thumbzilla.com/'

# Ensure the download folder exists
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# Function to get video links from Thumbzilla

def get_video_links(page=1):
    url = f'{BASE_URL}newest/{page}'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = []

    for thumb in soup.select('.thumb a'):  # Select all links in thumbnail sections
        href = thumb.get('href')
        if href:
            links.append(BASE_URL.strip('/') + href)

    return links

# Function to download a video from its page URL

def download_video(video_page_url):
    try:
        ydl_opts = {
            'outtmpl': os.path.join(DOWNLOAD_FOLDER, '%(title)s.%(ext)s'),
            'quiet': True,
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([video_page_url])

        print(f"Downloaded: {video_page_url}")
    except Exception as e:
        print(f"Failed to download {video_page_url}: {e}")


if __name__ == '__main__':
    pages_to_scrape = 5  # Change this to scrape more pages (each page ~20 videos)

    for page in range(1, pages_to_scrape + 1):
        print(f"Scraping page {page}")
        video_links = get_video_links(page)

        for video_url in video_links:
            download_video(video_url)

    print("\n✅ Download Completed!")
