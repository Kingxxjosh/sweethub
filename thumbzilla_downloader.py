import requests
from bs4 import BeautifulSoup
import yt_dlp
import os

BASE_URL = 'https://www.thumbzilla.com'
SAVE_FOLDER = r'C:\Users\USER\Batch'

if not os.path.exists(SAVE_FOLDER):
    os.makedirs(SAVE_FOLDER)

def scrape_video_links(page_url):
    print(f"Scraping: {page_url}")
    response = requests.get(page_url)
    soup = BeautifulSoup(response.content, 'html.parser')

    video_links = []
    for a in soup.select('a.video-title'):
        link = a['href']
        if link.startswith('/video/'):
            full_link = BASE_URL + link
            video_links.append(full_link)

    return video_links

def download_video(video_url):
    ydl_opts = {
        'outtmpl': os.path.join(SAVE_FOLDER, '%(title)s.%(ext)s'),
        'format': 'best',
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        try:
            ydl.download([video_url])
        except Exception as e:
            print(f"Failed to download {video_url}: {e}")

if __name__ == '__main__':
    pages_to_scrape = 3  # Change to more pages like 10, 20 if you want more videos

    for page_num in range(1, pages_to_scrape + 1):
        url = f'{BASE_URL}/newest/{page_num}'
        video_links = scrape_video_links(url)

        for video_link in video_links:
            print(f'Downloading: {video_link}')
            download_video(video_link)

    print('Download complete!')
