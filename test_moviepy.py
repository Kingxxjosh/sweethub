from moviepy.editor import VideoFileClip

clip = VideoFileClip("static/uploads/sample.mp4")  # make sure sample.mp4 exists
print("✅ MoviePy works! Duration:", clip.duration)
