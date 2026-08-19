from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import yt_dlp

app = FastAPI()

# Frontend से रिक्वेस्ट अलाउ करने के लिए CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class VideoRequest(BaseModel):
    url: str

@app.post("/api/download")
async def extract_video(data: VideoRequest):
    url = data.url
    
    # लीगल सेफ्टी: YouTube को ब्लॉक करें (Optional, लेकिन सुरक्षित)
    if "youtube.com" in url or "youtu.be" in url:
        raise HTTPException(status_code=400, detail="YouTube downloading is disabled to respect copyright policies.")

    ydl_opts = {
        'format': 'best',
        'quiet': True,
        'no_warnings': True,
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            return {
                "success": True,
                "title": info.get('title'),
                "thumbnail": info.get('thumbnail'),
                "download_url": info.get('url'),
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error extracting video: {str(e)}")
      
