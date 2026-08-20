import os
import asyncio
import requests
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import yt_dlp

app = FastAPI(title="FreeVidLoader Dual-Engine Server")

# 1. CORS Middleware - Netlify, Cloudflare aur sabhi Domains ke liye Access Enable karta hai
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Input Data Model
class VideoRequest(BaseModel):
    url: HttpUrl

@app.get("/")
def health_check():
    return {
        "status": "online",
        "system": "All-in-One Video Downloader Engine",
        "version": "2.0-DualEngine"
    }

# --- Engine 1: yt-dlp Extractor ---
def extract_with_ytdlp(video_url: str):
    ydl_opts = {
        'format': 'best',
        'quiet': True,
        'no_warnings': True,
        'extract_flat': False,
        'socket_timeout': 10,
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(video_url, download=False)
        download_url = info.get('url')
        if not download_url and 'formats' in info:
            for fmt in reversed(info['formats']):
                if fmt.get('url'):
                    download_url = fmt['url']
                    break
        
        if not download_url:
            raise Exception("yt-dlp could not find a direct download URL.")

        return {
            "title": info.get('title', 'Social Media Video'),
            "download_url": download_url
        }

# --- Engine 2: Fallback API Extractor (Cobalt / Open Engine) ---
def extract_with_fallback(video_url: str):
    response = requests.post(
        "https://api.cobalt.tools/api/json",
        json={"url": video_url},
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        timeout=10
    )
    if response.status_code == 200:
        data = response.json()
        direct_url = data.get("url")
        if direct_url:
            return {
                "title": "Social Media Video",
                "download_url": direct_url
            }
    raise Exception("Fallback Engine failed to extract video link.")

# 3. Main Download API Endpoint
@app.post("/api/download")
async def extract_video(payload: VideoRequest):
    video_url = str(payload.url)
    loop = asyncio.get_event_loop()
    
    # Attempt 1: Try Primary Engine (yt-dlp)
    try:
        result = await loop.run_in_executor(None, extract_with_ytdlp, video_url)
        if result and result.get("download_url"):
            return {
                "success": True,
                "engine_used": "primary_ytdlp",
                "title": result.get("title"),
                "download_url": result.get("download_url")
            }
    except Exception as primary_error:
        print(f"[Engine 1 Failed] Trying Fallback Engine... Error: {primary_error}")

    # Attempt 2: Try Secondary Fallback Engine
    try:
        result = await loop.run_in_executor(None, extract_with_fallback, video_url)
        if result and result.get("download_url"):
            return {
                "success": True,
                "engine_used": "secondary_fallback",
                "title": result.get("title"),
                "download_url": result.get("download_url")
            }
    except Exception as fallback_error:
        print(f"[Engine 2 Failed] Both engines failed. Error: {fallback_error}")

    # If Both Engines Fail
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unable to extract video direct link. The video might be private, age-restricted, or unsupported."
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
