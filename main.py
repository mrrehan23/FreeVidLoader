from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import yt_dlp
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 🛑 Cloudflare Pages, Netlify और Localhost सभी को परमिशन
origins = [
    "https://freevidloader.pages.dev",
    "https://freevidloader.netlify.app",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS", "GET"],
    allow_headers=["*"],
)

class VideoRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "ok", "message": "FreeVidLoader API is active!"}

@app.post("/api/download")
@limiter.limit("3/minute")
async def extract_video(request: Request, data: VideoRequest):
    url = data.url
    if "youtube.com" in url or "youtu.be" in url:
        raise HTTPException(status_code=400, detail="YouTube is disabled.")

    ydl_opts = {'format': 'best', 'quiet': True, 'no_warnings': True}

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
        raise HTTPException(status_code=400, detail=str(e))
