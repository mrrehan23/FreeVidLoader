import asyncio
import ipaddress
import logging
import os
import socket
import secrets
from typing import Literal
from urllib.parse import urlparse

import yt_dlp

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


# ============================================================
# FREEVIDLOADER BACKEND
# Security + yt-dlp extraction
# ============================================================


# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("freevidloader")


# ------------------------------------------------------------
# FRONTEND DOMAINS
# ------------------------------------------------------------

ALLOWED_ORIGINS = {
    "https://freevidloader.netlify.app",
    "https://freevidloader.pages.dev",
}


# ------------------------------------------------------------
# SERVER SECRET
# ------------------------------------------------------------

EDGE_API_SECRET = os.environ.get("EDGE_API_SECRET")

if not EDGE_API_SECRET:
    raise RuntimeError(
        "EDGE_API_SECRET environment variable is missing."
    )


# ------------------------------------------------------------
# RATE LIMIT
# ------------------------------------------------------------

PROCESS_RATE_LIMIT = "10/minute"


# ------------------------------------------------------------
# APP
# ------------------------------------------------------------

app = FastAPI(
    title="FreeVidLoader API",
    version="3.1",
    docs_url=None,
    redoc_url=None,
)


# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-FreeVidLoader-Auth"],
)


# ------------------------------------------------------------
# RATE LIMITER
# ------------------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address
)

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


# ------------------------------------------------------------
# REQUEST MODEL
# ------------------------------------------------------------

class VideoRequest(BaseModel):

    url: HttpUrl

    format: Literal[
        "mp4",
        "mp3",
    ] = "mp4"

    quality: Literal[
        "best",
        "1080p",
        "720p",
        "480p",
        "360p",
        "audio",
    ] = "best"


# ------------------------------------------------------------
# ERROR HELPER
# ------------------------------------------------------------

def fail(
    code: str,
    message: str,
    http_status: int = 400,
):

    raise HTTPException(
        status_code=http_status,
        detail={
            "success": False,
            "error_code": code,
            "message": message,
        },
    )


# ------------------------------------------------------------
# SECURITY:
# AUTHENTICATED REQUEST CHECK
# ------------------------------------------------------------

def verify_backend_secret(
    request: Request,
):

    supplied_secret = request.headers.get(
        "X-FreeVidLoader-Auth"
    )

    if not supplied_secret:

        fail(
            "UNAUTHORIZED",
            "Unauthorized request.",
            401,
        )

    # Constant-time comparison.
    if not secrets.compare_digest(
        supplied_secret,
        EDGE_API_SECRET,
    ):

        fail(
            "UNAUTHORIZED",
            "Unauthorized request.",
            401,
        )


# ------------------------------------------------------------
# SECURITY:
# APPROVED FRONTEND ORIGIN
# ------------------------------------------------------------

def verify_frontend_origin(
    request: Request,
):

    origin = request.headers.get("origin")

    if origin is None:
        return

    if origin not in ALLOWED_ORIGINS:

        fail(
            "ORIGIN_NOT_ALLOWED",
            "This API is available only through FreeVidLoader.",
            403,
        )


# ------------------------------------------------------------
# URL VALIDATION
# ------------------------------------------------------------

def validate_public_url(
    raw_url: str,
):

    if not raw_url:

        fail(
            "INVALID_URL",
            "Please enter a valid URL.",
        )

    if len(raw_url) > 4096:

        fail(
            "URL_TOO_LONG",
            "The URL is too long.",
        )

    parsed = urlparse(raw_url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:

        fail(
            "INVALID_SCHEME",
            "Only HTTP and HTTPS URLs are supported.",
        )

    hostname = parsed.hostname

    if not hostname:

        fail(
            "INVALID_URL",
            "Invalid hostname.",
        )

    hostname = hostname.lower().rstrip(".")

    blocked_hosts = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_hosts:

        fail(
            "BLOCKED_HOST",
            "This host is not allowed.",
            403,
        )

    try:

        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):

            fail(
                "BLOCKED_ADDRESS",
                "Private or internal addresses are not allowed.",
                403,
            )

    except ValueError:

        pass

    return raw_url


# ------------------------------------------------------------
# DNS SECURITY CHECK
# ------------------------------------------------------------

def resolves_to_private_ip(
    hostname: str,
):

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for result in results:

            address = result[4][0]

            try:

                ip = ipaddress.ip_address(
                    address
                )

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):

                    return True

            except ValueError:

                continue

    except Exception:

        return False

    return False


# ------------------------------------------------------------
# FORMAT SELECTOR
# ------------------------------------------------------------

def build_format_selector(
    requested_format: str,
    requested_quality: str,
):

    if requested_format == "mp3":

        return "bestaudio/best"

    if requested_quality == "best":

        return (
            "bestvideo*+bestaudio/"
            "best"
        )

    height = {
        "1080p": 1080,
        "720p": 720,
        "480p": 480,
        "360p": 360,
    }.get(
        requested_quality
    )

    if height is None:

        return (
            "bestvideo*+bestaudio/"
            "best"
        )

    return (
        f"bestvideo[height<={height}][ext=mp4]+"
        f"bestaudio[ext=m4a]/"
        f"best[height<={height}][ext=mp4]/"
        f"best[height<={height}]/"
        f"best"
    )


# ------------------------------------------------------------
# YT-DLP
# ------------------------------------------------------------

def extract_media(
    video_url: str,
    requested_format: str,
    requested_quality: str,
):

    format_selector = build_format_selector(
        requested_format,
        requested_quality,
    )

    ydl_opts = {

        "format": format_selector,

        "skip_download": True,

        "quiet": True,

        "no_warnings": True,

        "noplaylist": True,

        "socket_timeout": 20,

        "retries": 2,

        "fragment_retries": 2,

        "http_headers": {
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 "
                "Safari/537.36"
            )
        },
    }

    if requested_format == "mp3":

        ydl_opts[
            "postprocessors"
        ] = [
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": "mp3",
                "preferredquality": "192",
            }
        ]

    with yt_dlp.YoutubeDL(
        ydl_opts
    ) as ydl:

        info = ydl.extract_info(
            video_url,
            download=False,
        )

    if not info:

        raise RuntimeError(
            "No media information returned."
        )

    title = (
        info.get("title")
        or "FreeVidLoader Download"
    )

    direct_url = info.get("url")

    if not direct_url:

        formats = info.get(
            "formats"
        ) or []

        usable = [
            fmt
            for fmt in formats
            if fmt.get("url")
        ]

        if not usable:

            raise RuntimeError(
                "No downloadable format found."
            )

        direct_url = usable[-1].get(
            "url"
        )

    if not direct_url:

        raise RuntimeError(
            "No direct media URL found."
        )

    return {
        "title": title,
        "download_url": direct_url,
        "format": requested_format,
        "quality": requested_quality,
        "duration": info.get("duration"),
        "thumbnail": info.get("thumbnail"),
    }


# ------------------------------------------------------------
# HEALTH
# ------------------------------------------------------------

@app.get("/")
async def root():

    return {
        "status": "online",
        "service": "FreeVidLoader API",
        "version": "3.1",
    }


@app.get("/health")
async def health():

    return {
        "status": "ok",
    }


# ------------------------------------------------------------
# PROCESS
# ------------------------------------------------------------

@app.post("/api/process")
@limiter.limit(
    PROCESS_RATE_LIMIT
)
async def process_video(
    request: Request,
    payload: VideoRequest,
):

    # SECURITY CHECK 1
    verify_frontend_origin(
        request
    )

    # SECURITY CHECK 2
    verify_backend_secret(
        request
    )

    video_url = validate_public_url(
        str(payload.url)
    )

    parsed = urlparse(
        video_url
    )

    if parsed.hostname:

        if resolves_to_private_ip(
            parsed.hostname
        ):

            fail(
                "BLOCKED_ADDRESS",
                "Private or internal address is not allowed.",
                403,
            )

    logger.info(
        "Processing request | format=%s | quality=%s",
        payload.format,
        payload.quality,
    )

    try:

        result = await asyncio.wait_for(

            asyncio.to_thread(

                extract_media,

                video_url,

                payload.format,

                payload.quality,

            ),

            timeout=35,
        )

        return {

            "success": True,

            "title": result[
                "title"
            ],

            "format": result[
                "format"
            ],

            "quality": result[
                "quality"
            ],

            "download_url": result[
                "download_url"
            ],

            "duration": result[
                "duration"
            ],

            "thumbnail": result[
                "thumbnail"
            ],
        }

    except asyncio.TimeoutError:

        logger.warning(
            "Extraction timeout"
        )

        fail(
            "PROCESSING_TIMEOUT",
            "Server took too long. Please try again.",
            504,
        )

    except yt_dlp.utils.DownloadError:

        logger.warning(
            "yt-dlp extraction failed"
        )

        fail(
            "EXTRACTION_FAILED",
            (
                "Unable to process this media. "
                "It may be private, unavailable, "
                "unsupported, or temporarily blocked."
            ),
            422,
        )

    except HTTPException:

        raise

    except Exception as exc:

        logger.exception(
            "Unexpected server error: %s",
            str(exc)[:500],
        )

        fail(
            "SERVER_ERROR",
            "Temporary server error. Please try again.",
            500,
        )


# ------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------

@app.on_event(
    "startup"
)
async def startup_event():

    logger.info(
        "FreeVidLoader API started."
    )

    logger.info(
        "Frontend origins configured: %s",
        ", ".join(
            sorted(
                ALLOWED_ORIGINS
            )
        ),
    )


# ------------------------------------------------------------
# LOCAL DEVELOPMENT
# ------------------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    port = int(
        os.environ.get(
            "PORT",
            "8000",
        )
    )

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
    )
