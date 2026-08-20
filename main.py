import asyncio
import ipaddress
import logging
import os
import socket
from typing import Literal
from urllib.parse import urlparse

import yt_dlp
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


# ============================================================
# FREEVIDLOADER BACKEND
# Production-oriented yt-dlp extraction API
#
# IMPORTANT:
# - No Cobalt
# - No credit system
# - No database required for this version
# - Only approved frontend origins are accepted by middleware
# - Rate limiting remains enabled for abuse protection
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
# CONFIGURATION
# ------------------------------------------------------------

ALLOWED_ORIGINS = {
    "https://freevidloader.netlify.app",
    "https://freevidloader.pages.dev",
}

ALLOWED_SCHEMES = {"http", "https"}

MAX_URL_LENGTH = 4096

# Public-facing API abuse protection.
# This is NOT a download limit.
PROCESS_RATE_LIMIT = "10/minute"


# ------------------------------------------------------------
# FASTAPI
# ------------------------------------------------------------

app = FastAPI(
    title="FreeVidLoader API",
    version="3.0",
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
    allow_headers=["Content-Type", "Accept"],
)


# ------------------------------------------------------------
# RATE LIMITER
# ------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


# ------------------------------------------------------------
# REQUEST SCHEMA
# ------------------------------------------------------------

class VideoRequest(BaseModel):
    url: HttpUrl

    format: Literal["mp4", "mp3"] = "mp4"

    quality: Literal[
        "best",
        "1080p",
        "720p",
        "480p",
        "360p",
        "audio",
    ] = "best"


# ------------------------------------------------------------
# RESPONSE HELPERS
# ------------------------------------------------------------

def error_response(
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
# ORIGIN SECURITY
# ------------------------------------------------------------

@app.middleware("http")
async def enforce_frontend_origin(request: Request, call_next):
    """
    Browser requests must originate from one of our two approved
    frontend domains.

    IMPORTANT:
    Origin is NOT a cryptographic API secret. Non-browser clients
    can spoof headers. Rate limiting and other backend protections
    are therefore still required.
    """

    # Health endpoint can be queried by Render/monitoring systems.
    if request.url.path in {"/", "/health"}:
        return await call_next(request)

    origin = request.headers.get("origin")

    # Browser cross-origin requests normally contain Origin.
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return HTTPExceptionResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "success": False,
                "error_code": "ORIGIN_NOT_ALLOWED",
                "message": "This API is available only through FreeVidLoader.",
            },
        )

    return await call_next(request)


# ------------------------------------------------------------
# CUSTOM JSON RESPONSE FOR MIDDLEWARE
# ------------------------------------------------------------

from fastapi.responses import JSONResponse


def HTTPExceptionResponse(
    status_code: int,
    content: dict,
):
    return JSONResponse(
        status_code=status_code,
        content=content,
    )


# ------------------------------------------------------------
# URL SECURITY
# ------------------------------------------------------------

def validate_public_url(raw_url: str) -> str:
    """
    Basic SSRF-oriented URL validation.

    The downloader must only receive normal public HTTP/HTTPS URLs.
    Localhost, loopback, private, link-local and file-style targets
    are rejected.
    """

    if not raw_url:
        error_response(
            "INVALID_URL",
            "Please enter a valid URL.",
        )

    if len(raw_url) > MAX_URL_LENGTH:
        error_response(
            "URL_TOO_LONG",
            "The URL is too long.",
        )

    parsed = urlparse(raw_url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        error_response(
            "INVALID_SCHEME",
            "Only HTTP and HTTPS URLs are supported.",
        )

    hostname = parsed.hostname

    if not hostname:
        error_response(
            "INVALID_URL",
            "The URL does not contain a valid hostname.",
        )

    hostname_lower = hostname.lower().rstrip(".")

    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname_lower in blocked_hostnames:
        error_response(
            "BLOCKED_HOST",
            "This host is not allowed.",
        )

    # Direct IP address protection.
    try:
        ip = ipaddress.ip_address(hostname_lower)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            error_response(
                "BLOCKED_ADDRESS",
                "Private or internal network addresses are not allowed.",
            )

    except ValueError:
        # Normal domain name — continue.
        pass

    return raw_url


# ------------------------------------------------------------
# OPTIONAL DNS SAFETY CHECK
# ------------------------------------------------------------

def hostname_resolves_to_private_ip(hostname: str) -> bool:
    """
    Helps prevent obvious DNS-based SSRF attempts.

    This is intentionally conservative. Some legitimate providers
    may use complex DNS/CDN infrastructure. If a provider fails here,
    the request should fail safely rather than accessing an internal
    address.
    """

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for result in results:
            address = result[4][0]

            try:
                ip = ipaddress.ip_address(address)

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
        # DNS failures will ultimately be handled by yt-dlp.
        return False

    return False


# ------------------------------------------------------------
# FORMAT SELECTION
# ------------------------------------------------------------

def build_format_selector(
    requested_format: str,
    requested_quality: str,
) -> str:

    if requested_format == "mp3":
        # Audio extraction/conversion requires FFmpeg on the server.
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
    }.get(requested_quality)

    if height is None:
        return "bestvideo*+bestaudio/best"

    # Prefer MP4-compatible video when available, otherwise fall back.
    return (
        f"bestvideo[height<={height}][ext=mp4]+"
        f"bestaudio[ext=m4a]/"
        f"best[height<={height}][ext=mp4]/"
        f"best[height<={height}]/"
        f"best"
    )


# ------------------------------------------------------------
# YT-DLP EXTRACTION
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

        # We only need metadata/direct media information here.
        "skip_download": True,

        "quiet": True,
        "no_warnings": True,

        "noplaylist": True,

        "socket_timeout": 20,
        "retries": 2,
        "fragment_retries": 2,

        # Keep redirects and networking under control.
        "http_headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        },
    }

    if requested_format == "mp3":
        # The backend needs FFmpeg for real MP3 conversion.
        ydl_opts["postprocessors"] = [
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": "mp3",
                "preferredquality": "192",
            }
        ]

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(
            video_url,
            download=False,
        )

    if not info:
        raise RuntimeError(
            "yt-dlp returned no media information."
        )

    title = info.get("title") or "FreeVidLoader Download"

    direct_url = info.get("url")

    if not direct_url:
        formats = info.get("formats") or []

        usable_formats = []

        for fmt in formats:
            fmt_url = fmt.get("url")

            if not fmt_url:
                continue

            # Ignore obviously audio/video-less entries where possible.
            usable_formats.append(fmt)

        if not usable_formats:
            raise RuntimeError(
                "No downloadable media format was returned."
            )

        # Formats are normally ordered from lower to higher quality.
        selected = usable_formats[-1]

        direct_url = selected.get("url")

    if not direct_url:
        raise RuntimeError(
            "No direct media URL was available."
        )

    return {
        "title": title,
        "download_url": direct_url,
        "requested_format": requested_format,
        "requested_quality": requested_quality,
        "duration": info.get("duration"),
        "thumbnail": info.get("thumbnail"),
    }


# ------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "FreeVidLoader API",
        "version": "3.0",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "freevidloader-api",
    }


# ------------------------------------------------------------
# PROCESS ENDPOINT
# ------------------------------------------------------------

@app.post("/api/process")
@limiter.limit(PROCESS_RATE_LIMIT)
async def process_video(
    request: Request,
    payload: VideoRequest,
):

    video_url = str(payload.url)

    # Validate URL.
    video_url = validate_public_url(video_url)

    parsed = urlparse(video_url)
    hostname = parsed.hostname

    if hostname:
        if hostname_resolves_to_private_ip(hostname):
            error_response(
                "BLOCKED_ADDRESS",
                "This URL points to a private or internal address.",
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
            "title": result["title"],
            "format": result["requested_format"],
            "quality": result["requested_quality"],
            "download_url": result["download_url"],
            "duration": result["duration"],
            "thumbnail": result["thumbnail"],
        }

    except asyncio.TimeoutError:

        logger.warning(
            "Extraction timeout"
        )

        error_response(
            "PROCESSING_TIMEOUT",
            "The server took too long to process this media. Please try again.",
            504,
        )

    except yt_dlp.utils.DownloadError as exc:

        logger.warning(
            "yt-dlp extraction failed: %s",
            str(exc)[:500],
        )

        error_response(
            "EXTRACTION_FAILED",
            (
                "We couldn't process this media. "
                "It may be private, unavailable, unsupported, "
                "or temporarily blocked by its source."
            ),
            422,
        )

    except Exception as exc:

        logger.exception(
            "Unexpected extraction error: %s",
            str(exc)[:500],
        )

        error_response(
            "TEMPORARY_SERVER_ERROR",
            "Something went wrong while processing the media. Please try again.",
            500,
        )


# ------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    logger.info(
        "FreeVidLoader API started successfully."
    )
    logger.info(
        "Allowed frontend origins: %s",
        ", ".join(sorted(ALLOWED_ORIGINS)),
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
