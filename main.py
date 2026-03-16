import os
import uuid
import time
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import re

app = FastAPI(title="LARA Drop")

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

def sanitize_filename(filename: str) -> str:
    # Remove any path traversal attempts and keep only safe characters
    name = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

import secrets

# In-memory storage for file metadata
class shared_file(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int
    uploader_ip: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    timestamp: float
    expires_at: float
    is_public: bool = False
    access_token: Optional[str] = None

files_metadata: List[shared_file] = []

def get_client_ip(request: Request):
    # Try to get the real IP if behind a proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

@app.post("/api/upload")
@limiter.limit("5/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    lat: Optional[float] = Form(None),
    lon: Optional[float] = Form(None),
    is_public: bool = Form(False),
    expires_in: int = Form(1)
):
    safe_name = sanitize_filename(file.filename)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    access_token = None
    if is_public:
        access_token = secrets.token_urlsafe(192)
    
    # Large file protection (cap at 100MB for demo)
    content = await file.read(100 * 1024 * 1024)
    if await file.read(1):  # Try to read one more byte
         raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    with open(file_path, "wb") as buffer:
        buffer.write(content)
    
    now = time.time()
    metadata = shared_file(
        id=file_id,
        filename=safe_name,
        content_type=file.content_type,
        size=len(content),
        uploader_ip=get_client_ip(request),
        lat=lat,
        lon=lon,
        timestamp=now,
        expires_at=now + (expires_in * 3600),
        is_public=is_public,
        access_token=access_token
    )
    files_metadata.append(metadata)
    
    return {
        "status": "success", 
        "file_id": file_id, 
        "is_public": is_public,
        "access_token": access_token,
        "expires_at": metadata.expires_at
    }

@app.get("/api/discover")
async def discover_files(
    request: Request,
    lat: Optional[float] = None,
    lon: Optional[float] = None
):
    client_ip = get_client_ip(request)
    client_subnet = ".".join(client_ip.split(".")[:-1])
    
    now = time.time()
    nearby_files = []
    
    for f in files_metadata:
        if f.expires_at < now:
            continue
            
        is_nearby = False
        
        # 1. Matching Subnet (Network Discovery)
        f_subnet = ".".join(f.uploader_ip.split(".")[:-1])
        if f_subnet == client_subnet:
            is_nearby = True
            
        # 2. Geolocation Discovery (within ~500m)
        if not is_nearby and lat is not None and lon is not None and f.lat is not None and f.lon is not None:
            # Simple Euclidean distance for small scales
            dist = ((f.lat - lat)**2 + (f.lon - lon)**2)**0.5
            # ~0.005 degrees is roughly 500m
            if dist < 0.005:
                is_nearby = True
        
        if is_nearby:
            nearby_files.append(f)
            
    return nearby_files

@app.get("/api/download/{file_id}")
@limiter.limit("20/minute")
async def download_file(request: Request, file_id: str, lat: Optional[float] = None, lon: Optional[float] = None):
    file_meta = next((f for f in files_metadata if f.id == file_id), None)
    if not file_meta or file_meta.expires_at < time.time():
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    # Strict proximity check for non-public downloads
    if not file_meta.is_public:
        client_ip = get_client_ip(request)
        client_subnet = ".".join(client_ip.split(".")[:-1])
        uploader_subnet = ".".join(file_meta.uploader_ip.split(".")[:-1])
        
        is_auth = False
        if client_subnet == uploader_subnet:
            is_auth = True
        elif lat is not None and lon is not None and file_meta.lat is not None and file_meta.lon is not None:
             dist = ((file_meta.lat - lat)**2 + (file_meta.lon - lon)**2)**0.5
             if dist < 0.005:
                 is_auth = True
        
        if not is_auth:
            raise HTTPException(status_code=403, detail="Security Error: Proximity mismatch for private sharing")
    
    file_path = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File content missing")
        
    return FileResponse(file_path, filename=file_meta.filename, media_type=file_meta.content_type)

@app.get("/api/p/{access_token}")
@limiter.limit("50/minute")
async def public_download(access_token: str):
    # Public downloads via long random token - No proximity check needed
    file_meta = next((f for f in files_metadata if f.access_token == access_token), None)
    if not file_meta or file_meta.expires_at < time.time():
        raise HTTPException(status_code=404, detail="Invalid or expired link")
        
    file_path = os.path.join(UPLOAD_DIR, file_meta.id)
    return FileResponse(file_path, filename=file_meta.filename, media_type=file_meta.content_type)

from fastapi.concurrency import run_in_threadpool
import asyncio

async def cleanup_loop():
    while True:
        now = time.time()
        to_remove = []
        for f in files_metadata:
            if f.expires_at < now:
                to_remove.append(f)
        
        for f in to_remove:
            files_metadata.remove(f)
            file_path = os.path.join(UPLOAD_DIR, f.id)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"Cleanup: Deleted expired file {f.filename}")
                except:
                    pass
        
        await asyncio.sleep(60) # Run cleanup every minute

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_loop())

# Serve static files (Frontend)
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("index.html", "r", encoding="utf-8") as f:
        content = f.read()
        # Ensure CSS path is correct if we changed it, but for now we'll just fix the link in index.html
        return content

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
