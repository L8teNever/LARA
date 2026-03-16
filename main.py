import os
import uuid
import time
import asyncio
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
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
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
import clamd

# Support multiple files per share
class file_entry(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int

class shared_bundle(BaseModel):
    id: str
    files: List[file_entry]
    uploader_ip: str
    uploader_name: Optional[str] = None # Added for Drop
    target_peer_id: Optional[str] = None # Added for Drop
    lat: Optional[float] = None
    lon: Optional[float] = None
    timestamp: float
    expires_at: float
    is_public: bool = False
    access_token: Optional[str] = None

class Peer(BaseModel):
    id: str
    name: str
    ip: str
    lat: Optional[float] = None
    lon: Optional[float] = None
    last_seen: float
    source: Optional[str] = None # Added: 'Network' or 'Location'

files_metadata: List[shared_bundle] = []
active_peers: List[Peer] = []

def get_client_ip(request: Request):
    # Try to get the real IP if behind a proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

def scan_for_viruses(file_path: str):
    try:
        # Connect to ClamAV (assumes service name 'clamav' in docker-compose)
        cd = clamd.ClamdNetworkSocket(host="clamav", port=3310)
        result = cd.scan(file_path)
        if result and any(status == 'FOUND' for _, (_, status) in result.items()):
            return False, "Virus found!"
        return True, None
    except Exception as e:
        # If ClamAV is not available (e.g. during local dev), we log and continue
        # but in production/docker it will be available.
        print(f"Virus scanner warning: {e}")
        return True, None

@app.post("/api/upload")
@limiter.limit("5/minute")
async def upload_file(
    request: Request,
    files: List[UploadFile] = File(...),
    lat: Optional[float] = Form(None),
    lon: Optional[float] = Form(None),
    is_public: bool = Form(False),
    expires_in: int = Form(1),
    uploader_name: Optional[str] = Form(None),
    target_peer_id: Optional[str] = Form(None)
):
    bundle_id = str(uuid.uuid4())
    bundle_files = []
    
    total_size = 0
    max_bundle_size = 1024 * 1024 * 1024  # 1GB
    
    for file in files:
        file_id = str(uuid.uuid4())
        safe_name = sanitize_filename(file.filename)
        file_path = os.path.join(UPLOAD_DIR, file_id)
        
        file_size = 0
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk: break
                file_size += len(chunk)
                total_size += len(chunk)
                if total_size > max_bundle_size:
                    os.remove(file_path)
                    for f in bundle_files:
                        if os.path.exists(os.path.join(UPLOAD_DIR, f.id)):
                            os.remove(os.path.join(UPLOAD_DIR, f.id))
                    raise HTTPException(status_code=413, detail="Total bundle size exceeds 1GB")
                buffer.write(chunk)
        
        safe, error = scan_for_viruses(file_path)
        if not safe:
            os.remove(file_path)
            for f in bundle_files:
                if os.path.exists(os.path.join(UPLOAD_DIR, f.id)):
                    os.remove(os.path.join(UPLOAD_DIR, f.id))
            raise HTTPException(status_code=400, detail=f"Security Alert: {error} in {safe_name}")

        bundle_files.append(file_entry(id=file_id, filename=safe_name, content_type=file.content_type, size=file_size))
    
    access_token = None
    if is_public:
        access_token = secrets.token_urlsafe(192)
    
    now = time.time()
    metadata = shared_bundle(
        id=bundle_id,
        files=bundle_files,
        uploader_ip=get_client_ip(request),
        uploader_name=uploader_name,
        target_peer_id=target_peer_id,
        lat=lat,
        lon=lon,
        timestamp=now,
        expires_at=now + (expires_in * 3600),
        is_public=is_public,
        access_token=access_token
    )
    files_metadata.append(metadata)
    
    return {"status": "success", "bundle_id": bundle_id, "is_public": is_public, "access_token": access_token}

@app.post("/api/peers/register")
async def register_peer(request: Request, peer: Peer):
    # Update or add peer
    existing = next((p for p in active_peers if p.id == peer.id), None)
    if existing:
        active_peers.remove(existing)
    
    peer.ip = get_client_ip(request)
    peer.last_seen = time.time()
    active_peers.append(peer)
    return {"status": "ok"}

@app.get("/api/peers/discover")
async def discover_peers(request: Request, lat: Optional[float] = None, lon: Optional[float] = None):
    client_ip = get_client_ip(request)
    client_subnet = ".".join(client_ip.split(".")[:-1])
    now = time.time()
    
    # Cleanup old peers (not seen for 30s)
    to_remove = [p for p in active_peers if now - p.last_seen > 30]
    for p in to_remove: active_peers.remove(p)
    
    nearby_peers = []
    for p in active_peers:
        peer_subnet = ".".join(p.ip.split(".")[:-1])
        source = None
        
        # 1. Check Network (Subnet)
        if peer_subnet == client_subnet:
            source = "Network"
        # 2. Check Location (Geo)
        elif lat is not None and lon is not None and p.lat is not None and p.lon is not None:
            dist = ((p.lat - lat)**2 + (p.lon - lon)**2)**0.5
            if dist < 0.005: 
                source = "Location"
        
        if source:
            p_copy = p.copy()
            p_copy.source = source
            nearby_peers.append(p_copy)
    return nearby_peers

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
            
        # If it's a targeted Drop, only show to target or uploader
        if f.target_peer_id:
             # We can't strictly check target on discovery without user ID 
             # So we let UI filter by target ID or use IP subnet as heuristic
             pass

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
            
    # Sort by timestamp descending (newest first)
    nearby_files.sort(key=lambda x: x.timestamp, reverse=True)
            
    return nearby_files

@app.get("/api/download/{file_id}")
@limiter.limit("20/minute")
async def download_file(request: Request, file_id: str, lat: Optional[float] = None, lon: Optional[float] = None):
    # Find the bundle containing this file
    bundle = None
    file_meta = None
    for b in files_metadata:
        for f in b.files:
            if f.id == file_id:
                bundle = b
                file_meta = f
                break
        if bundle: break

    if not bundle or bundle.expires_at < time.time():
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    # Strict proximity check for non-public bundles
    if not bundle.is_public:
        client_ip = get_client_ip(request)
        client_subnet = ".".join(client_ip.split(".")[:-1])
        uploader_subnet = ".".join(bundle.uploader_ip.split(".")[:-1])
        
        is_auth = False
        if client_subnet == uploader_subnet:
            is_auth = True
        elif lat is not None and lon is not None and bundle.lat is not None and bundle.lon is not None:
             dist = ((bundle.lat - lat)**2 + (bundle.lon - lon)**2)**0.5
             if dist < 0.005:
                 is_auth = True
        
        if not is_auth:
            raise HTTPException(status_code=403, detail="Security Error: Proximity mismatch")
    
    file_path = os.path.join(UPLOAD_DIR, file_id)
    return FileResponse(file_path, filename=file_meta.filename, media_type=file_meta.content_type)

@app.get("/api/p/{access_token}")
async def public_view(access_token: str):
    # This now returns a list of files in the bundle for the UI to display
    bundle = next((b for b in files_metadata if b.access_token == access_token), None)
    if not bundle or bundle.expires_at < time.time():
        raise HTTPException(status_code=404, detail="Invalid or expired link")
    return bundle

async def cleanup_loop():
    while True:
        now = time.time()
        to_remove = []
        for b in files_metadata:
            if b.expires_at < now:
                to_remove.append(b)
        
        for b in to_remove:
            files_metadata.remove(b)
            for f in b.files:
                file_path = os.path.join(UPLOAD_DIR, f.id)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        print(f"Cleanup: Deleted expired file {f.filename}")
                    except: pass
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_loop())

@app.get("/drop")
async def redirect_drop():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/")

# Serve static files (Frontend)
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
