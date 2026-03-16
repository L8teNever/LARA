import os
import uuid
import time
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="LARA Drop")

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
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    lat: Optional[float] = Form(None),
    lon: Optional[float] = Form(None),
    is_public: bool = Form(False),
    expires_in: int = Form(1) # Default 1 hour
):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id)
    
    access_token = None
    if is_public:
        access_token = secrets.token_urlsafe(48)
    
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)
    
    now = time.time()
    metadata = shared_file(
        id=file_id,
        filename=file.filename,
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
async def download_file(file_id: str):
    file_meta = next((f for f in files_metadata if f.id == file_id), None)
    if not file_meta or file_meta.expires_at < time.time():
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    file_path = os.path.join(UPLOAD_DIR, file_id)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File content missing")
        
    return FileResponse(file_path, filename=file_meta.filename, media_type=file_meta.content_type)

@app.get("/api/p/{access_token}")
async def public_download(access_token: str):
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
