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
            "connect-src 'self' https://account-drop.l8tenever.com; "
            "manifest-src 'self'; "
            "worker-src 'self'; "
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
import urllib.request
import json as json_lib

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
    uploader_name: Optional[str] = None
    target_peer_id: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    coord_source: Optional[str] = None  # "gps" or "ip"
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
    coord_source: Optional[str] = None  # "gps" or "ip"
    last_seen: float
    source: Optional[str] = None  # Discovery source: 'Network' or 'Location'

files_metadata: List[shared_bundle] = []
active_peers: List[Peer] = []

# Ultrasonic proximity pings: peer_id -> timestamp of last ping sent
ultrasonic_pings: dict = {}  # { peer_id: float(timestamp) }
# Confirmed ultrasonic pairs: frozenset({id_a, id_b}) -> expiry timestamp
ultrasonic_pairs: dict = {}  # { frozenset: float(expiry) }

# Manual pairing codes: code -> { "peer_id": str, "expires": float }
manual_pairing_codes: dict = {}
# Manual pairs: frozenset({id_a, id_b}) -> expiry timestamp
manual_pairs: dict = {}

import random
import database as db

# Init shared database on import
db.init_db()

def is_nearby_geo(lat1, lon1, src1, lat2, lon2, src2) -> bool:
    """Check if two coordinates are nearby, with dynamic radius based on source accuracy.
    GPS+GPS: 500m (0.005°), GPS+IP: 10km (0.1°), IP+IP: 20km (0.2°)"""
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return False
    dist = ((lat1 - lat2)**2 + (lon1 - lon2)**2)**0.5
    if src1 == "gps" and src2 == "gps":
        return dist < 0.005   # ~500m — both precise
    elif src1 == "gps" or src2 == "gps":
        return dist < 0.1     # ~10km — one precise, one city-level
    else:
        return dist < 0.2     # ~20km — both city-level (IP)

def get_client_ip(request: Request):
    # Try to get the real IP if behind a proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

# Cache IP geolocation results to avoid hammering the API
_ip_geo_cache: dict = {}  # ip -> {"lat": float, "lon": float, "ts": float}

def ip_to_coords(ip: str) -> tuple:
    """Returns (lat, lon) for an IP via ip-api.com, with 10min cache. Returns (None, None) on failure."""
    now = time.time()
    cached = _ip_geo_cache.get(ip)
    if cached and now - cached["ts"] < 600:
        return cached["lat"], cached["lon"]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,lat,lon",
            headers={"User-Agent": "LARA/1.0"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json_lib.loads(resp.read())
            if data.get("status") == "success":
                _ip_geo_cache[ip] = {"lat": data["lat"], "lon": data["lon"], "ts": now}
                return data["lat"], data["lon"]
    except Exception:
        pass
    _ip_geo_cache[ip] = {"lat": None, "lon": None, "ts": now}
    return None, None

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
    
    # Track coord source and apply IP fallback
    uploader_ip = get_client_ip(request)
    upload_coord_source = "gps" if (lat is not None and lon is not None) else None
    if lat is None or lon is None:
        lat, lon = ip_to_coords(uploader_ip)
        if lat is not None:
            upload_coord_source = "ip"

    now = time.time()
    metadata = shared_bundle(
        id=bundle_id,
        files=bundle_files,
        uploader_ip=uploader_ip,
        uploader_name=uploader_name,
        target_peer_id=target_peer_id,
        lat=lat,
        lon=lon,
        coord_source=upload_coord_source,
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

    # IP geolocation fallback if browser didn't provide coords
    if peer.lat is None or peer.lon is None:
        ip_lat, ip_lon = ip_to_coords(peer.ip)
        if ip_lat is not None:
            peer.lat = ip_lat
            peer.lon = ip_lon
            peer.coord_source = "ip"

    active_peers.append(peer)

    # Update device heartbeat in account DB (if registered)
    try:
        db.update_device_heartbeat(peer.id)
    except Exception:
        pass

    return {"status": "ok"}

@app.get("/api/peers/all-ids")
async def all_peer_ids():
    """Return all currently registered peer IDs for ultrasonic cross-referencing"""
    now = time.time()
    return [p.id for p in active_peers if now - p.last_seen < 30]

@app.post("/api/ultrasonic/ping")
async def ultrasonic_ping(request: Request, data: dict):
    """Register that this peer is currently emitting an ultrasonic tone"""
    peer_id = data.get("peer_id")
    if not peer_id:
        raise HTTPException(status_code=400, detail="peer_id required")
    ultrasonic_pings[peer_id] = time.time()
    return {"status": "ok"}

@app.post("/api/ultrasonic/heard")
async def ultrasonic_heard(request: Request, data: dict):
    """Report that this peer heard another peer's ultrasonic tone"""
    listener_id = data.get("listener_id")
    heard_ids = data.get("heard_ids", [])
    if not listener_id:
        raise HTTPException(status_code=400, detail="listener_id required")

    now = time.time()
    confirmed = []
    for emitter_id in heard_ids:
        # Only confirm if the emitter actually pinged recently (within 15s)
        ping_time = ultrasonic_pings.get(emitter_id)
        if ping_time and now - ping_time < 15:
            pair_key = frozenset({listener_id, emitter_id})
            ultrasonic_pairs[pair_key] = now + 300  # 5 min expiry
            confirmed.append(emitter_id)

    # Cleanup expired pairs
    expired = [k for k, v in ultrasonic_pairs.items() if v < now]
    for k in expired:
        del ultrasonic_pairs[k]

    return {"status": "ok", "confirmed": confirmed}

@app.post("/api/pairing/generate")
async def pairing_generate(data: dict):
    """Generate a 6-digit pairing code for this peer. Valid for 2 minutes."""
    peer_id = data.get("peer_id")
    if not peer_id:
        raise HTTPException(status_code=400, detail="peer_id required")

    # Clean expired codes
    now = time.time()
    expired = [c for c, v in manual_pairing_codes.items() if v["expires"] < now]
    for c in expired:
        del manual_pairing_codes[c]

    # Remove any existing code for this peer
    old = [c for c, v in manual_pairing_codes.items() if v["peer_id"] == peer_id]
    for c in old:
        del manual_pairing_codes[c]

    # Generate unique 6-digit code
    for _ in range(100):
        code = f"{random.randint(0, 999999):06d}"
        if code not in manual_pairing_codes:
            break

    manual_pairing_codes[code] = {"peer_id": peer_id, "expires": now + 120}
    return {"code": code}


@app.post("/api/pairing/join")
async def pairing_join(data: dict):
    """Enter a pairing code to connect with another device for 5 minutes."""
    peer_id = data.get("peer_id")
    code = data.get("code", "").strip()
    if not peer_id or not code:
        raise HTTPException(status_code=400, detail="peer_id and code required")

    now = time.time()
    entry = manual_pairing_codes.get(code)
    if not entry or entry["expires"] < now:
        raise HTTPException(status_code=404, detail="Code ungültig oder abgelaufen")

    other_id = entry["peer_id"]
    if other_id == peer_id:
        raise HTTPException(status_code=400, detail="Du kannst dich nicht mit dir selbst verbinden")

    # Create pair for 5 minutes
    pair_key = frozenset({peer_id, other_id})
    manual_pairs[pair_key] = now + 300

    # Remove used code
    del manual_pairing_codes[code]

    # Get the other peer's name
    other_peer = next((p for p in active_peers if p.id == other_id), None)
    other_name = other_peer.name if other_peer else "Unbekannt"

    return {"status": "ok", "paired_with": other_id, "paired_name": other_name}


@app.get("/api/peers/discover")
async def discover_peers(request: Request, lat: Optional[float] = None, lon: Optional[float] = None, coord_source: Optional[str] = None, peer_id: Optional[str] = None):
    client_ip = get_client_ip(request)
    client_subnet = ".".join(client_ip.split(".")[:-1])
    now = time.time()

    # Determine client coord source
    client_coord_source = coord_source or "gps"

    # IP geolocation fallback for the requesting client
    if lat is None or lon is None:
        lat, lon = ip_to_coords(client_ip)
        client_coord_source = "ip"

    # Cleanup expired ultrasonic pairs
    expired_pairs = [k for k, v in ultrasonic_pairs.items() if v < now]
    for k in expired_pairs:
        del ultrasonic_pairs[k]

    # Cleanup expired manual pairs
    expired_manual = [k for k, v in manual_pairs.items() if v < now]
    for k in expired_manual:
        del manual_pairs[k]

    # Cleanup old peers (not seen for 30s)
    to_remove = [p for p in active_peers if now - p.last_seen > 30]
    for p in to_remove: active_peers.remove(p)

    # Cleanup pairs referencing dead peers (cache cleared = new peer_id, old one never heartbeats again)
    alive_ids = {p.id for p in active_peers}
    dead_ultrasonic = [k for k in ultrasonic_pairs if not k.issubset(alive_ids)]
    for k in dead_ultrasonic:
        del ultrasonic_pairs[k]
    dead_manual = [k for k in manual_pairs if not k.issubset(alive_ids)]
    for k in dead_manual:
        del manual_pairs[k]

    # Load saved contacts for this peer from account system
    saved_contact_ids = set()
    if peer_id:
        try:
            saved_contact_ids = db.get_saved_peer_ids(peer_id)
        except Exception:
            pass

    nearby_peers = []
    for p in active_peers:
        peer_subnet = ".".join(p.ip.split(".")[:-1])
        sources = []

        # 1. Check Network (same subnet = same WLAN)
        if peer_subnet == client_subnet:
            sources.append("Network")

        # 2. Check Location (GPS/IP) — always check, with dynamic radius
        if is_nearby_geo(lat, lon, client_coord_source, p.lat, p.lon, p.coord_source or "gps"):
            sources.append("Location")

        # 3. Ultrasonic proximity — confirmed pair within 5min window
        if peer_id:
            pair_key = frozenset({peer_id, p.id})
            if pair_key in ultrasonic_pairs and ultrasonic_pairs[pair_key] > now:
                sources.append("Ultrasonic")

        # 4. Manual pairing — confirmed pair within 5min window
        if peer_id:
            pair_key = frozenset({peer_id, p.id})
            if pair_key in manual_pairs and manual_pairs[pair_key] > now:
                sources.append("Manual")

        # 5. Saved contacts (persistent, from account system)
        if peer_id and p.id in saved_contact_ids:
            sources.append("Saved")

        if sources:
            p_copy = p.copy()
            # Priority: Saved > Manual > Ultrasonic > Network > Location
            if "Saved" in sources:
                p_copy.source = "Saved"
            elif "Manual" in sources:
                p_copy.source = "Manual"
            elif "Ultrasonic" in sources:
                p_copy.source = "Ultrasonic"
            elif "Network" in sources:
                p_copy.source = "Network"
            else:
                p_copy.source = "Location"
            nearby_peers.append(p_copy)
    return nearby_peers

@app.get("/api/discover")
async def discover_files(
    request: Request,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    peer_id: Optional[str] = None,
    coord_source: Optional[str] = None
):
    client_ip = get_client_ip(request)
    client_subnet = ".".join(client_ip.split(".")[:-1])

    client_coord_source = coord_source or "gps"

    # IP geolocation fallback
    if lat is None or lon is None:
        lat, lon = ip_to_coords(client_ip)
        client_coord_source = "ip"

    now = time.time()
    nearby_files = []

    # Always include targeted drops for this peer (regardless of network/location)
    if peer_id:
        for f in files_metadata:
            if f.expires_at >= now and f.target_peer_id == peer_id:
                nearby_files.append(f)

    for f in files_metadata:
        if f.expires_at < now:
            continue

        is_nearby = False

        # 1. Matching Subnet (same WLAN)
        f_subnet = ".".join(f.uploader_ip.split(".")[:-1])
        if f_subnet == client_subnet:
            is_nearby = True

        # 2. Geolocation (dynamic radius based on coord source)
        if not is_nearby and is_nearby_geo(lat, lon, client_coord_source, f.lat, f.lon, f.coord_source or "gps"):
            is_nearby = True

        if is_nearby and f not in nearby_files:
            nearby_files.append(f)

    # Sort by timestamp descending (newest first)
    nearby_files.sort(key=lambda x: x.timestamp, reverse=True)
            
    return nearby_files

@app.get("/api/ip-location")
async def ip_location(request: Request):
    """Fallback geolocation via IP when browser geolocation is unavailable"""
    client_ip = get_client_ip(request)
    try:
        # Use ip-api.com (free, no key needed, 45 req/min)
        req = urllib.request.Request(
            f"http://ip-api.com/json/{client_ip}?fields=status,lat,lon",
            headers={"User-Agent": "LARA/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json_lib.loads(resp.read())
            if data.get("status") == "success":
                return {"lat": data["lat"], "lon": data["lon"], "source": "ip"}
    except Exception:
        pass
    return {"lat": None, "lon": None, "source": "none"}

@app.get("/api/download/{file_id}")
@limiter.limit("20/minute")
async def download_file(request: Request, file_id: str, lat: Optional[float] = None, lon: Optional[float] = None, peer_id: Optional[str] = None):
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

    # Targeted drops: if you are the intended recipient, always allow
    if bundle.target_peer_id and peer_id and bundle.target_peer_id == peer_id:
        pass  # Authorized as target recipient
    elif not bundle.is_public:
        # Proximity check for non-public, non-targeted bundles
        client_ip = get_client_ip(request)
        client_subnet = ".".join(client_ip.split(".")[:-1])
        uploader_subnet = ".".join(bundle.uploader_ip.split(".")[:-1])

        is_auth = False
        # 1. Same subnet
        if client_subnet == uploader_subnet:
            is_auth = True
        # 2. Geolocation proximity
        elif lat is not None and lon is not None and bundle.lat is not None and bundle.lon is not None:
             dist = ((bundle.lat - lat)**2 + (bundle.lon - lon)**2)**0.5
             if dist < 0.005:
                 is_auth = True
        # 3. Targeted drop for this peer (fallback without peer_id param)
        elif bundle.target_peer_id:
            is_auth = True  # Targeted drops are shown only to target in UI anyway

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

        # Cleanup stale peers, pairs, and pairing codes
        stale_peers = [p for p in active_peers if now - p.last_seen > 60]
        for p in stale_peers:
            active_peers.remove(p)
        alive_ids = {p.id for p in active_peers}
        for d in [ultrasonic_pairs, manual_pairs]:
            dead = [k for k in d if not k.issubset(alive_ids)]
            for k in dead:
                del d[k]
        expired_codes = [c for c, v in manual_pairing_codes.items() if v["expires"] < now]
        for c in expired_codes:
            del manual_pairing_codes[c]

        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_loop())

@app.get("/drop")
async def redirect_drop():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/")

@app.post("/share-target")
async def share_target(request: Request):
    """Fallback for Web Share Target when SW hasn't intercepted.
    Redirect to main page — files will be lost but app opens."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/?shared=fallback", status_code=303)

# PWA: manifest and service worker
from fastapi.responses import JSONResponse

@app.get("/manifest.json")
async def get_manifest():
    with open("manifest.json", "r", encoding="utf-8") as f:
        import json as _json
        return JSONResponse(content=_json.load(f), media_type="application/manifest+json")

@app.get("/sw.js")
async def get_sw():
    return FileResponse("sw.js", media_type="application/javascript",
                        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})

# Serve static files (Frontend)
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
