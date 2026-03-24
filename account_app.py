"""
LARA Account App — runs on separate port (8001), behind Cloudflare Zero Trust.
Provides: device management, contact system, persistent connections.
Shares SQLite DB with main app so saved contacts appear in discovery.
"""
import os
import time
import json as json_lib
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import database as db

MAIN_SITE = "https://drop.l8tenever.com"

app = FastAPI(title="LARA Account")

# --- Cloudflare Zero Trust JWT Auth ---

def get_user_email(request: Request) -> str:
    """Extract user email from Cloudflare Zero Trust headers.
    CF Access sets Cf-Access-Authenticated-User-Email header after auth."""
    email = request.headers.get("Cf-Access-Authenticated-User-Email")
    if not email:
        raise HTTPException(status_code=401, detail="Nicht angemeldet.")
    return email.lower().strip()

def is_authenticated(request: Request) -> bool:
    """Check if request comes through Cloudflare Zero Trust."""
    return request.headers.get("Cf-Access-Authenticated-User-Email") is not None

# --- Security Headers ---

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
            "connect-src 'self' *; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Allow CORS from main app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://drop.l8tenever.com", "https://account.drop.l8tenever.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Init DB on startup ---

@app.on_event("startup")
async def startup():
    db.init_db()
    import asyncio
    asyncio.create_task(cleanup_loop())

async def cleanup_loop():
    """Periodically clean up stale devices (not seen for 7 days)."""
    import asyncio
    while True:
        try:
            removed = db.cleanup_stale_devices(max_age_days=7)
            if removed > 0:
                print(f"Account cleanup: removed {removed} stale device(s)")
        except Exception as e:
            print(f"Cleanup error: {e}")
        await asyncio.sleep(3600)  # Every hour

# --- Account Info ---

@app.get("/api/account/me")
async def get_me(request: Request):
    email = get_user_email(request)
    devices = db.get_devices(email)
    contacts = db.get_contacts(email)
    pending = db.get_pending_requests(email)
    return {
        "email": email,
        "devices": devices,
        "contacts": contacts,
        "pending_requests": pending
    }

# --- Device Management ---

@app.post("/api/account/devices/register")
async def register_device(request: Request):
    email = get_user_email(request)
    body = await request.json()
    peer_id = body.get("peer_id")
    name = body.get("name")
    if not peer_id or not name:
        raise HTTPException(status_code=400, detail="peer_id und name erforderlich")
    result = db.register_device(email, peer_id, name)
    return result

@app.post("/api/account/devices/heartbeat")
async def device_heartbeat(request: Request):
    email = get_user_email(request)
    body = await request.json()
    peer_id = body.get("peer_id")
    if not peer_id:
        raise HTTPException(status_code=400, detail="peer_id erforderlich")
    # Verify device belongs to this email
    dev_email = db.get_device_email(peer_id)
    if dev_email != email:
        raise HTTPException(status_code=403, detail="Gerät gehört nicht zu deinem Account")
    db.update_device_heartbeat(peer_id)
    return {"status": "ok"}

@app.post("/api/account/devices/rename")
async def rename_device(request: Request):
    email = get_user_email(request)
    body = await request.json()
    peer_id = body.get("peer_id")
    new_name = body.get("name")
    if not peer_id or not new_name:
        raise HTTPException(status_code=400, detail="peer_id und name erforderlich")
    if db.rename_device(peer_id, email, new_name):
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Gerät nicht gefunden")

@app.delete("/api/account/devices/{peer_id}")
async def delete_device(request: Request, peer_id: str):
    email = get_user_email(request)
    if db.remove_device(peer_id, email):
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Gerät nicht gefunden")

# --- Contact System ---

@app.post("/api/account/contacts/request")
async def request_contact(request: Request):
    """Send a contact request to save another device."""
    email = get_user_email(request)
    body = await request.json()
    my_peer_id = body.get("my_peer_id")
    target_peer_id = body.get("target_peer_id")
    if not my_peer_id or not target_peer_id:
        raise HTTPException(status_code=400, detail="my_peer_id und target_peer_id erforderlich")

    # Verify my device belongs to me
    dev_email = db.get_device_email(my_peer_id)
    if dev_email != email:
        raise HTTPException(status_code=403, detail="Dein Gerät ist nicht registriert")

    # Get target device's email
    target_email = db.get_device_email(target_peer_id)
    if not target_email:
        raise HTTPException(status_code=404, detail="Das Zielgerät hat keinen Account. Beide brauchen einen Account für Kontakte.")

    result = db.send_contact_request(email, my_peer_id, target_email, target_peer_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.get("/api/account/contacts/pending")
async def get_pending(request: Request):
    email = get_user_email(request)
    return db.get_pending_requests(email)

@app.post("/api/account/contacts/{contact_id}/accept")
async def accept_contact(request: Request, contact_id: int):
    email = get_user_email(request)
    if db.accept_contact(contact_id, email):
        return {"status": "ok", "message": "Kontakt akzeptiert!"}
    raise HTTPException(status_code=404, detail="Anfrage nicht gefunden")

@app.delete("/api/account/contacts/{contact_id}")
async def delete_contact(request: Request, contact_id: int):
    email = get_user_email(request)
    if db.reject_contact(contact_id, email):
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Kontakt nicht gefunden")

# --- Serve Account UI ---

@app.get("/", response_class=HTMLResponse)
async def account_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url=MAIN_SITE)
    return FileResponse(os.path.join(os.path.dirname(__file__), "account.html"))
