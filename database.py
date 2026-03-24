"""
Shared SQLite database for LARA account features.
Used by both main app (to check saved contacts in discover) and account app (full CRUD).
"""
import sqlite3
import os
import time
import threading

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "lara_accounts.db")

_local = threading.local()

def get_db() -> sqlite3.Connection:
    """Get a thread-local database connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn

def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            peer_id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_devices_email ON devices(email);

        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_email TEXT NOT NULL,
            requester_peer_id TEXT NOT NULL,
            target_email TEXT NOT NULL,
            target_peer_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at REAL NOT NULL,
            UNIQUE(requester_peer_id, target_peer_id)
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_target ON contacts(target_email, status);
        CREATE INDEX IF NOT EXISTS idx_contacts_requester ON contacts(requester_email);
    """)
    conn.commit()

# --- Device operations ---

def register_device(email: str, peer_id: str, name: str) -> dict:
    """Register or update a device for an account."""
    conn = get_db()
    now = time.time()
    existing = conn.execute("SELECT * FROM devices WHERE peer_id = ?", (peer_id,)).fetchone()
    if existing:
        conn.execute("UPDATE devices SET email = ?, name = ?, last_seen = ? WHERE peer_id = ?",
                      (email, name, now, peer_id))
    else:
        conn.execute("INSERT INTO devices (peer_id, email, name, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                      (peer_id, email, name, now, now))
    conn.commit()
    return {"peer_id": peer_id, "email": email, "name": name}

def get_devices(email: str) -> list:
    """Get all devices for an account."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM devices WHERE email = ? ORDER BY last_seen DESC", (email,)).fetchall()
    return [dict(r) for r in rows]

def update_device_heartbeat(peer_id: str):
    """Update last_seen for a device."""
    conn = get_db()
    conn.execute("UPDATE devices SET last_seen = ? WHERE peer_id = ?", (time.time(), peer_id))
    conn.commit()

def rename_device(peer_id: str, email: str, new_name: str) -> bool:
    """Rename a device (only if owned by this email)."""
    conn = get_db()
    result = conn.execute("UPDATE devices SET name = ? WHERE peer_id = ? AND email = ?",
                           (new_name, peer_id, email))
    conn.commit()
    return result.rowcount > 0

def remove_device(peer_id: str, email: str) -> bool:
    """Remove a device (only if owned by this email). Also removes related contacts."""
    conn = get_db()
    result = conn.execute("DELETE FROM devices WHERE peer_id = ? AND email = ?", (peer_id, email))
    if result.rowcount > 0:
        conn.execute("DELETE FROM contacts WHERE requester_peer_id = ? OR target_peer_id = ?", (peer_id, peer_id))
        conn.commit()
        return True
    conn.commit()
    return False

def get_device_email(peer_id: str) -> str | None:
    """Get the email associated with a peer_id."""
    conn = get_db()
    row = conn.execute("SELECT email FROM devices WHERE peer_id = ?", (peer_id,)).fetchone()
    return row["email"] if row else None

# --- Contact operations ---

def send_contact_request(requester_email: str, requester_peer_id: str,
                          target_email: str, target_peer_id: str) -> dict:
    """Send a contact request. Both must have registered devices."""
    conn = get_db()
    now = time.time()

    # Check target device exists and belongs to target email
    target_dev = conn.execute("SELECT * FROM devices WHERE peer_id = ? AND email = ?",
                               (target_peer_id, target_email)).fetchone()
    if not target_dev:
        return {"error": "Zielgerät nicht gefunden oder gehört nicht zu diesem Account."}

    # Check not already exists
    existing = conn.execute(
        "SELECT * FROM contacts WHERE requester_peer_id = ? AND target_peer_id = ?",
        (requester_peer_id, target_peer_id)
    ).fetchone()
    if existing:
        return {"error": "Anfrage existiert bereits.", "status": existing["status"]}

    # Check reverse direction too
    reverse = conn.execute(
        "SELECT * FROM contacts WHERE requester_peer_id = ? AND target_peer_id = ?",
        (target_peer_id, requester_peer_id)
    ).fetchone()
    if reverse:
        if reverse["status"] == "accepted":
            return {"error": "Ihr seid bereits verbunden."}
        return {"error": "Es gibt bereits eine Anfrage von diesem Gerät an dich."}

    conn.execute(
        "INSERT INTO contacts (requester_email, requester_peer_id, target_email, target_peer_id, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
        (requester_email, requester_peer_id, target_email, target_peer_id, now)
    )
    conn.commit()
    return {"status": "pending", "message": "Kontaktanfrage gesendet."}

def get_pending_requests(email: str) -> list:
    """Get pending contact requests for an account (incoming)."""
    conn = get_db()
    rows = conn.execute("""
        SELECT c.*, d.name as requester_name
        FROM contacts c
        JOIN devices d ON d.peer_id = c.requester_peer_id
        WHERE c.target_email = ? AND c.status = 'pending'
        ORDER BY c.created_at DESC
    """, (email,)).fetchall()
    return [dict(r) for r in rows]

def accept_contact(contact_id: int, email: str) -> bool:
    """Accept a contact request (only if you're the target)."""
    conn = get_db()
    result = conn.execute(
        "UPDATE contacts SET status = 'accepted' WHERE id = ? AND target_email = ? AND status = 'pending'",
        (contact_id, email)
    )
    conn.commit()
    return result.rowcount > 0

def reject_contact(contact_id: int, email: str) -> bool:
    """Reject/delete a contact request."""
    conn = get_db()
    result = conn.execute(
        "DELETE FROM contacts WHERE id = ? AND (target_email = ? OR requester_email = ?)",
        (contact_id, email, email)
    )
    conn.commit()
    return result.rowcount > 0

def get_contacts(email: str) -> list:
    """Get all accepted contacts for an account (both directions)."""
    conn = get_db()
    rows = conn.execute("""
        SELECT c.id, c.requester_peer_id, c.target_peer_id, c.requester_email, c.target_email,
               d1.name as requester_name, d2.name as target_name,
               d1.last_seen as requester_last_seen, d2.last_seen as target_last_seen
        FROM contacts c
        JOIN devices d1 ON d1.peer_id = c.requester_peer_id
        JOIN devices d2 ON d2.peer_id = c.target_peer_id
        WHERE (c.requester_email = ? OR c.target_email = ?) AND c.status = 'accepted'
        ORDER BY c.created_at DESC
    """, (email, email)).fetchall()
    return [dict(r) for r in rows]

def get_same_account_peer_ids(peer_id: str) -> set:
    """Get all other peer_ids that belong to the same email account.
    These are the user's own devices — always linked automatically."""
    conn = get_db()
    row = conn.execute("SELECT email FROM devices WHERE peer_id = ?", (peer_id,)).fetchone()
    if not row:
        return set()
    rows = conn.execute("SELECT peer_id FROM devices WHERE email = ? AND peer_id != ?",
                         (row["email"], peer_id)).fetchall()
    return {r["peer_id"] for r in rows}

def get_saved_peer_ids(peer_id: str) -> set:
    """Get all peer_ids that should always be visible: own devices + accepted contacts.
    Used by main app's discover to always show saved contacts."""
    conn = get_db()
    result = set()

    # 1. Own devices (same email = automatically linked)
    result.update(get_same_account_peer_ids(peer_id))

    # 2. Accepted contacts
    rows = conn.execute("""
        SELECT requester_peer_id, target_peer_id FROM contacts
        WHERE (requester_peer_id = ? OR target_peer_id = ?) AND status = 'accepted'
    """, (peer_id, peer_id)).fetchall()
    for r in rows:
        if r["requester_peer_id"] == peer_id:
            result.add(r["target_peer_id"])
        else:
            result.add(r["requester_peer_id"])
    return result

def cleanup_stale_devices(max_age_days: int = 7):
    """Remove devices not seen for max_age_days and their contacts."""
    conn = get_db()
    cutoff = time.time() - (max_age_days * 86400)
    stale = conn.execute("SELECT peer_id FROM devices WHERE last_seen < ?", (cutoff,)).fetchall()
    for row in stale:
        pid = row["peer_id"]
        conn.execute("DELETE FROM contacts WHERE requester_peer_id = ? OR target_peer_id = ?", (pid, pid))
        conn.execute("DELETE FROM devices WHERE peer_id = ?", (pid,))
    conn.commit()
    return len(stale)
