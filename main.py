"""Device Monitor server (FastAPI).

Consented company-device monitoring backend: device registration, pulse
(carries revoke/kill), daily log upload, and an admin console with root +
per-site admin scoping. Matches server-api.md. SQLite by default.

Admin auth: admin logs in -> gets a token (here: the admin id). In production
use real JWT/refresh; this is a working demo core.
"""
import hashlib
import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Body, Header
from pydantic import BaseModel
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATABASE_URL", "sqlite:///" + str(BASE_DIR / "monitor.db")).split("://")[-1])
LOG_ROOT = BASE_DIR / "logs"
LOG_ROOT.mkdir(exist_ok=True)

app = FastAPI(title="Device Monitor", version="1.0.0")


def db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    from passlib.context import CryptContext
    bc = CryptContext(schemes=["bcrypt"])
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'site_admin',
            site_id INTEGER REFERENCES sites(id)
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL UNIQUE,
            app_version TEXT, os_version TEXT, package TEXT,
            site_id INTEGER REFERENCES sites(id),
            last_seen_at TEXT, status TEXT DEFAULT 'active',
            revoked_at TEXT, enrolled_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS log_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER REFERENCES devices(id),
            log_date TEXT, stored_path TEXT, checksum TEXT,
            size INTEGER DEFAULT 0, fetched_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT, action TEXT, target TEXT, ts TEXT
        );
        """)
        n = conn.execute("SELECT COUNT(*) c FROM admins WHERE role='root'").fetchone()["c"]
        if n == 0:
            pw = os.environ.get("ROOT_PASSWORD", "change-me-root")
            conn.execute("INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)",
                         ("root", bc.hash(pw), "root"))


@app.on_event("startup")
def _startup():
    init_db()


# ---------- Auth ----------
def get_admin(authorization: Optional[str] = Header(None)):
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token:
        raise HTTPException(401, "Missing token")
    with db() as conn:
        row = conn.execute("SELECT * FROM admins WHERE id=?", (token,)).fetchone()
    if not row:
        raise HTTPException(401, "Bad token")
    return row


# ---------- Device endpoints ----------
class RegisterBody(BaseModel):
    device_id: str
    app_version: Optional[str] = None
    os_version: Optional[str] = None
    package: Optional[str] = None
    site_id: Optional[int] = None


@app.post("/device/register")
def register(body: RegisterBody):
    with db() as conn:
        conn.execute("""
            INSERT INTO devices(device_id, app_version, os_version, package, site_id, last_seen_at, status)
            VALUES(?,?,?,?,?,?, 'active')
            ON CONFLICT(device_id) DO UPDATE SET last_seen_at=excluded.last_seen_at
        """, (body.device_id, body.app_version, body.os_version, body.package, body.site_id,
              datetime.utcnow().isoformat()))
    return {
        "enrolled": True,
        "config": {
            "uploadIntervalS": 60, "requireWifi": True,
            "deleteAfterUpload": True, "serverTime": datetime.utcnow().isoformat(),
        },
    }


class PulseBody(BaseModel):
    device_id: str
    app_version: Optional[str] = None


@app.post("/device/pulse")
def pulse(body: PulseBody):
    now = datetime.utcnow().isoformat()
    with db() as conn:
        row = conn.execute("SELECT status FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        conn.execute("UPDATE devices SET last_seen_at=? WHERE device_id=?", (now, body.device_id))
    if not row:
        raise HTTPException(404, "device not enrolled")
    return {"status": row["status"], "action": "none" if row["status"] == "active" else "revoked"}


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@app.post("/device/logs/{log_date}")
async def upload_log(log_date: str, log: UploadFile = File(...), device_id: str = Form(...)):
    content = await log.read()
    cs = _sha(content.decode("utf-8", "replace"))
    with db() as conn:
        dev = conn.execute("SELECT id FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if not dev:
            raise HTTPException(404, "enroll the device first")
        path = LOG_ROOT / f"{device_id}.{log_date}.log"
        path.write_bytes(content)
        conn.execute("INSERT INTO log_files(device_id,log_date,stored_path,checksum,size) VALUES(?,?,?,?,?)",
                     (dev["id"], log_date, str(path), cs, len(content)))
    return {"receivedSha": cs, "size": len(content)}


# ---------- Admin endpoints ----------
@app.get("/admin/health")
def health():
    return {"ok": True}


@app.post("/admin/login")
def admin_login(body: dict = Body(...)):
    with db() as conn:
        row = conn.execute("SELECT * FROM admins WHERE username=?", (body.get("username"),)).fetchone()
    if not row:
        raise HTTPException(401, "bad credentials")
    from passlib.context import CryptContext
    bc = CryptContext(schemes=["bcrypt"])
    if not bc.verify(body.get("password", ""), row["password_hash"]):
        raise HTTPException(401, "bad credentials")
    return {"token": str(row["id"]), "role": row["role"], "site_id": row["site_id"]}


@app.get("/admin/devices")
def list_devices(admin=Depends(get_admin)):
    with db() as conn:
        if admin["role"] == "root":
            rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM devices WHERE site_id=? ORDER BY id", (admin["site_id"],)).fetchall()
    return {"devices": [dict(r) for r in rows]}


@app.get("/admin/devices/{device_id}/logs")
def device_logs(device_id: str, admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] == "root":
            rows = conn.execute(
                "SELECT d.device_id,l.log_date,l.size,l.checksum FROM log_files l "
                "JOIN devices d ON d.id=l.device_id WHERE d.device_id=?", (device_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT d.device_id,l.log_date,l.size,l.checksum FROM log_files l "
                "JOIN devices d ON d.id=l.device_id WHERE d.device_id=? AND d.site_id=?",
                (device_id, admin["site_id"])).fetchall()
    return {"logs": [dict(r) for r in rows]}


@app.post("/admin/devices/{device_id}/revoke")
def revoke_device(device_id: str, admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] != "root":
            s = conn.execute("SELECT site_id FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if not s or s["site_id"] != admin["site_id"]:
                raise HTTPException(403, "not your site")
        conn.execute("UPDATE devices SET status='revoked', revoked_at=? WHERE device_id=?",
                     (datetime.utcnow().isoformat(), device_id))
        conn.execute("INSERT INTO audit(actor,action,target,ts) VALUES(?,?,?,?)",
                     (admin["username"], "revoke", device_id, datetime.utcnow().isoformat()))
    return {"ok": True, "status": "revoked"}


@app.post("/admin/devices/{device_id}/restore")
def restore_device(device_id: str, admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        conn.execute("UPDATE devices SET status='active', revoked_at=NULL WHERE device_id=?", (device_id,))
    return {"ok": True, "status": "active"}


@app.get("/admin/audit")
def audit(admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    return {"audit": [dict(r) for r in rows]}


@app.post("/admin/setup/admin")
def create_admin(body: dict = Body(...), admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    from passlib.context import CryptContext
    bc = CryptContext(schemes=["bcrypt"])
    with db() as conn:
        conn.execute("INSERT INTO admins(username,password_hash,role,site_id) VALUES(?,?,?,?)",
                     (body.get("username"), bc.hash(body.get("password")), body.get("role", "site_admin"), body.get("site_id")))
    return {"ok": True}