"""Device Monitor server (FastAPI).

Consented company-device monitoring backend: device registration, pulse
(carries revoke/kill), daily log upload, and an admin console with root +
per-site admin scoping. Matches server-api.md. SQLite by default.

Admin auth: admin logs in -> gets a token (here: the admin id). In production
use real JWT/refresh; this is a working demo core.
"""
import hashlib
import json
import math
import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Body, Header
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from typing import Optional
from zoneinfo import ZoneInfo


def now_local(dt, tzname):
    """Return dt (UTC) shifted into the configured timezone."""
    try:
        return dt.astimezone(ZoneInfo(tzname))
    except Exception:
        try:
            return dt.astimezone(ZoneInfo("Africa/Algiers"))
        except Exception:
            return dt


def haversine(lat1, lng1, lat2, lng2):
    """Great-circle distance in metres."""
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def audit(conn, actor, action, target=None, result=None, reason=None, device_id=None, detail=None):
    """Write a full accountability record (incl. result/reason for admin actions)."""
    conn.execute(
        "INSERT INTO audit(actor,action,target,ts,result,reason,device_id,detail) VALUES(?,?,?,?,?,?,?,?)",
        (actor, action, target, datetime.utcnow().isoformat(), result, reason, device_id, detail))

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
            revoked_at TEXT, enrolled_at TEXT DEFAULT (datetime('now')),
            lat REAL, lng REAL, location_at TEXT, speed REAL,
            model TEXT, manufacturer TEXT, android_id TEXT,
            build_number TEXT, sdk INTEGER, security_patch TEXT,
            battery_pct INTEGER, charging INTEGER DEFAULT 0,
            storage_total INTEGER, storage_free INTEGER,
            rooted INTEGER DEFAULT 0, unknown_sources INTEGER DEFAULT 0,
            unlocked_boot INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT, cmd TEXT, param TEXT,
            issued_by TEXT, created_at TEXT, acked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT, package TEXT, label TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS device_policy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL UNIQUE,
            policy JSON NOT NULL
        );
        CREATE TABLE IF NOT EXISTS geofences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT, name TEXT, lat REAL, lng REAL,
            radius_m REAL, active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS log_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER REFERENCES devices(id),
            log_date TEXT, stored_path TEXT, checksum TEXT,
            size INTEGER DEFAULT 0, fetched_at TEXT
        );
        CREATE TABLE IF NOT EXISTS location_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER REFERENCES devices(id),
            lat REAL, lng REAL, speed REAL,
            ts TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT, action TEXT, target TEXT, ts TEXT,
            result TEXT, reason TEXT, device_id TEXT, detail TEXT
        );
        """)
        n = conn.execute("SELECT COUNT(*) c FROM admins WHERE role='root'").fetchone()["c"]
        if n == 0:
            pw = os.environ.get("ROOT_PASSWORD", "change-me-root")
            conn.execute("INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)",
                         ("root", bc.hash(pw), "root"))
        # default work-hours settings (24h). The admin panel overrides these.
        defaults = [
            ("work_start", "07:00"), ("work_end", "19:00"),
            ("work_active", "1"),    # 1 = enforce work-hours window for location
            ("location_interval_s", "60"),
            ("timezone", "Africa/Algiers"),
        ]
        for k, v in defaults:
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        # best-effort migrations for pre-existing DBs
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
        for c, d in {"model":"TEXT","manufacturer":"TEXT","android_id":"TEXT","build_number":"TEXT",
                     "sdk":"INTEGER","security_patch":"TEXT","battery_pct":"INTEGER","charging":"INTEGER DEFAULT 0",
                     "storage_total":"INTEGER","storage_free":"INTEGER","rooted":"INTEGER DEFAULT 0",
                     "unknown_sources":"INTEGER DEFAULT 0","unlocked_boot":"INTEGER DEFAULT 0"}.items():
            if c not in cols:
                try: conn.execute(f"ALTER TABLE devices ADD COLUMN {c} {d}")
                except Exception: pass
        acols = [r["name"] for r in conn.execute("PRAGMA table_info(audit)").fetchall()]
        for c, d in {"result":"TEXT","reason":"TEXT","device_id":"TEXT","detail":"TEXT"}.items():
            if c not in acols:
                try: conn.execute(f"ALTER TABLE audit ADD COLUMN {c} {d}")
                except Exception: pass


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
    lat: Optional[float] = None
    lng: Optional[float] = None
    speed: Optional[float] = None
    battery_pct: Optional[int] = None
    charging: Optional[int] = None


class InventoryBody(BaseModel):
    device_id: str
    model: Optional[str] = None
    manufacturer: Optional[str] = None
    android_id: Optional[str] = None
    os_version: Optional[str] = None
    sdk: Optional[int] = None
    security_patch: Optional[str] = None
    build_number: Optional[str] = None
    battery_pct: Optional[int] = None
    charging: Optional[int] = None
    storage_total: Optional[int] = None
    storage_free: Optional[int] = None
    rooted: Optional[int] = 0
    unknown_sources: Optional[int] = 0
    unlocked_boot: Optional[int] = 0
    apps: Optional[list] = None


@app.post("/device/pulse")
def pulse(body: PulseBody):
    now = datetime.utcnow().isoformat()
    with db() as conn:
        row = conn.execute("SELECT status FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        # Determine work-hours state from admin settings
        srow = conn.execute("SELECT key,value FROM settings WHERE key IN ('work_start','work_end','work_active','timezone')").fetchall()
        st = {r["key"]: r["value"] for r in srow}
        work_enforce = st.get("work_active", "1") == "1"
        locally = now_local(datetime.utcnow(), st.get("timezone", "Africa/Algiers"))
        if work_enforce:
            start_s, end_s = st.get("work_start", "07:00"), st.get("work_end", "19:00")
            in_hours = int(locally.strftime("%H%M")) >= int(start_s.replace(":", "")) and \
                       int(locally.strftime("%H%M")) <= int(end_s.replace(":", ""))
        else:
            in_hours = True
        if row and body.lat is not None and body.lng is not None and in_hours:
            conn.execute("UPDATE devices SET last_seen_at=?, lat=?, lng=?, speed=?, location_at=?, battery_pct=COALESCE(?,battery_pct), charging=COALESCE(?,charging) WHERE device_id=?",
                         (now, body.lat, body.lng, body.speed, now, body.battery_pct, body.charging, body.device_id))
            conn.execute("INSERT INTO location_history(device_id,lat,lng,speed,ts) "
                         "SELECT id,?,?,?,? FROM devices WHERE device_id=?",
                         (body.lat, body.lng, body.speed, now, body.device_id))
        elif row:
            conn.execute("UPDATE devices SET last_seen_at=?, battery_pct=COALESCE(?,battery_pct), charging=COALESCE(?,charging) WHERE device_id=?",
                         (now, body.battery_pct, body.charging, body.device_id))
        # geofence breach check (only when in-work-hours and have a location)
        if row and row["status"] == "active" and body.lat is not None and body.lng is not None:
            gf = conn.execute("SELECT name,lat,lng,radius_m FROM geofences WHERE device_id=? AND active=1", (body.device_id,)).fetchall()
            for g in gf:
                breach = haversine(body.lat, body.lng, g["lat"], g["lng"]) > (g["radius_m"] or 0)
                if breach:
                    audit(conn, "system", "geofence_breach",
                          target=f"{body.device_id}:{g['name']}", device_id=body.device_id,
                          detail=f"location {round(body.lat,4)},{round(body.lng,4)} outside {g['radius_m']}m of {g['name']}")
    if not row:
        raise HTTPException(404, "device not enrolled")
    # read any pending commands
    with db() as conn:
        pending = conn.execute("SELECT id,cmd,param FROM commands WHERE device_id=? AND acked_at IS NULL ORDER BY id LIMIT 5", (body.device_id,)).fetchall()
        cmds = [{"id": c["id"], "cmd": c["cmd"], "param": c["param"]} for c in pending]
        policy = conn.execute("SELECT policy FROM device_policy WHERE device_id=?", (body.device_id,)).fetchone()
    return {"status": row["status"], "action": "none" if row["status"] == "active" else "revoked",
            "in_work_hours": in_hours, "commands": cmds, "policy": json.loads(policy["policy"]) if policy else None}


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


@app.post("/device/inventory")
def report_inventory(body: InventoryBody):
    with db() as conn:
        dev = conn.execute("SELECT id FROM devices WHERE device_id=?", (body.device_id,)).fetchone()
        if not dev:
            raise HTTPException(404, "enroll first")
        conn.execute("""
            UPDATE devices SET model=?, manufacturer=?, android_id=?, os_version=?,
              sdk=?, security_patch=?, build_number=?, battery_pct=COALESCE(?,battery_pct),
              charging=COALESCE(?,charging), storage_total=?, storage_free=?,
              rooted=?, unknown_sources=?, unlocked_boot=?
            WHERE device_id=?""",
            (body.model, body.manufacturer, body.android_id, body.os_version,
             body.sdk, body.security_patch, body.build_number, body.battery_pct,
             body.charging, body.storage_total, body.storage_free,
             body.rooted, body.unknown_sources, body.unlocked_boot, body.device_id))
        if body.apps:
            conn.execute("DELETE FROM apps WHERE device_id=?", (body.device_id,))
            for a in body.apps[:500]:
                conn.execute("INSERT OR REPLACE INTO apps(device_id,package,label,updated_at) VALUES(?,?,?,?)",
                             (body.device_id, a.get("package"), a.get("label"), datetime.utcnow().isoformat()))
    return {"ok": True}


@app.post("/device/commands/ack")
def ack_command(body: dict = Body(...)):
    cid = body.get("id"); result = body.get("result")
    with db() as conn:
        conn.execute("UPDATE commands SET acked_at=? WHERE id=?",
                     (datetime.utcnow().isoformat(), cid))
    return {"ok": True}


# ---------- Admin endpoints ----------
@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
def admin_ui():
    idx = BASE_DIR / "static" / "index.html"
    if idx.exists():
        return HTMLResponse(idx.read_text(encoding="utf-8"))
    return HTMLResponse("<h3>Admin UI not deployed (missing static/index.html).</h3>")


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


@app.get("/admin/devices/{device_id}/logs/{log_date}/content", response_class=PlainTextResponse)
def log_content(device_id: str, log_date: str, admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] == "root":
            dev = conn.execute("SELECT id FROM devices WHERE device_id=?", (device_id,)).fetchone()
        else:
            dev = conn.execute("SELECT id FROM devices WHERE device_id=? AND site_id=?", (device_id, admin["site_id"])).fetchone()
        if not dev:
            raise HTTPException(404, "device not found")
        row = conn.execute("SELECT stored_path FROM log_files WHERE device_id=? AND log_date=?",
                           (dev["id"], log_date)).fetchone()
    if not row:
        raise HTTPException(404, "no log for that date")
    p = Path(row["stored_path"])
    if not p.exists():
        raise HTTPException(404, "stored file missing on server")
    return PlainTextResponse(p.read_text(errors="replace"))


@app.post("/admin/devices/{device_id}/revoke")
def revoke_device(device_id: str, admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] != "root":
            s = conn.execute("SELECT site_id FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if not s or s["site_id"] != admin["site_id"]:
                raise HTTPException(403, "not your site")
        conn.execute("UPDATE devices SET status='revoked', revoked_at=? WHERE device_id=?",
                     (datetime.utcnow().isoformat(), device_id))
        audit(conn, admin["username"], "revoke", target=device_id, result="ok", device_id=device_id)
    return {"ok": True, "status": "revoked"}


@app.post("/admin/devices/{device_id}/restore")
def restore_device(device_id: str, admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        conn.execute("UPDATE devices SET status='active', revoked_at=NULL WHERE device_id=?", (device_id,))
        audit(conn, admin["username"], "restore", target=device_id, result="ok", device_id=device_id)
    return {"ok": True, "status": "active"}


@app.get("/admin/audit")
def list_audit(admin: dict = Depends(get_admin)):
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
        audit(conn, admin["username"], "create_admin", target=body.get("username"),
              result="ok", detail=f"role={body.get('role')}")
    return {"ok": True}


@app.delete("/admin/devices/{device_id}")
def delete_device(device_id: str, admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        d = conn.execute("SELECT id FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if not d:
            raise HTTPException(404, "device not found")
        conn.execute("DELETE FROM log_files WHERE device_id=?", (d["id"],))
        conn.execute("DELETE FROM location_history WHERE device_id=?", (d["id"],))
        conn.execute("DELETE FROM devices WHERE id=?", (d["id"],))
        audit(conn, admin["username"], "delete", target=device_id, result="ok", device_id=device_id)
    return {"ok": True, "deleted": device_id}


@app.get("/admin/devices/{device_id}/locations")
def device_locations(device_id: str, admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] == "root":
            dev = conn.execute("SELECT id FROM devices WHERE device_id=?", (device_id,)).fetchone()
        else:
            dev = conn.execute("SELECT id FROM devices WHERE device_id=? AND site_id=?", (device_id, admin["site_id"])).fetchone()
        if not dev:
            raise HTTPException(404, "device not found")
        rows = conn.execute(
            "SELECT lat,lng,speed,ts FROM location_history WHERE device_id=? ORDER BY ts DESC LIMIT 500",
            (dev["id"],)).fetchall()
    return {"locations": [dict(r) for r in rows]}


@app.get("/admin/devices/{device_id}/detail")
def device_detail(device_id: str, admin: dict = Depends(get_admin)):
    """Full per-device console data: row + pushed apps + client-installed apps + geofences + pending commands + device-specific audit."""
    with db() as conn:
        if admin["role"] == "root":
            dev = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        else:
            dev = conn.execute("SELECT * FROM devices WHERE device_id=? AND site_id=?", (device_id, admin["site_id"])).fetchone()
        if not dev:
            raise HTTPException(404, "device not found")
        dv = dict(dev)
        # client-reported installed apps (from /device/inventory)
        apps = conn.execute("SELECT package,label,updated_at FROM apps WHERE device_id=? ORDER BY label LIMIT 500",
                            (device_id,)).fetchall()
        # current compliance flags
        issues = []
        if dv.get("rooted"): issues.append("rooted")
        if dv.get("unknown_sources"): issues.append("unknown-sources")
        if dv.get("unlocked_boot"): issues.append("unlocked-bootloader")
        try:
            patch = int(str(dv.get("security_patch") or "").replace("-", "")) or 0
            if 0 < patch < 20260700: issues.append("outdated-patch")
        except Exception: pass
        dv["compliance"] = issues
        dv["apps"] = [dict(a) for a in apps]
        # geofences for this device
        geo = conn.execute("SELECT * FROM geofences WHERE device_id=? AND active=1", (device_id,)).fetchall()
        dv["geofences"] = [dict(g) for g in geo]
        # policy
        pol = conn.execute("SELECT policy FROM device_policy WHERE device_id=?", (device_id,)).fetchone()
        dv["policy"] = json.loads(pol["policy"]) if pol else None
        # pending commands
        pend = conn.execute("SELECT id,cmd,param,issued_by,created_at FROM commands WHERE device_id=? AND acked_at IS NULL ORDER BY id DESC",
                            (device_id,)).fetchall()
        dv["commands"] = [dict(p) for p in pend]
        # device-specific audit
        aud = conn.execute("SELECT actor,action,ts,result,reason FROM audit WHERE device_id=? OR target=? ORDER BY id DESC LIMIT 50",
                           (device_id, device_id)).fetchall()
        dv["audit"] = [dict(a) for a in aud]
    return dv


@app.get("/admin/settings")
def get_settings(admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        rows = conn.execute("SELECT key,value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


@app.post("/admin/settings")
def set_settings(body: dict = Body(...), admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    allowed = {"work_start", "work_end", "work_active", "location_interval_s", "timezone"}
    with db() as conn:
        for k, v in body.items():
            if k in allowed:
                conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, str(v)))
        audit(conn, admin["username"], "set_settings", result="ok", detail=json.dumps(body))
    return {"ok": True}


def _issue_command(conn, device_id, cmd, param, actor, reason=None):
    conn.execute("INSERT INTO commands(device_id,cmd,param,issued_by,created_at) VALUES(?,?,?,?,?)",
                 (device_id, cmd, param, actor, datetime.utcnow().isoformat()))
    audit(conn, actor, f"command:{cmd}", target=device_id, result="queued",
          device_id=device_id, reason=reason, detail=param or None)


@app.post("/admin/devices/{device_id}/lock")
def device_lock(device_id: str, body: dict = Body(default={}), admin: dict = Depends(get_admin)):
    with db() as conn:
        if admin["role"] != "root":
            dev = conn.execute("SELECT id FROM devices WHERE device_id=? AND site_id=?", (device_id, admin["site_id"])).fetchone()
            if not dev: raise HTTPException(403, "device not in your site")
        _issue_command(conn, device_id, "lock", "screen", admin["username"], reason=body.get("reason"))
    return {"ok": True, "queued": "lock"}


@app.post("/admin/devices/{device_id}/wipe")
def device_wipe(device_id: str, body: dict = Body(default={}), admin: dict = Depends(get_admin)):
    if admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        _issue_command(conn, device_id, "wipe", "full", admin["username"], reason=body.get("reason"))
    return {"ok": True, "queued": "wipe"}


@app.post("/admin/devices/{device_id}/command")
def device_command(device_id: str, body: dict = Body(...), admin: dict = Depends(get_admin)):
    cmd = body.get("cmd")
    if cmd not in ("lock", "wipe", "beeper", "sync", "restrict_apps", "kiosk"):
        raise HTTPException(400, "unsupported command")
    if cmd == "wipe" and admin["role"] != "root":
        raise HTTPException(403, "root only")
    with db() as conn:
        _issue_command(conn, device_id, cmd, body.get("param", ""), admin["username"], reason=body.get("reason"))
    return {"ok": True, "queued": cmd}


@app.post("/admin/devices/{device_id}/policy")
def set_device_policy(device_id: str, body: dict = Body(...), admin: dict = Depends(get_admin)):
    with db() as conn:
        if not conn.execute("SELECT id FROM devices WHERE device_id=?",
                            (device_id,)).fetchone():
            raise HTTPException(404, "device not found")
        conn.execute("INSERT OR REPLACE INTO device_policy(device_id,policy) VALUES(?,?)",
                     (device_id, json.dumps(body.get("policy", {}))))
        audit(conn, admin["username"], "set_policy", target=device_id, result="ok",
              device_id=device_id, detail=json.dumps(body.get("policy", {})))
    return {"ok": True}


@app.post("/admin/devices/{device_id}/geofence")
def set_geofence(device_id: str, body: dict = Body(...), admin: dict = Depends(get_admin)):
    with db() as conn:
        conn.execute("INSERT INTO geofences(device_id,name,lat,lng,radius_m,active) VALUES(?,?,?,?,?,1)",
                     (device_id, body.get("name", "zone1"), body.get("lat"), body.get("lng"), body.get("radius_m", 500)))
        audit(conn, admin["username"], "set_geofence", target=device_id, result="ok",
              device_id=device_id, detail=f"{body.get('name')} r={body.get('radius_m')}m")
    return {"ok": True}


@app.delete("/admin/geofence/{gfid}")
def del_geofence(gfid: int, admin: dict = Depends(get_admin)):
    with db() as conn:
        row = conn.execute("SELECT device_id FROM geofences WHERE id=?", (gfid,)).fetchone()
        conn.execute("DELETE FROM geofences WHERE id=?", (gfid,))
        audit(conn, admin["username"], "del_geofence", target=row["device_id"] if row else None, result="ok")
    return {"ok": True}


@app.get("/admin/compliance")
def compliance(admin: dict = Depends(get_admin)):
    """Dashboard: flag each device for root, unknown sources, unlocked boot, outdated OS/patch."""
    with db() as conn:
        q = "SELECT device_id,model,os_version,security_patch,sdk,rooted,unknown_sources,unlocked_boot,last_seen_at,status FROM devices"
        parms = ()
        if admin["role"] != "root":
            q += " WHERE site_id=?"
            parms = (admin["site_id"],)
        rows = conn.execute(q, parms).fetchall()
    out = []
    for r in rows:
        issues = []
        if r["rooted"]: issues.append("rooted")
        if r["unknown_sources"]: issues.append("unknown-sources")
        if r["unlocked_boot"]: issues.append("unlocked-bootloader")
        try:
            patch = int(str(r["security_patch"] or "").replace("-", "")) or 0
            if 0 < patch < 20260700: issues.append("outdated-patch")
        except Exception: pass
        out.append(dict(r) | {"issues": issues, "ok": len(issues) == 0})
    return {"devices": out}


@app.get("/admin/geofences")
def list_geofences(admin: dict = Depends(get_admin)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM geofences").fetchall()
    return {"geofences": [dict(r) for r in rows]}


@app.get("/admin/metrics")
def dashboard_metrics(admin: dict = Depends(get_admin)):
    """Aggregate overview for the dashboard (active/offline, health, battery, storage, versions, actions)."""
    import time
    now = datetime.utcnow().timestamp()
    offline_after_s = 120
    with db() as conn:
        scope = ""; parms = ()
        if admin["role"] != "root":
            site_id = admin["site_id"]
            scope = "WHERE site_id=?"
            parms = (site_id,)
        devices = conn.execute(f"SELECT * FROM devices {scope}".strip(), parms).fetchall()
        total = len(devices)
        active = sum(1 for d in devices if d["status"] == "active")
        revoked = total - active
        offline = 0
        low_battery = 0
        weighted_health = 0.0
        versions = {}
        for d in devices:
            lst = d["last_seen_at"]
            try:
                st = datetime.fromisoformat(lst).timestamp()
            except Exception:
                st = 0
            if time.time() - st > offline_after_s:
                offline += 1
            bp = d["battery_pct"]
            if bp is not None and bp < 20:
                low_battery += 1
            # simple health score: 0-100
            score = 100.0
            if d["rooted"]: score -= 30
            if d["unknown_sources"]: score -= 20
            if d["unlocked_boot"]: score -= 20
            if bp is not None and bp < 20: score -= 10
            if d["security_patch"] is not None and d["security_patch"]:
                try:
                    if int(str(d["security_patch"]).replace("-", "")) < 20260700: score -= 15
                except Exception: pass
            weighted_health += max(0, score)
            v = d["os_version"]
            if v: versions[v] = versions.get(v, 0) + 1
        avg_health = round(weighted_health / total, 1) if total else 0.0
        # remote actions performed (from audit)
        actions = conn.execute("SELECT action, result, COUNT(*) n FROM audit WHERE action LIKE 'command:%' OR action IN ('revoke','restore','set_policy','wipe','lock') GROUP BY action, result").fetchall()
        admin_actions = [{"action": a["action"], "result": a["result"], "count": a["n"]} for a in actions]
        # recent audit last-30
        recent_audit = conn.execute("SELECT actor,action,target,ts,result,reason,device_id FROM audit ORDER BY id DESC LIMIT 30").fetchall()
        # storage totals
        total_storage = sum((d["storage_total"] or 0) for d in devices)
        free_storage = sum((d["storage_free"] or 0) for d in devices)
    return {
        "total": total, "active": active, "offline": offline,
        "revoked": revoked, "low_battery": low_battery,
        "avg_health": avg_health,
        "total_storage": total_storage, "free_storage": free_storage,
        "os_versions": versions,
        "admin_actions": admin_actions,
        "recent_audit": [dict(r) for r in recent_audit],
    }