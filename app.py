import os, hmac, hashlib, base64, io, sqlite3, re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError
import jwt
import qrcode
from starlette.concurrency import run_in_threadpool

# ---------- Configuration & Environment ----------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def required_secret(name: str, minimum_length: int) -> str:
    value = os.environ.get(name, "").strip()
    if len(value) < minimum_length:
        raise RuntimeError(
            f"{name} must be set to a random value of at least {minimum_length} characters. "
            "See .env.example and README.md."
        )
    return value


SECRET = required_secret("CODE_SECRET", 32).encode()
STAFF_KEY = required_secret("STAFF_KEY", 24)
ACCESS_TEAM_DOMAIN = os.environ.get("CF_ACCESS_TEAM_DOMAIN", "").strip().rstrip("/")
ACCESS_AUD = os.environ.get("CF_ACCESS_AUD", "").strip()
if ACCESS_TEAM_DOMAIN and not ACCESS_TEAM_DOMAIN.startswith(("https://", "http://")):
    ACCESS_TEAM_DOMAIN = f"https://{ACCESS_TEAM_DOMAIN}"
if ACCESS_TEAM_DOMAIN:
    access_domain = urlsplit(ACCESS_TEAM_DOMAIN)
    if (
        access_domain.scheme != "https"
        or not access_domain.netloc
        or access_domain.path
        or access_domain.query
        or access_domain.fragment
        or access_domain.username
        or access_domain.password
    ):
        raise RuntimeError("CF_ACCESS_TEAM_DOMAIN must be an HTTPS Cloudflare Access team domain.")
if bool(ACCESS_TEAM_DOMAIN) != bool(ACCESS_AUD):
    raise RuntimeError("Set both CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD to enable Cloudflare Access.")
ACCESS_ISSUER = ACCESS_TEAM_DOMAIN if ACCESS_TEAM_DOMAIN else ""
ACCESS_JWKS_CLIENT = (
    PyJWKClient(f"{ACCESS_ISSUER}/cdn-cgi/access/certs", timeout=5)
    if ACCESS_ISSUER
    else None
)
DB_PATH = Path(os.environ.get("DB_PATH", "delegates.db"))
DB = str(DB_PATH if DB_PATH.is_absolute() else BASE_DIR / DB_PATH)

app = FastAPI(title="AI Safety Summit - Entry Pass & Volunteer Check-in")

# Mount local static files for offline client libraries (qrcode.js, html5-qrcode.min.js)
if (BASE_DIR / "static").is_dir():
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@contextmanager
def db():
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS delegates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            generated_at TEXT,
            checked_in_at TEXT
        )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_token ON delegates(token)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_email ON delegates(email)")


init_db()


# ---------- Delegate Code (HMAC) ----------
def make_code(delegate_id: int) -> str:
    """Generate unguessable HMAC-based delegate code."""
    mac = hmac.new(SECRET, f"delegate:{delegate_id}".encode(), hashlib.sha256).digest()
    tag = base64.b32encode(mac).decode()[:10]
    return f"SUM{delegate_id:04d}-{tag}"


def parse_code(code: str) -> Optional[int]:
    """Verify HMAC signature and return delegate_id if authentic, else None."""
    code = code.strip().upper()
    match = re.fullmatch(r"SUM([0-9]{4,})-([A-Z2-7]{10})", code)
    if not match:
        return None
    try:
        delegate_id = int(match.group(1))
    except ValueError:
        return None
    if delegate_id < 1:
        return None
    return delegate_id if hmac.compare_digest(make_code(delegate_id), code) else None


def delegate_by_token(token: str):
    with db() as con:
        row = con.execute("SELECT * FROM delegates WHERE token=?", (token,)).fetchone()
    if not row:
        raise HTTPException(404, "Invalid or expired link")
    return row


def verify_staff(x_staff_key: str):
    if not hmac.compare_digest(x_staff_key or "", STAFF_KEY):
        raise HTTPException(401, "Bad or missing staff key")


@app.middleware("http")
async def disable_api_caching(request, call_next):
    staff_paths = {
        "/scan",
        "/api/attendees",
        "/api/checkin",
        "/api/checkin_by_id",
        "/api/stats",
        "/api/offline_roster",
        "/api/sync_checkins",
    }

    def access_error(message: str, status_code: int) -> Response:
        return Response(
            message,
            status_code=status_code,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    if request.url.path in staff_paths:
        if not ACCESS_ISSUER or not ACCESS_AUD or not ACCESS_JWKS_CLIENT:
            return access_error("Cloudflare Access is not configured for staff routes.", 503)
        assertion = request.headers.get("Cf-Access-Jwt-Assertion", "")
        if not assertion:
            return access_error("Cloudflare Access authentication required.", 401)
        try:
            await run_in_threadpool(verify_access_assertion, assertion)
        except PyJWKClientConnectionError:
            return access_error("Cloudflare Access verification is temporarily unavailable.", 503)
        except (PyJWKClientError, jwt.PyJWTError, ValueError):
            return access_error("Invalid Cloudflare Access token.", 401)
        except OSError:
            return access_error("Cloudflare Access verification is temporarily unavailable.", 503)

    response = await call_next(request)
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/") or request.url.path in staff_paths:
        response.headers["Cache-Control"] = "no-store"
    return response


def verify_access_assertion(assertion: str) -> None:
    if ACCESS_JWKS_CLIENT is None:
        raise ValueError("Cloudflare Access is not configured.")
    signing_key = ACCESS_JWKS_CLIENT.get_signing_key_from_jwt(assertion)
    jwt.decode(
        assertion,
        signing_key.key,
        algorithms=["RS256"],
        audience=ACCESS_AUD,
        issuer=ACCESS_ISSUER,
    )


# ---------- Delegate-Facing API ----------
class TokenBody(BaseModel):
    t: str = Field(max_length=128)


@app.get("/api/resolve")
def resolve(t: str = Query(max_length=128)):
    d = delegate_by_token(t)
    code = make_code(d["id"]) if d["generated_at"] else None
    return {
        "id": d["id"],
        "name": d["name"],
        "email": d["email"],
        "code": code,
        "generated_at": d["generated_at"],
        "checked_in_at": d["checked_in_at"]
    }


@app.post("/api/generate")
def generate(body: TokenBody):
    d = delegate_by_token(body.t)
    now = datetime.now(timezone.utc).isoformat()
    with db() as con:
        con.execute("UPDATE delegates SET generated_at=COALESCE(generated_at, ?) WHERE id=?",
                    (now, d["id"]))
    code = make_code(d["id"])
    return {
        "id": d["id"],
        "code": code,
        "name": d["name"],
        "email": d["email"],
        "generated_at": d["generated_at"] or now
    }


@app.get("/api/qr")
def qr(t: str = Query(max_length=128)):
    """Server-side QR generation fallback."""
    d = delegate_by_token(t)
    code = make_code(d["id"])
    img = qrcode.make(code, box_size=10, border=4)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), media_type="image/png")


# ---------- Volunteer Check-in API ----------
class CheckinBody(BaseModel):
    code: str = Field(max_length=64)


@app.post("/api/checkin")
def checkin(body: CheckinBody, x_staff_key: str = Header(default="")):
    verify_staff(x_staff_key)
    delegate_id = parse_code(body.code)
    if delegate_id is None:
        return {"status": "invalid", "message": "Code signature invalid or malformed"}
    now = datetime.now(timezone.utc).isoformat()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        d = con.execute("SELECT * FROM delegates WHERE id=?", (delegate_id,)).fetchone()
        if not d:
            return {"status": "invalid", "message": "Delegate record not found"}
        cur = con.execute(
            "UPDATE delegates SET checked_in_at=? WHERE id=? AND checked_in_at IS NULL",
            (now, delegate_id))
        if cur.rowcount == 0:
            return {
                "status": "already",
                "id": d["id"],
                "name": d["name"],
                "email": d["email"],
                "at": d["checked_in_at"]
            }
    return {
        "status": "ok",
        "id": d["id"],
        "name": d["name"],
        "email": d["email"],
        "at": now
    }


# ---------- Fallback Search Desk API ----------
@app.get("/api/attendees")
def search_attendees(q: str = Query(default="", max_length=100), x_staff_key: str = Header(default="")):
    """Searchable attendee list for volunteers when delegates lose their QR or email."""
    verify_staff(x_staff_key)
    query_str = f"%{q.strip().lower()}%"
    with db() as con:
        if q.strip():
            if q.strip().isdigit():
                rows = con.execute(
                    "SELECT * FROM delegates WHERE id=? OR LOWER(name) LIKE ? OR LOWER(email) LIKE ? ORDER BY name ASC LIMIT 50",
                    (int(q.strip()), query_str, query_str)
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM delegates WHERE LOWER(name) LIKE ? OR LOWER(email) LIKE ? ORDER BY name ASC LIMIT 50",
                    (query_str, query_str)
                ).fetchall()
        else:
            rows = con.execute("SELECT * FROM delegates ORDER BY name ASC LIMIT 50").fetchall()

    return [
        {
            "id": r["id"],
            "name": r["name"],
            "email": r["email"],
            "code": make_code(r["id"]),
            "checked_in_at": r["checked_in_at"],
            "generated_at": r["generated_at"]
        }
        for r in rows
    ]


class CheckinByIdBody(BaseModel):
    id: int = Field(gt=0)


@app.post("/api/checkin_by_id")
def checkin_by_id(body: CheckinByIdBody, x_staff_key: str = Header(default="")):
    """Check in directly by delegate ID from attendee fallback list."""
    verify_staff(x_staff_key)
    now = datetime.now(timezone.utc).isoformat()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        d = con.execute("SELECT * FROM delegates WHERE id=?", (body.id,)).fetchone()
        if not d:
            raise HTTPException(404, "Delegate not found")
        cur = con.execute(
            "UPDATE delegates SET checked_in_at=? WHERE id=? AND checked_in_at IS NULL",
            (now, body.id)
        )
        if cur.rowcount == 0:
            return {
                "status": "already",
                "id": d["id"],
                "name": d["name"],
                "email": d["email"],
                "at": d["checked_in_at"]
            }
    return {
        "status": "ok",
        "id": d["id"],
        "name": d["name"],
        "email": d["email"],
        "at": now
    }


@app.get("/api/stats")
def stats(x_staff_key: str = Header(default="")):
    verify_staff(x_staff_key)
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM delegates").fetchone()[0]
        checked_in = con.execute("SELECT COUNT(*) FROM delegates WHERE checked_in_at IS NOT NULL").fetchone()[0]
        generated = con.execute("SELECT COUNT(*) FROM delegates WHERE generated_at IS NOT NULL").fetchone()[0]
    return {
        "total": total,
        "checked_in": checked_in,
        "pending": total - checked_in,
        "generated": generated
    }


# ---------- Offline Roster & Sync API ----------
@app.get("/api/offline_roster")
def offline_roster(x_staff_key: str = Header(default="")):
    """Download delegate codes and check-in state for the offline scanner."""
    verify_staff(x_staff_key)
    with db() as con:
        rows = con.execute("SELECT id, name, email, checked_in_at FROM delegates").fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "code": make_code(r["id"]),
            "checked_in_at": r["checked_in_at"]
        }
        for r in rows
    ]


class SyncItem(BaseModel):
    code: str = Field(max_length=64)
    at: Optional[str] = Field(default=None, max_length=64)


class SyncBody(BaseModel):
    checkins: List[SyncItem] = Field(max_length=500)


@app.post("/api/sync_checkins")
def sync_checkins(body: SyncBody, x_staff_key: str = Header(default="")):
    """Sync check-ins captured while scanner was offline."""
    verify_staff(x_staff_key)
    results = []
    now_fallback = datetime.now(timezone.utc).isoformat()
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        for item in body.checkins:
            delegate_id = parse_code(item.code)
            if delegate_id is None:
                results.append({"code": item.code, "status": "invalid"})
                continue
            d = con.execute("SELECT * FROM delegates WHERE id=?", (delegate_id,)).fetchone()
            if not d:
                results.append({"code": item.code, "status": "invalid"})
                continue
            ts = item.at or now_fallback
            if item.at:
                try:
                    parsed_at = datetime.fromisoformat(item.at.replace("Z", "+00:00"))
                    if parsed_at.tzinfo is None or parsed_at.utcoffset() is None:
                        raise ValueError("Offline timestamp must include a UTC offset.")
                    ts = parsed_at.astimezone(timezone.utc).isoformat()
                except (ValueError, OverflowError):
                    results.append({"code": item.code, "status": "invalid_timestamp"})
                    continue
            cur = con.execute(
                "UPDATE delegates SET checked_in_at=? WHERE id=? AND checked_in_at IS NULL",
                (ts, delegate_id)
            )
            if cur.rowcount == 0:
                results.append({
                    "code": item.code,
                    "id": d["id"],
                    "status": "already",
                    "name": d["name"],
                    "at": d["checked_in_at"]
                })
            else:
                results.append({
                    "code": item.code,
                    "id": d["id"],
                    "status": "ok",
                    "name": d["name"],
                    "at": ts
                })
    return {"synced": results}


# ---------- HTML Pages ----------
BADGE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Summit Entry Pass | AI Safety Summit 2026</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
  <script src="/static/qrcode.js"></script>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.85);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --primary-glow: rgba(59, 130, 246, 0.25);
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --emerald: #10b981;
      --amber: #f59e0b;
      --rose: #f43f5e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, var(--bg) 70%);
      min-height: 100vh;
      color: var(--text);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }
    .container {
      width: 100%;
      max-width: 440px;
    }
    .badge-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 28px 24px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 40px var(--primary-glow);
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .badge-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 4px;
      background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
    }
    .event-brand {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(59, 130, 246, 0.12);
      border: 1px solid rgba(59, 130, 246, 0.3);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #93c5fd;
      margin-bottom: 18px;
    }
    .brand-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #3b82f6;
      box-shadow: 0 0 8px #3b82f6;
    }
    h1 {
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 6px;
      background: linear-gradient(180deg, #ffffff 30%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 24px;
    }
    .form-group {
      text-align: left;
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    input {
      width: 100%;
      padding: 13px 16px;
      font-size: 15px;
      font-family: inherit;
      color: #e2e8f0;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px;
      outline: none;
      transition: all 0.2s ease;
    }
    input:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
    }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      width: 100%;
      padding: 14px 20px;
      border-radius: 12px;
      font-size: 15px;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: #fff;
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
    }
    .btn-primary:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(37, 99, 235, 0.45);
    }
    .btn-primary:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: #f1f5f9;
      border: 1px solid rgba(255, 255, 255, 0.12);
      margin-top: 12px;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.2);
    }
    #out {
      display: none;
      margin-top: 24px;
      animation: fadeIn 0.4s ease forwards;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .qr-wrapper {
      background: #ffffff;
      padding: 16px;
      border-radius: 16px;
      display: inline-block;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
      margin-bottom: 16px;
    }
    .qr-wrapper canvas {
      display: block;
      width: 220px !important;
      height: 220px !important;
      border-radius: 6px;
    }
    .code-box {
      background: rgba(15, 23, 42, 0.7);
      border: 1px dashed rgba(59, 130, 246, 0.4);
      border-radius: 12px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .code-val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 17px;
      font-weight: 600;
      color: #60a5fa;
      letter-spacing: 0.08em;
    }
    .copy-btn {
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #93c5fd;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .copy-btn:hover { background: rgba(59, 130, 246, 0.25); }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 16px;
    }
    .status-pill.ready { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .status-pill.in { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .notice {
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.5;
      margin-top: 14px;
    }
    .err-box {
      background: rgba(244, 63, 94, 0.1);
      border: 1px solid rgba(244, 63, 94, 0.3);
      color: #fda4af;
      padding: 14px;
      border-radius: 12px;
      font-size: 14px;
      margin-top: 16px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge-card">
      <div class="event-brand">
        <span class="brand-dot"></span> AI Safety Summit 2026
      </div>
      <h1 id="title">Delegate Entry Pass</h1>
      <p id="welcome" class="subtitle">Validating secure summit invitation...</p>
      
      <div id="err" class="err-box"></div>

      <div id="form-section">
        <div class="form-group">
          <label>Registered Delegate Email</label>
          <input id="email" type="text" readonly placeholder="Loading email...">
        </div>
        <button id="go" class="btn btn-primary" disabled>
          <span>Generate My QR Code</span>
          <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </button>
      </div>

      <div id="out">
        <div id="statusBadge" class="status-pill ready">
          <span>●</span> Pass Active & Ready
        </div>
        
        <div class="qr-wrapper">
          <canvas id="qrCanvas"></canvas>
        </div>

        <div class="code-box">
          <span class="code-val" id="codeText">SUM----</span>
          <button class="copy-btn" id="copyBtn">Copy</button>
        </div>

        <a id="dlBtn" class="btn btn-primary" download="summit-entry-pass.png">
          <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
          Download Pass (PNG)
        </a>

        <p class="notice">
          Present this QR code on your phone or printed paper at entrance turnstiles. Each code admits exactly one person.
        </p>
      </div>
    </div>
  </div>

  <script>
    const t = new URLSearchParams(location.search).get("t");
    const $ = id => document.getElementById(id);
    let delegateData = null;

    function renderQR(code) {
      if (typeof qrcode === 'undefined') {
        console.error("qrcode library not loaded");
        return;
      }
      const qr = qrcode(0, 'M');
      qr.addData(code);
      qr.make();
      
      const count = qr.getModuleCount();
      const canvas = $("qrCanvas");
      const scale = 8;
      const margin = 4 * scale;
      canvas.width = count * scale + margin * 2;
      canvas.height = count * scale + margin * 2;
      const ctx = canvas.getContext("2d");
      
      // Clean white background
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Slate module color
      ctx.fillStyle = "#0f172a";
      for (let r = 0; r < count; r++) {
        for (let c = 0; c < count; c++) {
          if (qr.isDark(r, c)) {
            ctx.fillRect(margin + c * scale, margin + r * scale, scale, scale);
          }
        }
      }
      
      // Prepare high-res PNG download
      const pngUrl = canvas.toDataURL("image/png");
      const dl = $("dlBtn");
      dl.href = pngUrl;
      const safeName = (delegateData?.name || "delegate").toLowerCase().replace(/[^a-z0-9]/g, "-");
      dl.download = `summit-pass-${safeName}.png`;
      $("codeText").textContent = code;
    }

    async function init() {
      if (!t) {
        showError("Missing access token. Please check the personalized link in your invitation email.");
        return;
      }
      try {
        const r = await fetch("/api/resolve?t=" + encodeURIComponent(t));
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          showError(err.detail || "This pass link is invalid or expired. Please contact the summit organizers.");
          return;
        }
        delegateData = await r.json();
        $("email").value = delegateData.email;
        $("welcome").textContent = `Welcome, ${delegateData.name}. Confirm your registration below.`;
        $("go").disabled = false;

        // If delegate already generated code previously, show it right away
        if (delegateData.code) {
          displayPass(delegateData.code, delegateData.checked_in_at);
        }
      } catch (e) {
        showError("Network error while verifying link. Please check your connection.");
      }
    }

    function showError(msg) {
      $("err").textContent = msg;
      $("err").style.display = "block";
      $("welcome").textContent = "Pass verification failed";
      $("form-section").style.display = "none";
    }

    function displayPass(code, checkedInAt) {
      renderQR(code);
      if (checkedInAt) {
        $("statusBadge").className = "status-pill in";
        $("statusBadge").innerHTML = "<span>✓</span> Already Checked In";
      }
      $("form-section").style.display = "none";
      $("out").style.display = "block";
    }

    $("go").onclick = async () => {
      $("go").disabled = true;
      $("go").innerHTML = "Generating...";
      try {
        const r = await fetch("/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ t })
        });
        if (!r.ok) {
          showError("Could not generate delegate pass.");
          return;
        }
        const data = await r.json();
        displayPass(data.code, false);
      } catch (e) {
        showError("Network error generating pass.");
        $("go").disabled = false;
        $("go").innerHTML = "Generate My QR Code";
      }
    };

    $("copyBtn").onclick = () => {
      navigator.clipboard.writeText($("codeText").textContent);
      $("copyBtn").textContent = "Copied!";
      setTimeout(() => $("copyBtn").textContent = "Copy", 1800);
    };

    init();
  </script>
</body>
</html>"""


SCAN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Volunteer Scanner & Desk | AI Safety Summit 2026</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
  <script src="/static/html5-qrcode.min.js"></script>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.95);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.25);
      --amber: #f59e0b;
      --amber-glow: rgba(245, 158, 11, 0.25);
      --rose: #ef4444;
      --rose-glow: rgba(239, 68, 68, 0.25);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, var(--bg) 75%);
      min-height: 100vh;
      color: var(--text);
      padding: 16px;
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .wrapper {
      width: 100%;
      max-width: 580px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--card-border);
    }
    .logo-area h2 {
      font-size: 18px;
      font-weight: 700;
      color: #fff;
    }
    .logo-area p {
      font-size: 12px;
      color: var(--text-muted);
    }
    .staff-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      padding: 4px 10px;
      border-radius: 9999px;
      cursor: pointer;
    }
    .staff-badge.unlocked { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .staff-badge.locked { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    
    .stats-bar {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }
    .stat-card {
      background: rgba(18, 24, 38, 0.7);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 10px 12px;
      text-align: center;
    }
    .stat-val { font-size: 20px; font-weight: 800; color: #fff; }
    .stat-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 6px;
      background: rgba(15, 23, 42, 0.8);
      padding: 4px;
      border-radius: 12px;
      margin-bottom: 16px;
      border: 1px solid var(--card-border);
    }
    .tab-btn {
      flex: 1;
      padding: 9px 4px;
      font-size: 13px;
      font-weight: 600;
      background: transparent;
      color: var(--text-muted);
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
      text-align: center;
    }
    .tab-btn.active {
      background: #2563eb;
      color: #fff;
      box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35);
    }

    /* Tab Contents */
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }

    /* Result Banner */
    .result-banner {
      padding: 18px 20px;
      border-radius: 16px;
      margin-bottom: 16px;
      text-align: center;
      transition: all 0.2s ease;
      background: rgba(30, 41, 59, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .result-banner.ok {
      background: rgba(16, 185, 129, 0.15) !important;
      border: 2px solid #10b981 !important;
      box-shadow: 0 0 25px var(--emerald-glow);
    }
    .result-banner.already {
      background: rgba(245, 158, 11, 0.15) !important;
      border: 2px solid #f59e0b !important;
      box-shadow: 0 0 25px var(--amber-glow);
    }
    .result-banner.invalid {
      background: rgba(239, 68, 68, 0.15) !important;
      border: 2px solid #ef4444 !important;
      box-shadow: 0 0 25px var(--rose-glow);
    }
    .result-title {
      font-size: 22px;
      font-weight: 800;
      margin-bottom: 4px;
    }
    .result-detail {
      font-size: 14px;
      color: #cbd5e1;
    }

    /* Scanner Viewfinder */
    .scanner-box {
      background: #000;
      border-radius: 16px;
      overflow: hidden;
      position: relative;
      border: 1px solid var(--card-border);
      min-height: 280px;
    }
    #reader { width: 100%; }
    .scanner-controls {
      display: flex;
      gap: 10px;
      margin-top: 10px;
    }
    .scanner-controls button {
      flex: 1;
      padding: 10px;
      font-size: 13px;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.08);
      color: #fff;
      border: 1px solid var(--card-border);
      border-radius: 10px;
      cursor: pointer;
    }

    /* Fallback Search Desk */
    .search-input-wrap {
      position: relative;
      margin-bottom: 12px;
    }
    .search-input-wrap input {
      width: 100%;
      padding: 12px 16px;
      font-size: 14px;
      color: #fff;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      outline: none;
    }
    .search-input-wrap input:focus { border-color: #3b82f6; }
    .attendee-list {
      max-height: 400px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .attendee-card {
      background: rgba(18, 24, 38, 0.8);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 12px 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .att-info h4 { font-size: 15px; font-weight: 700; color: #f8fafc; }
    .att-info p { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
    .att-actions { display: flex; align-items: center; gap: 8px; }
    .btn-checkin {
      background: #10b981;
      color: #fff;
      border: none;
      padding: 7px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-checkin:hover { background: #059669; }
    .checked-badge {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
    }

    /* Key Modal */
    #keyModal {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 16px;
    }
    .modal-card {
      background: #1e293b;
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 16px;
      padding: 24px;
      width: 100%;
      max-width: 360px;
      text-align: center;
    }
    .modal-card input {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      margin: 16px 0;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #fff;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <header>
      <div class="logo-area">
        <h2>AI Safety Summit 2026</h2>
        <p>Volunteer Registration & Check-in Desk</p>
      </div>
      <div id="staffBadge" class="staff-badge locked">
        <span id="badgeDot">●</span> <span id="badgeText">Key Needed</span>
      </div>
    </header>

    <!-- Entrance Stats -->
    <div class="stats-bar">
      <div class="stat-card">
        <div class="stat-val" id="statTotal">-</div>
        <div class="stat-label">Registered</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" id="statCheckedIn" style="color: #34d399">-</div>
        <div class="stat-label">Checked In</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" id="statPending" style="color: #f59e0b">-</div>
        <div class="stat-label">Pending</div>
      </div>
    </div>

    <!-- Live Result Banner -->
    <div id="resultBanner" class="result-banner">
      <div class="result-title" id="resTitle">Ready to Scan</div>
      <div class="result-detail" id="resDetail">Position delegate QR code in front of camera</div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('camera', this)">📷 Scanner</button>
      <button class="tab-btn" onclick="switchTab('fallback', this)">🔍 Attendee Search</button>
      <button class="tab-btn" onclick="switchTab('manual', this)">⌨️ Manual Code</button>
      <button class="tab-btn" onclick="switchTab('offline', this)">📶 Offline / Sync</button>
    </div>

    <!-- Tab 1: Live QR Scanner -->
    <div id="tab-camera" class="tab-pane active">
      <div class="scanner-box">
        <div id="reader"></div>
      </div>
      <div class="scanner-controls">
        <button id="btnToggleCam">Toggle Camera</button>
        <button id="btnSoundTest">🔊 Test Beep</button>
      </div>
    </div>

    <!-- Tab 2: Attendee Search Fallback Desk -->
    <div id="tab-fallback" class="tab-pane">
      <div class="search-input-wrap">
        <input id="searchInput" placeholder="Search by name, email, or delegate ID...">
      </div>
      <div id="attendeeList" class="attendee-list">
        <div style="text-align: center; color: var(--text-muted); padding: 20px;">
          Type a name or email to search attendee database
        </div>
      </div>
    </div>

    <!-- Tab 3: Manual Code Entry -->
    <div id="tab-manual" class="tab-pane">
      <div style="background: rgba(18, 24, 38, 0.8); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px;">
        <label style="font-size: 13px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 8px;">
          DELEGATE CODE (e.g. SUM0001-K7X9...)
        </label>
        <div style="display: flex; gap: 8px;">
          <input id="manualInput" style="flex: 1; padding: 12px; background: rgba(15, 23, 42, 0.8); border: 1px solid var(--card-border); border-radius: 10px; color: #fff; font-family: 'JetBrains Mono', monospace; font-size: 16px;" placeholder="SUM0001-XXXX">
          <button id="manualBtn" style="padding: 12px 20px; background: #2563eb; color: #fff; border: none; border-radius: 10px; font-weight: 600; cursor: pointer;">Admit</button>
        </div>
      </div>
    </div>

    <!-- Tab 4: Offline Resilience & Sync -->
    <div id="tab-offline" class="tab-pane">
      <div style="background: rgba(18, 24, 38, 0.8); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px;">
        <h4 style="margin-bottom: 8px;">Offline Roster Cache</h4>
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
          If venue WiFi is unreliable, cache valid delegate codes locally on this device. Scans will be verified and queued for sync. Do not use a shared device; clear local data after the event.
        </p>
        <div style="display: flex; gap: 10px; margin-bottom: 16px;">
          <button id="btnCacheRoster" style="flex: 1; padding: 10px; background: rgba(255, 255, 255, 0.1); border: 1px solid var(--card-border); color: #fff; border-radius: 8px; cursor: pointer; font-weight: 600;">
            📥 Download Roster Cache
          </button>
          <button id="btnSyncPending" style="flex: 1; padding: 10px; background: #10b981; border: none; color: #fff; border-radius: 8px; cursor: pointer; font-weight: 600;">
            🔄 Sync Offline Scans (<span id="pendingCount">0</span>)
          </button>
          <button id="btnClearLocalData" style="flex: 1; padding: 10px; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #fecaca; border-radius: 8px; cursor: pointer; font-weight: 600;">
            Clear Local Data
          </button>
        </div>
        <div id="cacheStatus" style="font-size: 13px; color: #60a5fa;"></div>
      </div>
    </div>
  </div>

  <!-- Staff Key Auth Modal -->
  <div id="keyModal">
    <div class="modal-card">
      <h3 style="color: #fff; margin-bottom: 8px;">Volunteer Staff Authorization</h3>
      <p style="font-size: 13px; color: var(--text-muted);">Enter the event staff key to unlock scanner and check-in desk.</p>
      <input id="keyInput" type="password" placeholder="Enter staff key" autocomplete="current-password">
      <button id="keySave" style="width: 100%; padding: 12px; background: #2563eb; border: none; border-radius: 8px; color: #fff; font-weight: 600; cursor: pointer;">Unlock Scanner</button>
    </div>
  </div>

  <script>
    const $ = id => document.getElementById(id);
    let html5QrCode = null;
    let isBusy = false;
    let cameraRunning = false;
    let audioCtx = null;

    // Web Audio API synthesized chimes
    function playTone(type) {
      try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        const now = audioCtx.currentTime;

        if (type === 'ok') {
          // Cheerful high-pitch success chime
          osc.type = 'sine';
          osc.frequency.setValueAtTime(587.33, now); // D5
          osc.frequency.setValueAtTime(880, now + 0.1); // A5
          gain.gain.setValueAtTime(0.2, now);
          gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
          osc.start(now);
          osc.stop(now + 0.35);
        } else if (type === 'already') {
          // Warning two-tone buzz
          osc.type = 'triangle';
          osc.frequency.setValueAtTime(440, now);
          osc.frequency.setValueAtTime(330, now + 0.15);
          gain.gain.setValueAtTime(0.25, now);
          gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
          osc.start(now);
          osc.stop(now + 0.45);
        } else {
          // Error buzz
          osc.type = 'sawtooth';
          osc.frequency.setValueAtTime(150, now);
          gain.gain.setValueAtTime(0.3, now);
          gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
          osc.start(now);
          osc.stop(now + 0.4);
        }
      } catch (e) {
        console.warn("Audio feedback error:", e);
      }
    }

    function getStaffKey() {
      return sessionStorage.getItem("staff_key") || "";
    }

    function updateStaffBadge() {
      const key = getStaffKey();
      if (key) {
        $("staffBadge").className = "staff-badge unlocked";
        $("badgeText").textContent = "Key Set";
      } else {
        $("staffBadge").className = "staff-badge locked";
        $("badgeText").textContent = "Key Needed";
      }
    }

    $("staffBadge").onclick = () => {
      $("keyInput").value = "";
      $("keyModal").style.display = "flex";
    };

    $("keySave").onclick = () => {
      const val = $("keyInput").value.trim();
      if (!val) {
        $("keyInput").focus();
        return;
      }
      sessionStorage.setItem("staff_key", val);
      $("keyInput").value = "";
      $("keyModal").style.display = "none";
      updateStaffBadge();
      loadStats();
      loadAttendees("");
    };

    function showBanner(status, title, detail) {
      const banner = $("resultBanner");
      banner.className = `result-banner ${status}`;
      $("resTitle").textContent = title;
      $("resDetail").textContent = detail;
    }

    function readLocalList(key) {
      try {
        const stored = localStorage.getItem(key);
        if (!stored) return [];
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) return parsed;
        throw new Error("Stored value is not a list.");
      } catch (err) {
        console.error(`Could not read local ${key}:`, err);
        $("cacheStatus").textContent = `Could not read local ${key}. Offline data may need to be cleared.`;
        return [];
      }
    }

    function markCachedCheckin(id, at) {
      try {
        if (!localStorage.getItem("cached_roster")) return;
        const roster = readLocalList("cached_roster");
        const attendee = roster.find(d => d && d.id === id);
        if (attendee) {
          attendee.checked_in_at = at;
          localStorage.setItem("cached_roster", JSON.stringify(roster));
        }
      } catch (err) {
        console.error("Could not update cached check-in state:", err);
        $("cacheStatus").textContent = "Server check-in succeeded, but local roster could not be updated.";
      }
    }

    async function handleCheckin(code) {
      if (isBusy) return;
      isBusy = true;
      try {
        const res = await fetch("/api/checkin", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Staff-Key": getStaffKey()
          },
          body: JSON.stringify({ code })
        });

        if (res.status === 401) {
          sessionStorage.removeItem("staff_key");
          updateStaffBadge();
          playTone('invalid');
          showBanner("invalid", "STAFF KEY REJECTED", "Enter the current staff key to continue.");
          $("keyModal").style.display = "flex";
          return;
        }

        const data = await res.json();
        if (data.status === "ok") {
          markCachedCheckin(data.id, data.at);
          playTone('ok');
          const timeStr = new Date(data.at).toLocaleTimeString();
          showBanner("ok", `ADMIT: ${data.name}`, `Delegate #${data.id} • Checked in at ${timeStr}`);
          loadStats();
        } else if (data.status === "already") {
          markCachedCheckin(data.id, data.at);
          playTone('already');
          const timeStr = new Date(data.at).toLocaleTimeString();
          showBanner("already", `ALREADY CHECKED IN: ${data.name}`, `First scanned at ${timeStr} • Do not readmit`);
        } else {
          playTone('invalid');
          showBanner("invalid", "INVALID CODE", data.message || "Pass signature failed or not found.");
        }
      } catch (err) {
        // Offline Fallback Check
        const normalizedCode = code.trim().toUpperCase();
        const cached = readLocalList("cached_roster");
        const pending = readLocalList("pending_checkins");
        const found = cached.find(d => d && d.code === normalizedCode);
        const alreadyQueued = pending.some(
          item => typeof item?.code === "string" && item.code.trim().toUpperCase() === normalizedCode
        );
        if (found && (found.checked_in_at || alreadyQueued)) {
          playTone('already');
          showBanner("already", `ALREADY CHECKED IN: ${found.name}`, "This device has a prior check-in record.");
        } else if (found) {
          if (queueOfflineCheckin(normalizedCode)) {
            playTone('ok');
            showBanner("ok", `ADMIT (OFFLINE): ${found.name}`, `Queued check-in locally. Will sync when online.`);
          } else {
            playTone('invalid');
            showBanner("invalid", "OFFLINE QUEUE FAILED", "Do not admit: this device could not safely save the check-in.");
          }
        } else {
          playTone('invalid');
          showBanner("invalid", "NETWORK / OFFLINE ERROR", "Could not reach server and code not in offline cache.");
        }
      } finally {
        setTimeout(() => { isBusy = false; }, 2200);
      }
    }

    function queueOfflineCheckin(code) {
      try {
        const stored = localStorage.getItem("pending_checkins");
        const pending = stored ? JSON.parse(stored) : [];
        if (!Array.isArray(pending)) throw new Error("Pending check-ins are not a list.");
        pending.push({ code, at: new Date().toISOString() });
        localStorage.setItem("pending_checkins", JSON.stringify(pending));
        updatePendingCount();
        return true;
      } catch (err) {
        console.error("Could not queue offline check-in:", err);
        $("cacheStatus").textContent = "Offline queue unavailable. No check-in was recorded.";
        return false;
      }
    }

    function updatePendingCount() {
      const pending = readLocalList("pending_checkins");
      $("pendingCount").textContent = pending.length;
    }

    async function loadStats() {
      try {
        const res = await fetch("/api/stats", {
          headers: { "X-Staff-Key": getStaffKey() }
        });
        if (res.ok) {
          const d = await res.json();
          $("statTotal").textContent = d.total;
          $("statCheckedIn").textContent = d.checked_in;
          $("statPending").textContent = d.pending;
        }
      } catch (e) {}
    }

    // Attendee search fallback
    let searchTimeout = null;
    $("searchInput").oninput = (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => loadAttendees(e.target.value), 250);
    };

    async function loadAttendees(q) {
      try {
        const res = await fetch("/api/attendees?q=" + encodeURIComponent(q), {
          headers: { "X-Staff-Key": getStaffKey() }
        });
        if (!res.ok) return;
        const attendees = await res.json();
        renderAttendeeList(attendees);
      } catch (e) {
        console.error(e);
      }
    }

    function renderAttendeeList(list) {
      const container = $("attendeeList");
      if (!list.length) {
        container.innerHTML = `<div style="text-align:center; color: var(--text-muted); padding: 20px;">No matching delegates found.</div>`;
        return;
      }
      container.innerHTML = list.map(d => {
        const isChecked = !!d.checked_in_at;
        const timeStr = isChecked ? new Date(d.checked_in_at).toLocaleTimeString() : "";
        return `
          <div class="attendee-card">
            <div class="att-info">
              <h4>${escapeHtml(d.name)}</h4>
              <p>${escapeHtml(d.email)} • ID #${d.id} • ${d.code}</p>
            </div>
            <div class="att-actions">
              ${isChecked 
                ? `<span class="checked-badge">✓ In (${timeStr})</span>` 
                : `<button class="btn-checkin" onclick="checkinById(${d.id})">Admit</button>`}
            </div>
          </div>
        `;
      }).join("");
    }

    window.checkinById = async (id) => {
      try {
        const res = await fetch("/api/checkin_by_id", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Staff-Key": getStaffKey()
          },
          body: JSON.stringify({ id })
        });
        const d = await res.json();
        if (d.status === "ok") {
          markCachedCheckin(d.id, d.at);
          playTone('ok');
          showBanner("ok", `ADMIT: ${d.name}`, `Manual Fallback Check-in • #${d.id}`);
        } else if (d.status === "already") {
          markCachedCheckin(d.id, d.at);
          playTone('already');
          showBanner("already", `ALREADY CHECKED IN: ${d.name}`, `First at ${new Date(d.at).toLocaleTimeString()}`);
        }
        loadStats();
        loadAttendees($("searchInput").value);
      } catch (e) {
        alert("Error checking in delegate");
      }
    };

    function escapeHtml(str) {
      return (str || '').replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag));
    }

    // Manual Code Submit
    $("manualBtn").onclick = () => {
      const code = $("manualInput").value.trim();
      if (code) handleCheckin(code);
    };

    // Offline Roster Cache
    $("btnCacheRoster").onclick = async () => {
      try {
        $("cacheStatus").textContent = "Downloading roster...";
        const res = await fetch("/api/offline_roster", {
          headers: { "X-Staff-Key": getStaffKey() }
        });
        if (res.ok) {
          const list = await res.json();
          localStorage.setItem("cached_roster", JSON.stringify(list));
          $("cacheStatus").textContent = `✓ Cached ${list.length} attendees on device for offline scanning.`;
        } else {
          $("cacheStatus").textContent = "Failed to download roster. Check staff key.";
        }
      } catch (e) {
        $("cacheStatus").textContent = "Network error downloading roster.";
      }
    };

    // Sync Pending Offline Scans
    $("btnSyncPending").onclick = async () => {
      const pending = readLocalList("pending_checkins");
      if (!pending.length) {
        alert("No pending offline check-ins to sync.");
        return;
      }
      let syncedCount = 0;
      const unresolved = [];
      for (let offset = 0; offset < pending.length; offset += 200) {
        const batch = pending.slice(offset, offset + 200);
        try {
          const res = await fetch("/api/sync_checkins", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Staff-Key": getStaffKey()
            },
            body: JSON.stringify({ checkins: batch })
          });
          if (!res.ok) throw new Error(`Sync request failed (${res.status}).`);
          const data = await res.json();
          if (!Array.isArray(data.synced) || data.synced.length !== batch.length) {
            throw new Error("Unexpected sync response.");
          }
          data.synced.forEach((result, index) => {
            if (result.status === "ok" || result.status === "already") {
              syncedCount++;
              markCachedCheckin(result.id, result.at);
            } else {
              unresolved.push(batch[index]);
            }
          });
          localStorage.setItem("pending_checkins", JSON.stringify([
            ...unresolved,
            ...pending.slice(offset + batch.length)
          ]));
        } catch (err) {
          unresolved.push(...pending.slice(offset));
          localStorage.setItem("pending_checkins", JSON.stringify(unresolved));
          break;
        }
      }
      updatePendingCount();
      loadStats();
      const rejectedCount = unresolved.length;
      alert(rejectedCount
        ? `Synced ${syncedCount} check-in(s). ${rejectedCount} item(s) remain queued because they were invalid or could not be sent.`
        : `Synced ${syncedCount} check-in(s) successfully.`);
    };

    $("btnClearLocalData").onclick = () => {
      const pending = readLocalList("pending_checkins");
      const warning = pending.length
        ? `This removes the cached roster and discards ${pending.length} unsynced check-in(s) from this device. Continue?`
        : "This removes the cached roster and local check-in data from this device. Continue?";
      if (!window.confirm(warning)) return;
      localStorage.removeItem("cached_roster");
      localStorage.removeItem("pending_checkins");
      updatePendingCount();
      $("cacheStatus").textContent = "Local roster and queued check-ins cleared.";
    };

    // Tabs
    window.switchTab = (tab, button) => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      $("tab-" + tab).classList.add("active");
      button.classList.add("active");
      if (tab === 'fallback') loadAttendees($("searchInput").value);
    };

    // Camera Init
    async function startCamera() {
      try {
        if (!html5QrCode) html5QrCode = new Html5Qrcode("reader");
        await html5QrCode.start(
          { facingMode: "environment" },
          { fps: 12, qrbox: { width: 240, height: 240 } },
          decodedText => handleCheckin(decodedText)
        );
        cameraRunning = true;
      } catch (err) {
        console.warn("Camera start failed:", err);
      }
    }

    $("btnToggleCam").onclick = async () => {
      if (cameraRunning && html5QrCode) {
        await html5QrCode.stop();
        cameraRunning = false;
      } else {
        await startCamera();
      }
    };

    $("btnSoundTest").onclick = () => playTone('ok');

    // Startup
    updateStaffBadge();
    loadStats();
    updatePendingCount();
    if (!getStaffKey()) $("keyModal").style.display = "flex";
    startCamera();
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AI Safety Summit Registration & Access System</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px 20px; text-align: center; }
    .card { max-width: 500px; margin: 40px auto; background: #1e293b; padding: 30px; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); }
    h2 { margin-bottom: 12px; }
    p { color: #94a3b8; margin-bottom: 24px; font-size: 15px; }
    .btn { display: block; padding: 12px; margin: 10px 0; background: #3b82f6; color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600; }
    .btn.staff { background: #10b981; }
  </style>
</head>
<body>
  <div class="card">
    <h2>AI Safety Summit Access Portal</h2>
    <p>Volunteers can open the check-in desk. Delegate pass links are sent individually.</p>
    <a class="btn staff" href="/scan">Volunteer Scanner & Check-in Desk (/scan)</a>
  </div>
</body>
</html>"""


@app.get("/badge", response_class=HTMLResponse)
def badge_page():
    return BADGE_HTML


@app.get("/scan", response_class=HTMLResponse)
def scan_page():
    return SCAN_HTML