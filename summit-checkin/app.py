"""Summit check-in server.

Run:  VOLUNTEER_PASSCODE=... uvicorn app:app --host 0.0.0.0 --port 8000
"""
import base64
import csv
import hashlib
import hmac
import io
import os
import re
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import store

BASE = Path(__file__).parent
EVENT_NAME = os.environ.get("EVENT_NAME", "AI Safety Summit")
EVENT_DETAILS = os.environ.get("EVENT_DETAILS", "")
PASSCODE = os.environ.get("VOLUNTEER_PASSCODE", "")
if not PASSCODE:
    raise SystemExit("Set VOLUNTEER_PASSCODE before starting the server.")
SECRET = (os.environ.get("SECRET_KEY") or hashlib.sha256(("summit|" + PASSCODE).encode()).hexdigest()).encode()
SESSION_HOURS = 14
COOKIE = "volunteer_session"

store.init_db()
print(f"Storage: {store.backend_name()}")
app = FastAPI(title="Summit check-in", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


# ---------- volunteer sessions (signed cookie, no extra dependencies) ----------

def _sign(payload: str) -> str:
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_session(name: str) -> str:
    exp = int(time.time()) + SESSION_HOURS * 3600
    payload = base64.urlsafe_b64encode(f"{exp}|{name}".encode()).decode()
    return f"{payload}.{_sign(payload)}"


def read_session(cookie: str | None) -> str | None:
    """Returns the volunteer's name if the cookie is valid, else None."""
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        exp, name = base64.urlsafe_b64decode(payload.encode()).decode().split("|", 1)
        return name if int(exp) > time.time() else None
    except Exception:
        return None


def volunteer(request: Request) -> str:
    name = read_session(request.cookies.get(COOKIE))
    if name is None:
        raise HTTPException(status_code=401, detail="Sign in with the volunteer passcode.")
    return name


_failures: dict[str, list[float]] = {}


def _throttle(ip: str) -> None:
    now = time.time()
    recent = [t for t in _failures.get(ip, []) if now - t < 300]
    _failures[ip] = recent
    if len(recent) >= 8:
        raise HTTPException(status_code=429, detail="Too many attempts. Wait a few minutes.")


# ---------- pages ----------

@app.get("/")
def home():
    return RedirectResponse("/scan")


@app.get("/healthz")
def healthz(db: bool = False):
    """For uptime monitors. Add ?db=1 to also wake the database."""
    if db:
        with store.connect() as conn:
            conn.execute("SELECT 1").fetchone()
    return {"ok": True}


@app.get("/pass/{token}")
def pass_page(token: str):
    return FileResponse(BASE / "static" / "pass.html", headers={"Cache-Control": "no-store"})


@app.get("/scan")
def scan_page():
    return FileResponse(BASE / "static" / "scan.html", headers={"Cache-Control": "no-store"})


# ---------- registrant side ----------

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


@app.get("/api/pass/{token}")
def get_pass(token: str):
    if not TOKEN_RE.match(token):
        raise HTTPException(status_code=404, detail="Pass not found.")
    with store.connect() as conn:
        row = conn.execute("SELECT name, checked_in FROM registrants WHERE token=?", (token,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Pass not found.")
    return {
        "name": row["name"],
        "token": token,
        "checked_in": bool(row["checked_in"]),
        "event_name": EVENT_NAME,
        "event_details": EVENT_DETAILS,
    }


# ---------- volunteer side ----------

class Login(BaseModel):
    passcode: str
    name: str = ""


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    _throttle(ip)
    if not hmac.compare_digest(body.passcode.encode(), PASSCODE.encode()):
        _failures.setdefault(ip, []).append(time.time())
        raise HTTPException(status_code=401, detail="Wrong passcode.")
    name = (body.name.strip() or "Volunteer")[:40].replace("|", " ")
    response.set_cookie(
        COOKIE, make_session(name), max_age=SESSION_HOURS * 3600,
        httponly=True, samesite="lax", secure=request.url.scheme == "https",
    )
    return {"name": name}


def _public(row) -> dict:
    return {
        "id": row["id"], "name": row["name"], "email": row["email"], "source": row["source"],
        "checked_in": bool(row["checked_in"]), "checked_in_at": row["checked_in_at"],
        "checked_in_by": row["checked_in_by"],
    }


def _stats(conn) -> dict:
    r = conn.execute("SELECT COUNT(*) total, COALESCE(SUM(checked_in),0) done FROM registrants").fetchone()
    return {"total": r["total"], "checked_in": r["done"]}


class ScanBody(BaseModel):
    token: str


@app.post("/api/checkin")
def checkin_by_token(body: ScanBody, who: str = Depends(volunteer)):
    token = body.token.strip()
    if not TOKEN_RE.match(token):
        return {"status": "invalid"}
    with store.connect() as conn:
        status, row = store.check_in(conn, "token", token, who)
        stats = _stats(conn)
    return {"status": status, "person": _public(row) if row else None, "stats": stats}


@app.post("/api/checkin/{person_id}")
def checkin_by_id(person_id: int, who: str = Depends(volunteer)):
    with store.connect() as conn:
        status, row = store.check_in(conn, "id", person_id, who)
        stats = _stats(conn)
    return {"status": status, "person": _public(row) if row else None, "stats": stats}


@app.post("/api/undo/{person_id}")
def undo(person_id: int, who: str = Depends(volunteer)):
    with store.connect() as conn:
        conn.execute(
            "UPDATE registrants SET checked_in=0, checked_in_at=NULL, checked_in_by=NULL WHERE id=?",
            (person_id,),
        )
        row = conn.execute("SELECT * FROM registrants WHERE id=?", (person_id,)).fetchone()
        stats = _stats(conn)
    if row is None:
        raise HTTPException(status_code=404, detail="Not found.")
    return {"person": _public(row), "stats": stats}


@app.get("/api/search")
def search(q: str = "", who: str = Depends(volunteer)):
    q = q.strip()
    if len(q) < 2:
        return {"results": []}
    like = f"%{q}%"
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM registrants WHERE lower(name) LIKE lower(?) OR lower(email) LIKE lower(?) ORDER BY name LIMIT 25",
            (like, like),
        ).fetchall()
    return {"results": [_public(r) for r in rows]}


@app.get("/api/stats")
def stats(who: str = Depends(volunteer)):
    with store.connect() as conn:
        return {**_stats(conn), "volunteer": who, "event_name": EVENT_NAME}


class WalkIn(BaseModel):
    name: str
    email: str = ""


@app.post("/api/walkin")
def walk_in(body: WalkIn, who: str = Depends(volunteer)):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Enter a name.")
    with store.connect() as conn:
        try:
            row = store.add_registrant(conn, name, body.email, source="walk-in")
        except Exception:
            raise HTTPException(status_code=409, detail="That email is already registered. Search for it instead.")
        _, row = store.check_in(conn, "id", row["id"], who)
        stats = _stats(conn)
    return {"status": "ok", "person": _public(row), "stats": stats}


@app.get("/api/export.csv")
def export_csv(who: str = Depends(volunteer)):
    with store.connect() as conn:
        rows = conn.execute("SELECT * FROM registrants ORDER BY name").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "email", "source", "checked_in", "checked_in_at_utc", "checked_in_by"])
    for r in rows:
        w.writerow([r["name"], r["email"], r["source"], "yes" if r["checked_in"] else "no",
                    r["checked_in_at"] or "", r["checked_in_by"] or ""])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=attendance.csv"})
