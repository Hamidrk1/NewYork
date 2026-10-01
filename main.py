import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("X4G-Gateway")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="X4G Gateway", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "x4g_state.json"
SAVE_LOCK = asyncio.Lock()

LINKS = {}
SUBS = {}
AUTH = {}

async def load_state():
    global LINKS, AUTH, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
                data = json.loads(raw)
                LINKS.update(data.get("links", {}))
                SUBS.update(data.get("subs", {}))
                if "password_hash" in data:
                    AUTH["password_hash"] = data["password_hash"]
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH.get("password_hash"),
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=50)
activity_logs = deque(maxlen=200)
hourly_traffic = defaultdict(int)
http_client: httpx.AsyncClient | None = None

SESSION_COOKIE = "x4g_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}:{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "123456"))}
SESSIONS = dict()

def is_ip_allowed(ip: str) -> bool:
    return True

@app.on_event("startup")
async def startup_event():
    global http_client
    http_client = httpx.AsyncClient(timeout=10.0)
    await load_state()

@app.on_event("shutdown")
async def shutdown_event():
    if http_client:
        await http_client.aclose()

@app.get("/")
async def root():
    return {"status": "ok", "service": "X4G Gateway"}

# --- روت‌های ورود و صفحه لاگین ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    try:
        from pages import get_login_html
        return get_login_html()
    except Exception:
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>X4G Gateway - Login</title></head>
        <body style="background:#111;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;">
            <form action="/login" method="post" style="background:#222;padding:20px;border-radius:8px;">
                <h2>X4G Gateway Login</h2>
                <input type="password" name="password" placeholder="Password" required style="padding:10px;width:100%;box-sizing:border-box;margin-bottom:10px;"><br>
                <button type="submit" style="padding:10px 20px;width:100%;cursor:pointer;">Login</button>
            </form>
        </body>
        </html>
        """)

@app.post("/login")
async def handle_login(request: Request):
    form = await request.form()
    password = form.get("password", "")
    if hash_password(password) == AUTH.get("password_hash"):
        session_id = secrets.token_hex(16)
        SESSIONS[session_id] = time.time() + SESSION_TTL
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(key=SESSION_COOKIE, value=session_id, httponly=True)
        return response
    return HTMLResponse("<p style='color:red;'>رمز عبور اشتباه است! <a href='/login'>تلاش مجدد</a></p>", status_code=400)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id or session_id not in SESSIONS or SESSIONS[session_id] < time.time():
        return RedirectResponse(url="/login")
    
    try:
        from pages import get_dashboard_html
        return get_dashboard_html()
    except Exception:
        return HTMLResponse("<h1>خوش آمدید به داشبورد X4G Gateway</h1>")

@app.websocket("/relay")
async def websocket_relay(websocket: WebSocket, target_host: str = "127.0.0.1", target_port: int = 80):
    from relay_vless import handle_relay_vless
    await handle_relay_vless(websocket, target_host, target_port)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], reload=False)
