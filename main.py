import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
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
    await load_state()

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

# --- صفحه ورود (Login) ---
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X4G Gateway - ورود</title>
    <style>
        body { background: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 2.5rem; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 90%; max-width: 380px; text-align: center; border: 1px solid #334155; }
        h2 { margin-bottom: 1.5rem; color: #38bdf8; font-size: 1.5rem; }
        input { width: 100%; padding: 12px 15px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: #fff; margin-bottom: 1.2rem; box-sizing: border-box; font-size: 1rem; outline: none; }
        input:focus { border-color: #38bdf8; }
        button { width: 100%; padding: 12px; border: none; border-radius: 8px; background: #0284c7; color: #fff; font-size: 1rem; font-weight: bold; cursor: pointer; transition: 0.2s; }
        button:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🚀 X4G Gateway</h2>
        <form action="/login" method="post">
            <input type="password" name="password" placeholder="رمز عبور پنل" required>
            <button type="submit">ورود به پنل</button>
        </form>
    </div>
</body>
</html>
"""

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_HTML)

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
    return HTMLResponse("<div style='text-align:center;padding:50px;color:#f87171;font-family:sans-serif;'><h3>رمز عبور اشتباه است!</h3><a href='/login' style='color:#38bdf8;'>تلاش مجدد</a></div>", status_code=400)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id or session_id not in SESSIONS or SESSIONS[session_id] < time.time():
        return RedirectResponse(url="/login")
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>داشبورد X4G Gateway</title>
        <style>
            body { background: #0f172a; color: #fff; font-family: sans-serif; padding: 2rem; }
            .box { background: #1e293b; padding: 2rem; border-radius: 12px; border: 1px solid #334155; }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>سلام! به پنل مدیریت X4G Gateway خوش آمدید 🚀</h1>
            <p>سرویس شما با موفقیت و بدون ارور در حال اجراست.</p>
        </div>
    </body>
    </html>
    """)

@app.websocket("/relay")
async def websocket_relay(websocket: WebSocket, target_host: str = "127.0.0.1", target_port: int = 80):
    from relay_vless import handle_relay_vless
    await handle_relay_vless(websocket, target_host, target_port)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], reload=False)
