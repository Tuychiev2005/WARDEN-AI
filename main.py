import json
import asyncio
import socket
import sys
import logging
import os
import time
from pathlib import Path
from collections import defaultdict
 
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import CallbackQuery, Message, InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
 
import uvicorn
from fastapi import FastAPI, Form, WebSocket, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
 
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from telethon.tl.functions.account import GetPasswordRequest
 
import httpx
 
from security import analyze_message
from database import (
    create_user, get_user, update_session, save_alert_db,
    save_phone_code_hash,
    get_alerts, delete_old_alerts,
    get_whitelist, add_whitelist, remove_whitelist,
    get_db,
)
 
# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN            = os.getenv("BOT_TOKEN", "8694458387:AAFhaHAVLRfjutysQxXjG9EF_6_Huh8QMWA")
SECRET_KEY           = os.getenv("SECRET_KEY", "change-me-in-production-32 chars!!")
APP_PORT             = 8000
ALERT_RETENTION_DAYS = 30
WATCHDOG_INTERVAL    = 30
RATE_LIMIT_REQUESTS  = 5
RATE_LIMIT_WINDOW    = 60
 
# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("warden.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)
 
# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=86400,
    https_only=False,   # обязательно для HTTP
    same_site="lax",
)
 
BASE_DIR     = Path(__file__).resolve().parent
 
# ── FIX 1: Bot создаётся только если токен задан, иначе краш при старте ──────
bot: Bot | None = Bot(token=BOT_TOKEN) if BOT_TOKEN else None
dp           = Dispatcher()
active_ws    : set[WebSocket] = set()
clients         : dict[int, TelegramClient] = {}   # ключи ВСЕГДА int
_rate_store     : dict[str, list[float]] = defaultdict(list)
_2fa_pending    : dict[int, tuple] = {}
_pending_clients: dict[int, TelegramClient] = {}   # клиенты ожидающие ввода кода
 
 
# ── Exception handlers ────────────────────────────────────────────────────────
 
@app.exception_handler(Exception)
async def global_exc(request: Request, exc: Exception):
    log.error(f"Unhandled: {request.url} → {exc}", exc_info=True)
    return HTMLResponse(_tpl("Something went wrong", str(exc), back=True), status_code=500)
 
@app.exception_handler(404)
async def not_found(request: Request, exc: Exception):
    return RedirectResponse("/", status_code=302)
 
 
# ── Helpers ───────────────────────────────────────────────────────────────────
 
def find_open_port(start=8000, end=8100) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port)); return port
            except OSError:
                pass
    raise RuntimeError("No free port")
 
 
async def get_public_url(port=None) -> str:
    if port is None: port = APP_PORT
    async with httpx.AsyncClient(timeout=2) as c:
        for _ in range(5):
            try:
                r = await c.get("http://127.0.0.1:4040/api/tunnels")
                for t in r.json().get("tunnels", []):
                    if t.get("proto") == "https": return t["public_url"]
            except Exception: pass
            await asyncio.sleep(1)
    return f"http://127.0.0.1:{port}"
 
 
def _rate_ok(key: str) -> bool:
    now = time.time()
    _rate_store[key] = [t for t in _rate_store[key] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_store[key]) >= RATE_LIMIT_REQUESTS: return False
    _rate_store[key].append(now); return True
 
 
def _ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")
 
 
def _make_client(user_id: int, api_id: int, api_hash: str) -> TelegramClient:
    """Файловая сессия — только для восстановления уже авторизованных клиентов."""
    return TelegramClient(str(BASE_DIR / f"user_{user_id}"), api_id, api_hash)
 
 
def _make_auth_client(api_id: int, api_hash: str) -> TelegramClient:
    """StringSession — для авторизации. Каждый раз чистое соединение, без старых файлов."""
    return TelegramClient(
        StringSession(), api_id, api_hash,
        device_model="Desktop",
        system_version="Windows 10",
        app_version="1.0",
        lang_code="en",
        system_lang_code="en-US",
    )
 
 
# ── FIX 2: session хранит uid как str — всегда приводим к int ────────────────
def _get_uid(session) -> int | None:
    """
    SessionMiddleware сериализует значения в JSON — int превращается в str
    при некоторых конфигурациях. Приводим к int всегда.
    """
    uid = session.get("user_id")
    if uid is None:
        return None
    try:
        return int(uid)
    except (ValueError, TypeError):
        return None
 
 
def _js_redirect(url: str) -> HTMLResponse:
    """
    JS redirect вместо HTTP 303.
    Гарантирует что Set-Cookie сохранится в браузере до перехода.
    """
    return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{{background:#04060e;display:flex;align-items:center;justify-content:center;
height:100vh;margin:0;font-family:sans-serif;color:#22c55e;font-size:15px}}</style>
</head><body><div>Connecting to dashboard...</div>
<script>window.location.replace("{url}");</script>
</body></html>""")
 
 
async def _register_handler(client: TelegramClient, user_id: int) -> None:
    whitelist = set(get_whitelist(user_id))
 
    @client.on(events.NewMessage)
    async def handler(event):
        try:
            if event.sender_id in whitelist: return
            text = event.raw_text or ""

            # Fetch sender info for spam tracking in alerts
            sender_username = ""
            sender_name = ""
            try:
                sender = await event.get_sender()
                if sender:
                    sender_username = getattr(sender, "username", "") or ""
                    first = getattr(sender, "first_name", "") or ""
                    last  = getattr(sender, "last_name",  "") or ""
                    sender_name = (first + " " + last).strip()
            except Exception:
                pass

            result = analyze_message(
                event.sender_id, text, user_id=user_id,
                sender_username=sender_username, sender_name=sender_name,
            )
            if result.get("detected"):
                result["message"] = text
                await broadcast(user_id, result)
        except Exception as e:
            log.error(f"Handler error user={user_id}: {e}")
 
 
async def _finish_login(client: TelegramClient, user_id: int) -> None:
    update_session(user_id, client.session.save())
    try:
        me = await client.get_me()
        if me:
            db = get_db()
            db.execute("UPDATE users SET telegram_id=? WHERE id=?", (me.id, user_id))
            db.commit()
            log.info(f"User {user_id} → tg_id={me.id} name={me.first_name}")
    except Exception as e:
        log.warning(f"get_me failed: {e}")
 
    await _register_handler(client, user_id)
    clients[user_id] = client  # ключ всегда int
    asyncio.create_task(client.run_until_disconnected())
    log.info(f"User {user_id} authenticated and running")
 
 
async def broadcast(user_id: int, alert: dict) -> None:
    save_alert_db(user_id, alert)
    dead: set[WebSocket] = set()
    for ws in list(active_ws):
        try:
            await ws.send_text(json.dumps(alert))
        except Exception:
            dead.add(ws)
    active_ws.difference_update(dead)
 
    try:
        db = get_db()
        row = db.execute("SELECT telegram_id FROM users WHERE id=?", (user_id,)).fetchone()
        if row and row[0]:
            await _bot_notify(row[0], alert)
    except Exception as e:
        log.error(f"notify error: {e}")
 
 
async def _bot_notify(tg_id: int, alert: dict) -> None:
    if not bot:
        return
    try:
        emoji = {"SCAM": "🚫", "PHISHING": "🎣", "FLOOD": "💬"}.get(alert.get("type", ""), "⚠️")
        risk  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(alert.get("risk", ""), "")
        text  = f"{emoji} *{alert.get('type')} Detected*\n{risk} Risk: *{alert.get('risk')}*\nReason: `{alert.get('reason')}`"
        if alert.get("message"):
            text += f"\n\n`{alert['message'][:100].replace('`', chr(39))}`"
        await bot.send_message(tg_id, text, parse_mode="Markdown")
    except Exception as e:
        log.warning(f"bot_notify failed tg_id={tg_id}: {e}")
 
 
# ── Account API ───────────────────────────────────────────────────────────────
 
@app.get("/api/account")
async def api_account(request: Request):
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401, "Not authenticated")
    client = clients.get(uid)
    if not client or not client.is_connected():
        return JSONResponse({"error": "userbot_not_connected"}, status_code=503)
    try:
        me = await client.get_me()
        pwd = await client(GetPasswordRequest())
        return {
            "id":         me.id,
            "first_name": me.first_name or "",
            "last_name":  me.last_name  or "",
            "username":   me.username   or "",
            "phone":      me.phone      or "",
            "has_2fa":    pwd.has_password,
            "connected":  True,
        }
    except Exception as e:
        log.error(f"api_account error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/stats")
async def api_stats(request: Request, days: int = Query(7, ge=1, le=30)):
    """Returns per-day threat counts for the last N days (for analytics chart)."""
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401, "Not authenticated")
    db = get_db()
    rows = db.execute(
        """
        SELECT date(created_at) as day,
               type,
               COUNT(*) as cnt
        FROM alerts
        WHERE user_id = ?
          AND created_at >= datetime('now', ?)
        GROUP BY day, type
        ORDER BY day ASC
        """,
        (uid, f"-{days} days"),
    ).fetchall()

    # Build {date: {type: count}} structure
    from collections import defaultdict
    day_map: dict = defaultdict(lambda: defaultdict(int))
    for row in rows:
        day_map[row["day"]][row["type"]] += row["cnt"]

    # Also return top spammers from alerts table
    spammers = db.execute(
        """
        SELECT sender_id, sender_username, sender_name,
               COUNT(*) as hits
        FROM alerts
        WHERE user_id = ?
          AND sender_id IS NOT NULL AND sender_id != 0
          AND created_at >= datetime('now', ?)
        GROUP BY sender_id
        ORDER BY hits DESC
        LIMIT 10
        """,
        (uid, f"-{days} days"),
    ).fetchall()

    return {
        "days": days,
        "by_day": {day: dict(types) for day, types in sorted(day_map.items())},
        "top_spammers": [dict(r) for r in spammers],
    }


@app.post("/api/enable_2fa")
async def api_enable_2fa(request: Request):
    """
    Attempts to set a 2FA password via Telethon if none is set.
    Returns instructions or success.
    """
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401, "Not authenticated")

    body = await request.json()
    new_password = body.get("password", "").strip()
    hint         = body.get("hint", "Warden 2FA").strip()

    if not new_password or len(new_password) < 6:
        return JSONResponse({"error": "Password must be at least 6 characters."}, status_code=400)

    client = clients.get(uid)
    if not client or not client.is_connected():
        return JSONResponse({"error": "userbot_not_connected"}, status_code=503)

    try:
        from telethon.tl.functions.account import UpdatePasswordSettingsRequest
        from telethon.tl.types import account  # noqa
        pwd_info = await client(GetPasswordRequest())
        if pwd_info.has_password:
            return JSONResponse({"ok": False, "message": "2FA is already enabled."})

        # Use Telethon's built-in helper
        await client.edit_2fa(new_password=new_password, hint=hint)
        log.info(f"2FA enabled via API for user={uid}")
        return JSONResponse({"ok": True, "message": "2FA has been enabled successfully."})
    except Exception as e:
        log.error(f"enable_2fa error user={uid}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
 
 
# ── Watchdog ──────────────────────────────────────────────────────────────────
 
async def watchdog():
    while True:
        await asyncio.sleep(WATCHDOG_INTERVAL)
        for user_id, client in list(clients.items()):
            try:
                if not client.is_connected():
                    log.warning(f"Watchdog: reconnecting user {user_id}")
                    user = get_user(user_id)
                    if not user: continue
                    nc = _make_client(user_id, int(user["api_id"]), user["api_hash"])
                    await asyncio.wait_for(nc.connect(), timeout=15)
                    if await nc.is_user_authorized():
                        await _register_handler(nc, user_id)
                        clients[user_id] = nc
                        asyncio.create_task(nc.run_until_disconnected())
                        log.info(f"Watchdog: user {user_id} reconnected")
                    else:
                        await nc.disconnect()
            except Exception as e:
                log.error(f"Watchdog error user={user_id}: {e}")
 
 
async def cleanup_task():
    while True:
        await asyncio.sleep(86400)
        try:
            n = delete_old_alerts(ALERT_RETENTION_DAYS)
            log.info(f"Cleanup: deleted {n} old alerts")
        except Exception as e:
            log.error(f"Cleanup error: {e}")
 
 
# ── Bot ───────────────────────────────────────────────────────────────────────
 
@dp.message(Command("start"))
async def bot_start(message: Message):
    try:
        web_url = await get_public_url()
 
        kb = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="Connect Warden 🛡",
                        web_app=WebAppInfo(
                            url=f"{web_url}/index"
                        )
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="📘 Инструкция",
                        web_app=WebAppInfo(
                            url=f"{web_url}/help"
                        )
                    )
                ]
            ]
        )
 
        await message.answer("🛡 Орден WARDEN пробуждён…\n\nДобро пожаловать, путник.\n\nВы вошли в кибернетический щит, созданный для защиты цифрового королевства Telegram.\n\nКаждое действие будет записано.\nКаждая угроза будет выявлена.\nКаждая аномалия — нейтрализована.\n\n🤖 WARDEN AI уже наблюдает за системой…\n\nЧтобы получить больше функционала подключите Warden", reply_markup=kb)
 
    except Exception as e:
        log.error(f"bot_start: {e}")
        await message.answer(
            "🛡 Warden Security System\n\n"
            "Server is starting, try again."
        )
 

 
# ── Pages ─────────────────────────────────────────────────────────────────────
 
@app.get("/index")
async def home(request: Request):
    uid = _get_uid(request.session)
    if uid and uid in clients:
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse((BASE_DIR / "index.html").read_text(encoding="utf-8"))
 
 
@app.get("/start")
async def start_page(request: Request):
    uid = _get_uid(request.session)
    if uid and uid in clients:
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse((BASE_DIR / "start.html").read_text(encoding="utf-8"))
 
@app.get("/help")
async def help_page(request: Request):
    return HTMLResponse((BASE_DIR / "help.html").read_text(encoding="utf-8"))
 
@app.get("/dashboard")
async def dashboard(request: Request):
    uid = _get_uid(request.session)
    log.info(f"Dashboard request: uid={uid}, active clients={list(clients.keys())}")
    if not uid:
        log.warning("dashboard: no user_id in session → redirect /start")
        return RedirectResponse("/start", status_code=302)
    return HTMLResponse((BASE_DIR / "dashboard.html").read_text(encoding="utf-8"))
 
 
@app.get("/status")
async def status(request: Request):
    uid = _get_uid(request.session)
    if not uid: return {"status": "not_logged_in"}
    connected = uid in clients and clients[uid].is_connected()
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM alerts WHERE user_id=?", (uid,)).fetchone()[0]
    return {"status": "logged_in", "userbot_connected": connected, "alerts_count": count}
 
 
@app.get("/api/alerts")
async def api_alerts(
    request: Request,
    limit:  int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    type:   str = Query(None),
):
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401, "Not authenticated")
    return JSONResponse({"alerts": get_alerts(uid, limit=limit, offset=offset, alert_type=type)})
 
 
@app.get("/api/whitelist")
async def api_whitelist_get(request: Request):
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401)
    return {"whitelist": get_whitelist(uid)}
 
@app.post("/api/whitelist")
async def api_whitelist_add(request: Request, sender_id: int = Form(...)):
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401)
    add_whitelist(uid, sender_id); return {"ok": True}
 
@app.delete("/api/whitelist/{sender_id}")
async def api_whitelist_remove(request: Request, sender_id: int):
    uid = _get_uid(request.session)
    if not uid: raise HTTPException(401)
    remove_whitelist(uid, sender_id); return {"ok": True}
 
 
# ── Auth ──────────────────────────────────────────────────────────────────────
 
@app.post("/connect")
async def connect(api_id: str = Form(...), api_hash: str = Form(...), request: Request = None):
    if not _rate_ok(f"connect:{_ip(request)}"):
        return _err_page("Too many requests. Wait a minute.")
    api_id = api_id.strip()
    api_hash = api_hash.strip()
    if not api_id.isdigit() or len(api_hash) < 8:
        return _err_page("Invalid API ID or API HASH")
    user_id = create_user(api_id, api_hash)
    request.session["user_id"] = user_id  # сохраняем как int
    log.info(f"Session set at /connect: user_id={user_id}")
    html = (BASE_DIR / "phone.html").read_text(encoding="utf-8")
    return HTMLResponse(html.replace("{{ user_id }}", str(user_id)))
 
 
@app.post("/send_code")
async def send_code(phone: str = Form(...), user_id: int = Form(...), request: Request = None):
    if not _rate_ok(f"code:{_ip(request)}"):
        return _err_page("Too many requests. Wait a minute.")
    user = get_user(user_id)
    if not user: return _err_page("User not found. Start again.")
 
    phone = phone.strip()
    log.info(f"[send_code] user_id={user_id} phone={phone}")
 
    # Закрываем старый pending клиент если есть
    old_client = _pending_clients.pop(user_id, None)
    if old_client:
        try: await old_client.disconnect()
        except Exception: pass
 
    client = _make_auth_client(int(user["api_id"]), user["api_hash"])
    try:
        log.info(f"[send_code] Connecting to Telegram...")
        await asyncio.wait_for(client.connect(), timeout=20)
        log.info(f"[send_code] Connected. Sending code to {phone}...")
 
        sent = await asyncio.wait_for(
            client.send_code_request(phone),
            timeout=30
        )
 
        log.info(
            f"[send_code] Code sent OK! "
            f"phone_code_hash={sent.phone_code_hash[:8]}... "
            f"type={type(sent).__name__}"
        )
 
    except asyncio.TimeoutError:
        log.error(f"[send_code] Timeout for user={user_id}")
        try: await client.disconnect()
        except Exception: pass
        return _err_page("Connection timeout. Try again.")
    except errors.PhoneNumberInvalidError:
        log.error(f"[send_code] PhoneNumberInvalidError: {phone}")
        try: await client.disconnect()
        except Exception: pass
        return _err_page("Phone number is invalid. Include country code (e.g. +998...).")
    except errors.PhoneNumberBannedError:
        log.error(f"[send_code] PhoneNumberBannedError: {phone}")
        try: await client.disconnect()
        except Exception: pass
        return _err_page("This phone number is banned by Telegram.")
    except errors.FloodWaitError as e:
        log.warning(f"[send_code] FloodWaitError: wait {e.seconds}s for user={user_id}")
        try: await client.disconnect()
        except Exception: pass
        return _err_page(f"Too many attempts. Telegram says: wait {e.seconds} seconds.")
    except errors.ApiIdInvalidError:
        log.error(f"[send_code] ApiIdInvalidError for user={user_id}")
        try: await client.disconnect()
        except Exception: pass
        return _err_page("Invalid API ID or API HASH. Please check your credentials at my.telegram.org.")
    except Exception as e:
        log.error(f"[send_code] Unexpected error user={user_id}: {type(e).__name__}: {e}", exc_info=True)
        try: await client.disconnect()
        except Exception: pass
        return _err_page(f"Failed to send code: {type(e).__name__}: {e}")
 
    # Сохраняем клиент — НЕ отключаем, иначе phone_code_hash протухнет
    _pending_clients[user_id] = client
    save_phone_code_hash(user_id, phone, sent.phone_code_hash)
    request.session["user_id"] = user_id
    log.info(f"[send_code] Session saved, redirecting to verify. user_id={user_id}")
 
    html = (BASE_DIR / "verify.html").read_text(encoding="utf-8")
    html = (html
        .replace("{{ phone }}", phone)
        .replace("{{ user_id }}", str(user_id))
        .replace("{{ phone_code_hash }}", sent.phone_code_hash))
    return HTMLResponse(html)
 
 
@app.post("/verify")
async def verify(
    code: str = Form(...), phone: str = Form(...),
    user_id: int = Form(...), phone_code_hash: str = Form(...),
    request: Request = None,
):
    if not _rate_ok(f"verify:{_ip(request)}"):
        return _err_page("Too many requests. Wait a minute.")
    user = get_user(user_id)
    if not user: return _err_page("User not found. Start again.")
    # Используем уже подключённый клиент из /send_code
    client = _pending_clients.pop(user_id, None)
    if client is None or not client.is_connected():
        # Фоллбэк: создаём новый клиент если pending истёк
        if client:
            try: await client.disconnect()
            except Exception: pass
        client = _make_auth_client(int(user["api_id"]), user["api_hash"])
        try:
            await asyncio.wait_for(client.connect(), timeout=15)
        except asyncio.TimeoutError:
            await client.disconnect(); return _err_page("Connection timeout.")
    try:
        await client.sign_in(phone, code, phone_code_hash=phone_code_hash)
 
    except errors.SessionPasswordNeededError:
        _2fa_pending[user_id] = (client, phone)
        request.session["user_id"] = user_id
        html = (BASE_DIR / "Twofa.html").read_text(encoding="utf-8")
        return HTMLResponse(html.replace("{{ user_id }}", str(user_id)))
 
    except asyncio.TimeoutError:
        await client.disconnect(); return _err_page("Connection timeout.")
    except errors.PhoneCodeExpiredError:
        await client.disconnect(); return _resend_page(phone, user_id)
    except errors.PhoneCodeInvalidError:
        await client.disconnect(); return _err_page("Invalid code. Please try again.")
    except Exception as e:
        await client.disconnect(); return _err_page(f"Login failed: {e}")
 
    request.session["user_id"] = user_id
    log.info(f"Session set at /verify: user_id={user_id}")
    await _finish_login(client, user_id)
    return _js_redirect("/dashboard")
 
 
@app.post("/verify_2fa")
async def verify_2fa(password: str = Form(...), user_id: int = Form(...), request: Request = None):
    if not _rate_ok(f"2fa:{_ip(request)}"):
        return _err_page("Too many requests.")
    if user_id not in _2fa_pending:
        return _err_page("Session expired. Please start again.")
 
    client, phone = _2fa_pending.pop(user_id)
    try:
        await client.sign_in(password=password)
    except errors.PasswordHashInvalidError:
        await client.disconnect()
        return _err_page("Wrong 2FA password.")
    except Exception as e:
        await client.disconnect()
        return _err_page(f"2FA failed: {e}")
 
    request.session["user_id"] = user_id
    log.info(f"Session set at /verify_2fa: user_id={user_id}")
    await _finish_login(client, user_id)
    return _js_redirect("/dashboard")
 
 
@app.post("/logout")
async def logout(request: Request):
    uid = _get_uid(request.session)
    request.session.clear()
    if uid and uid in clients:
        try: await clients[uid].disconnect()
        except Exception: pass
        del clients[uid]
    return RedirectResponse("/start", status_code=302)
 
 
# ── WebSocket ─────────────────────────────────────────────────────────────────
 
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_ws.add(websocket)
    log.info(f"WS+ total={len(active_ws)}")
 
    # ── FIX 3: WebSocket не имеет .session из SessionMiddleware ───────────────
    # Читаем session вручную из cookies через itsdangerous (тот же механизм)
    uid = None
    try:
        from itsdangerous import TimestampSigner, BadSignature
        from itsdangerous.exc import SignatureExpired
        import base64, json as _json
 
        cookie = websocket.cookies.get("session")
        if cookie:
            try:
                signer = TimestampSigner(SECRET_KEY)
                data = signer.unsign(cookie, max_age=86400)
                payload = _json.loads(base64.b64decode(data))
                uid = int(payload.get("user_id")) if payload.get("user_id") else None
            except Exception as e:
                log.warning(f"WS session decode failed: {e}")
    except ImportError:
        log.warning("itsdangerous not available for WS session")
 
    log.info(f"WS session uid={uid}")
 
    if uid:
        try:
            for alert in reversed(get_alerts(uid, limit=50)):
                await websocket.send_text(json.dumps({**alert, "_history": True}))
        except Exception as e:
            log.warning(f"WS history error: {e}")
 
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except Exception:
        pass
    finally:
        active_ws.discard(websocket)
        log.info(f"WS- total={len(active_ws)}")
 
 
# ── Startup ───────────────────────────────────────────────────────────────────
 
async def load_clients():
    db = get_db()
    rows = db.execute(
        "SELECT id, api_id, api_hash, session FROM users WHERE session IS NOT NULL AND session != ''"
    ).fetchall()
    for user_id, api_id, api_hash, session_str in rows:
        client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
        try:
            await asyncio.wait_for(client.connect(), timeout=15)
            if await client.is_user_authorized():
                await _register_handler(client, user_id)
                clients[user_id] = client  # int key
                asyncio.create_task(client.run_until_disconnected())
                log.info(f"Restored client user={user_id}")
            else:
                await client.disconnect()
        except Exception as e:
            log.error(f"Load client user={user_id}: {e}")
            try: await client.disconnect()
            except Exception: pass
 
 
async def start_bot():
    if not bot:
        log.warning("BOT_TOKEN not set — bot disabled")
        return
    try:
        log.info("Starting bot...")
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot, handle_signals=False, allowed_updates=["message", "callback_query"])
    except Exception as e:
        log.error(f"Bot error: {e}")
 
 
# ── HTML helpers ──────────────────────────────────────────────────────────────
 
def _tpl(title: str, msg: str, back: bool = True) -> str:
    btn = '<button onclick="window.history.back()" style="padding:12px 28px;border:none;border-radius:12px;background:#22c55e;color:#04060e;cursor:pointer;font-weight:700;font-size:14px;">Go Back</button>' if back else ""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#04060e;color:#e2e8f0;font-family:'Syne',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}}.box{{text-align:center;max-width:400px;padding:48px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:24px}}h2{{font-size:24px;color:#ef4444;margin-bottom:12px}}p{{color:#64748b;margin-bottom:24px;line-height:1.5}}</style>
</head><body><div class="box"><h2>{title}</h2><p>{msg}</p>{btn}</div></body></html>"""
 
 
def _err_page(msg: str, back: bool = True) -> HTMLResponse:
    return HTMLResponse(_tpl("Error", msg, back))
 
 
def _resend_page(phone: str, user_id: int) -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#04060e;color:#e2e8f0;font-family:'Syne',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}}.box{{text-align:center;max-width:400px;padding:48px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:24px}}h2{{font-size:24px;color:#f59e0b;margin-bottom:12px}}p{{color:#64748b;margin-bottom:24px}}.btn{{padding:14px 28px;border:none;border-radius:12px;background:#22c55e;color:#04060e;cursor:pointer;font-weight:700;font-size:14px}}</style>
</head><body><div class="box"><h2>Code Expired</h2><p>The code has expired. Request a new one.</p>
<form method="post" action="/send_code"><input type="hidden" name="phone" value="{phone}"><input type="hidden" name="user_id" value="{user_id}"><button class="btn" type="submit">Send New Code</button></form></div></body></html>""")
 
 
# ── Main ──────────────────────────────────────────────────────────────────────
 
async def main():
    global APP_PORT
    APP_PORT = find_open_port()
    log.info(f"Starting Warden on port {APP_PORT}")
    await load_clients()
    asyncio.create_task(start_bot())
    asyncio.create_task(watchdog())
    asyncio.create_task(cleanup_task())
    config = uvicorn.Config(app, host="0.0.0.0", port=APP_PORT, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
 
 
if __name__ == "__main__":
    asyncio.run(main())