import sqlite3
import threading
import logging
from pathlib import Path
 
log = logging.getLogger(__name__)
 
DB_PATH = Path(__file__).resolve().parent / "database.db"
_local  = threading.local()
 
 
def get_db() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _init_schema(_local.conn)
    return _local.conn
 
 
def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            api_id          TEXT,
            api_hash        TEXT,
            phone           TEXT,
            phone_code_hash TEXT,
            session         TEXT,
            telegram_id     INTEGER DEFAULT 0,
            created_at      TEXT    DEFAULT (datetime('now'))
        );
 
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER,
            type            TEXT,
            risk            TEXT,
            reason          TEXT,
            message         TEXT,
            sender_id       INTEGER DEFAULT 0,
            sender_username TEXT    DEFAULT '',
            sender_name     TEXT    DEFAULT '',
            created_at      TEXT    DEFAULT (datetime('now'))
        );
 
        CREATE TABLE IF NOT EXISTS whitelist (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            sender_id INTEGER,
            UNIQUE(user_id, sender_id)
        );
    """)
    # migrations для старых БД
    for col, definition in [
        ("phone_code_hash", "TEXT"),
        ("telegram_id",     "INTEGER DEFAULT 0"),
        ("created_at",      "TEXT DEFAULT (datetime('now'))"),
    ]:
        try:
            conn.execute(f"SELECT {col} FROM users LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
    # alerts migrations
    for col, definition in [
        ("sender_id",       "INTEGER DEFAULT 0"),
        ("sender_username", "TEXT DEFAULT ''"),
        ("sender_name",     "TEXT DEFAULT ''"),
    ]:
        try:
            conn.execute(f"SELECT {col} FROM alerts LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {definition}")
    conn.commit()
    log.info("Database schema ready")
 
 
# ── Users ─────────────────────────────────────────────────────────────────────
 
def create_user(api_id: str, api_hash: str) -> int:
    db = get_db()
    cur = db.execute("INSERT INTO users(api_id, api_hash) VALUES (?, ?)", (api_id, api_hash))
    db.commit()
    log.info(f"Created user id={cur.lastrowid}")
    return cur.lastrowid
 
 
def get_user(user_id: int) -> dict | None:
    """Возвращает dict с именованными ключами — индексы не сдвигаются никогда."""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None
 
 
def update_session(user_id: int, session: str) -> None:
    db = get_db()
    db.execute("UPDATE users SET session=? WHERE id=?", (session, user_id))
    db.commit()
 
 
def save_phone_code_hash(user_id: int, phone: str, phone_code_hash: str) -> None:
    db = get_db()
    db.execute(
        "UPDATE users SET phone=?, phone_code_hash=? WHERE id=?",
        (phone, phone_code_hash, user_id)
    )
    db.commit()
 
 
def save_telegram_id(user_id: int, telegram_id: int) -> None:
    db = get_db()
    db.execute("UPDATE users SET telegram_id=? WHERE id=?", (telegram_id, user_id))
    db.commit()
 
 
# ── Alerts ────────────────────────────────────────────────────────────────────
 
def save_alert_db(user_id: int, alert: dict) -> None:
    db = get_db()
    db.execute(
        """INSERT INTO alerts
           (user_id, type, risk, reason, message, sender_id, sender_username, sender_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id,
            alert.get("type"),
            alert.get("risk"),
            alert.get("reason"),
            alert.get("message", ""),
            alert.get("sender_id", 0),
            alert.get("sender_username", ""),
            alert.get("sender_name", ""),
        ),
    )
    db.commit()
 
 
def get_alerts(user_id: int, limit: int = 50, offset: int = 0, alert_type: str = None) -> list:
    db = get_db()
    if alert_type:
        rows = db.execute(
            "SELECT * FROM alerts WHERE user_id=? AND type=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (user_id, alert_type, limit, offset),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]
 
 
def delete_old_alerts(days: int) -> int:
    db = get_db()
    cur = db.execute(
        "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
        (f"-{days} days",),
    )
    db.commit()
    return cur.rowcount
 
 
# ── Whitelist ─────────────────────────────────────────────────────────────────
 
def get_whitelist(user_id: int) -> list[int]:
    db = get_db()
    rows = db.execute("SELECT sender_id FROM whitelist WHERE user_id=?", (user_id,)).fetchall()
    return [r[0] for r in rows]
 
 
def add_whitelist(user_id: int, sender_id: int) -> None:
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO whitelist(user_id, sender_id) VALUES (?, ?)",
        (user_id, sender_id)
    )
    db.commit()
 
 
def remove_whitelist(user_id: int, sender_id: int) -> None:
    db = get_db()
    db.execute(
        "DELETE FROM whitelist WHERE user_id=? AND sender_id=?",
        (user_id, sender_id)
    )
    db.commit()