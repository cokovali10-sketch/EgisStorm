import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "history.db")
MAX_ROWS = 1000


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            tool TEXT NOT NULL,
            query TEXT,
            summary TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def log_history(tool, query, summary=None):
    try:
        conn = _connect()
        conn.execute(
            "INSERT INTO history (ts, tool, query, summary) VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(timespec="seconds"), tool, query, summary),
        )
        conn.execute(
            "DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT ?)",
            (MAX_ROWS,),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def get_history(limit=50):
    conn = _connect()
    rows = conn.execute(
        "SELECT ts, tool, query, summary FROM history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]