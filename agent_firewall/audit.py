"""SQLite audit log + approval queue. Shared by the proxy process and the dashboard process (WAL mode)."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    session_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,          -- tool_call | tool_result | session
    server      TEXT,
    tool        TEXT,
    decision    TEXT NOT NULL,          -- allow | block | approval_required | approved | denied | sanitized | blocked_output | pass
    risk        TEXT,
    taint       TEXT,
    reason      TEXT,
    detail      TEXT                    -- JSON: args, detector verdict, etc.
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    session_id  TEXT NOT NULL,
    server      TEXT,
    tool        TEXT NOT NULL,
    args        TEXT,
    risk        TEXT,
    taint       TEXT,
    reason      TEXT,
    context     TEXT,                   -- JSON: taint sources, flagged snippets
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | denied | expired
    decided_at  REAL,
    decided_by  TEXT
);
"""


class AuditLog:
    def __init__(self, db_path: str | Path = "agent_firewall.db"):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    # ---- events ------------------------------------------------------------------------

    def log(self, *, session_id: str, kind: str, decision: str, server: str | None = None, tool: str | None = None,
            risk: str | None = None, taint: str | None = None, reason: str | None = None, detail: dict | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, session_id, kind, server, tool, decision, risk, taint, reason, detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), session_id, kind, server, tool, decision, risk, taint, reason, _dumps(detail)),
            )
            return int(cur.lastrowid)

    def events(self, limit: int = 200, session_id: str | None = None) -> list[dict]:
        q, p = "SELECT * FROM events", []
        if session_id:
            q, p = q + " WHERE session_id = ?", [session_id]
        q += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(q, [*p, limit]).fetchall()
        return [_row(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT decision, COUNT(*) AS n FROM events GROUP BY decision").fetchall()
            pending = self._conn.execute("SELECT COUNT(*) FROM approvals WHERE status='pending'").fetchone()[0]
        return {"by_decision": {r["decision"]: r["n"] for r in rows}, "pending_approvals": pending}

    # ---- approvals ---------------------------------------------------------------------

    def create_approval(self, *, session_id: str, server: str | None, tool: str, args: dict, risk: str, taint: str,
                        reason: str, context: dict | None = None) -> str:
        aid = uuid.uuid4().hex[:12]
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals (id, ts, session_id, server, tool, args, risk, taint, reason, context) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (aid, time.time(), session_id, server, tool, _dumps(args), risk, taint, reason, _dumps(context)),
            )
        return aid

    def approval_status(self, aid: str) -> str | None:
        with self._lock:
            r = self._conn.execute("SELECT status FROM approvals WHERE id = ?", (aid,)).fetchone()
        return r["status"] if r else None

    def decide(self, aid: str, approve: bool, by: str = "dashboard") -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'",
                ("approved" if approve else "denied", time.time(), by, aid),
            )
            return cur.rowcount == 1

    def expire(self, aid: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE approvals SET status='expired', decided_at=? WHERE id=? AND status='pending'", (time.time(), aid))

    def approvals(self, status: str | None = None, limit: int = 100) -> list[dict]:
        q, p = "SELECT * FROM approvals", []
        if status:
            q, p = q + " WHERE status = ?", [status]
        q += " ORDER BY ts DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(q, [*p, limit]).fetchall()
        return [_row(r) for r in rows]


def _dumps(obj) -> str | None:
    if obj is None:
        return None
    s = json.dumps(obj, default=str, ensure_ascii=False)
    return s if len(s) < 20000 else s[:20000] + "...(truncated)"


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    for k in ("detail", "args", "context"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except (ValueError, TypeError):
                pass
    return d
