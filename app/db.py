"""SQLite storage for scan jobs and the consent audit log.

The audit log stores input *types* and tools run, never passwords or other
secrets. Job rows keep the identifiers the student typed so the on-screen
report and PDF can be regenerated; those rows live only on localhost.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_db_path: Path | None = None

ISO = "%Y-%m-%dT%H:%M:%S%z"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_db_path() -> Path:
    root = Path(__file__).resolve().parent.parent
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    return data / "footprint.db"


def init_db(path: str | Path | None = None) -> Path:
    """Create tables if needed and return the database path."""
    global _db_path
    _db_path = Path(path) if path else default_db_path()
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = _connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    inputs_json TEXT NOT NULL,
                    consent INTEGER NOT NULL,
                    tools_json TEXT,
                    progress_json TEXT,
                    findings_json TEXT,
                    score INTEGER,
                    score_breakdown_json TEXT,
                    remediation_json TEXT,
                    confidence_notes_json TEXT,
                    ai_summary TEXT,
                    ai_status TEXT,
                    error TEXT,
                    is_demo INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    job_id TEXT,
                    input_types TEXT NOT NULL,
                    consent INTEGER NOT NULL,
                    tools_run TEXT,
                    is_demo INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS rate_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()
    return _db_path


def _connect() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("init_db() must be called before using the database")
    conn = sqlite3.connect(str(_db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _dumps(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def _loads(value: str | None, default: Any = None) -> Any:
    if value is None or value == "":
        return default
    return json.loads(value)


def create_job(
    job_id: str,
    inputs: dict,
    consent: bool,
    is_demo: bool = False,
    status: str = "queued",
) -> dict:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO jobs (
                    id, created_at, status, inputs_json, consent,
                    tools_json, progress_json, findings_json, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    now,
                    status,
                    _dumps(inputs),
                    1 if consent else 0,
                    _dumps({}),
                    _dumps({}),
                    _dumps([]),
                    1 if is_demo else 0,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return get_job(job_id)


def update_job(job_id: str, **fields: Any) -> None:
    allowed = {
        "status",
        "tools_json",
        "progress_json",
        "findings_json",
        "score",
        "score_breakdown_json",
        "remediation_json",
        "confidence_notes_json",
        "ai_summary",
        "ai_status",
        "error",
        "is_demo",
        "inputs_json",
        "consent",
    }
    json_fields = {
        "tools_json",
        "progress_json",
        "findings_json",
        "score_breakdown_json",
        "remediation_json",
        "confidence_notes_json",
        "inputs_json",
    }
    # Callers may pass the decoded objects with shorter names.
    aliases = {
        "tools": "tools_json",
        "progress": "progress_json",
        "findings": "findings_json",
        "score_breakdown": "score_breakdown_json",
        "remediation": "remediation_json",
        "confidence_notes": "confidence_notes_json",
        "inputs": "inputs_json",
    }
    normalized: dict[str, Any] = {}
    for key, value in fields.items():
        key = aliases.get(key, key)
        if key not in allowed:
            raise ValueError(f"Cannot update job field {key!r}")
        if key in json_fields and not isinstance(value, str):
            value = _dumps(value)
        if key == "consent":
            value = 1 if value else 0
        if key == "is_demo":
            value = 1 if value else 0
        normalized[key] = value
    if not normalized:
        return
    assignments = ", ".join(f"{k} = ?" for k in normalized)
    values = list(normalized.values()) + [job_id]
    with _lock:
        conn = _connect()
        try:
            conn.execute(f"UPDATE jobs SET {assignments} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()


def get_job(job_id: str) -> dict | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        finally:
            conn.close()
    if row is None:
        return None
    return _job_from_row(row)


def _job_from_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "status": row["status"],
        "inputs": _loads(row["inputs_json"], {}),
        "consent": bool(row["consent"]),
        "tools": _loads(row["tools_json"], {}),
        "progress": _loads(row["progress_json"], {}),
        "findings": _loads(row["findings_json"], []),
        "score": row["score"],
        "score_breakdown": _loads(row["score_breakdown_json"], []),
        "remediation": _loads(row["remediation_json"], []),
        "confidence_notes": _loads(row["confidence_notes_json"], []),
        "ai_summary": row["ai_summary"],
        "ai_status": row["ai_status"],
        "error": row["error"],
        "is_demo": bool(row["is_demo"]),
    }


def add_audit_entry(
    job_id: str | None,
    input_types: list[str] | str,
    consent: bool,
    tools_run: list[str] | str | None,
    is_demo: bool = False,
) -> None:
    if isinstance(input_types, list):
        input_types = ",".join(input_types)
    if isinstance(tools_run, list):
        tools_run = ",".join(tools_run)
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO audit_log (timestamp, job_id, input_types, consent, tools_run, is_demo)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _utc_now(),
                    job_id,
                    input_types or "",
                    1 if consent else 0,
                    tools_run or "",
                    1 if is_demo else 0,
                ),
            )
            conn.commit()
        finally:
            conn.close()


def list_audit(limit: int = 200) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT id, timestamp, job_id, input_types, consent, tools_run, is_demo
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            conn.close()
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "job_id": r["job_id"],
            "input_types": r["input_types"],
            "consent": bool(r["consent"]),
            "tools_run": r["tools_run"],
            "is_demo": bool(r["is_demo"]),
        }
        for r in rows
    ]


def record_rate_event() -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO rate_events (timestamp) VALUES (?)",
                (_utc_now(),),
            )
            conn.commit()
        finally:
            conn.close()


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def count_scans_in_last_hour() -> int:
    """Count live (non-demo) rate-limit events in the rolling 60-minute window."""
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT timestamp FROM rate_events").fetchall()
        finally:
            conn.close()
    n = 0
    for row in rows:
        ts = _parse_ts(row["timestamp"])
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff:
            n += 1
    return n
