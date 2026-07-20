"""Minimal task-scoped result memory and failure evidence."""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_objects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body_text TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope='task'),
    profile_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    producer_runtime TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    UNIQUE(content_hash,profile_id,task_id,run_id)
);
CREATE TABLE IF NOT EXISTS memory_candidates (
    id TEXT PRIMARY KEY,
    result_text TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'candidate' CHECK(state='candidate'),
    profile_id TEXT NOT NULL,
    task_id TEXT,
    run_id TEXT NOT NULL,
    producer_runtime TEXT NOT NULL
);
"""


def ensure_memory_schema(conn: sqlite3.Connection) -> None:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_objects'"
    ).fetchone()
    if not exists:
        conn.executescript(SCHEMA)


def create_memory_object(
    conn: sqlite3.Connection,
    *,
    title: str,
    body_text: str,
    profile_id: str,
    task_id: str,
    run_id: str,
    producer_runtime: str,
) -> dict[str, Any]:
    ensure_memory_schema(conn)
    digest = hashlib.sha256(body_text.encode()).hexdigest()
    object_id = f"memory-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO memory_objects
           (id,title,body_text,scope,profile_id,task_id,run_id,producer_runtime,content_hash)
           VALUES(?,?,?,'task',?,?,?,?,?)""",
        (object_id, title, body_text, profile_id, task_id, run_id, producer_runtime, digest),
    )
    return dict(conn.execute("SELECT * FROM memory_objects WHERE id=?", (object_id,)).fetchone())


def create_memory_candidate(
    conn: sqlite3.Connection,
    *,
    result_text: str,
    profile_id: str,
    task_id: str | None,
    run_id: str,
    producer_runtime: str,
) -> dict[str, Any]:
    ensure_memory_schema(conn)
    candidate_id = f"candidate-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO memory_candidates
           (id,result_text,profile_id,task_id,run_id,producer_runtime)
           VALUES(?,?,?,?,?,?)""",
        (candidate_id, result_text, profile_id, task_id, run_id, producer_runtime),
    )
    return dict(conn.execute("SELECT * FROM memory_candidates WHERE id=?", (candidate_id,)).fetchone())


def search_memory(
    conn: sqlite3.Connection,
    query: str,
    *,
    profile_id: str,
    scopes: list[str] | tuple[str, ...],
    task_id: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    ensure_memory_schema(conn)
    if tuple(scopes) != ("task",) or not task_id:
        raise ValueError("minimal memory search requires one explicit task scope")
    rows = conn.execute(
        """SELECT * FROM memory_objects
           WHERE profile_id=? AND task_id=? AND (title LIKE ? OR body_text LIKE ?)
           ORDER BY rowid DESC LIMIT ?""",
        (profile_id, task_id, f"%{query}%", f"%{query}%", max(1, min(limit, 100))),
    ).fetchall()
    return [dict(row) for row in rows]
