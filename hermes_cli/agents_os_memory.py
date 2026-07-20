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


def _insert_compatible(
    conn: sqlite3.Connection,
    table: str,
    values: dict[str, Any],
) -> None:
    """Insert only columns exposed by the existing Agents OS schema."""
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    selected = [(key, value) for key, value in values.items() if key in columns]
    names = ",".join(key for key, _ in selected)
    placeholders = ",".join("?" for _ in selected)
    conn.execute(
        f"INSERT INTO {table} ({names}) VALUES ({placeholders})",
        tuple(value for _, value in selected),
    )


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
    digest = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
    object_id = f"memory-{uuid.uuid4().hex[:12]}"
    _insert_compatible(
        conn,
        "memory_objects",
        {
            "id": object_id,
            "kind": "execution_result",
            "title": title,
            "body_text": body_text,
            "body_uri": None,
            "content_hash": digest,
            "scope": "task",
            "profile_id": profile_id,
            "project_id": None,
            "task_id": task_id,
            "run_id": run_id,
            "producer_runtime": producer_runtime,
        },
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
    result_hash = hashlib.sha256(result_text.encode("utf-8")).hexdigest()
    _insert_compatible(
        conn,
        "memory_candidates",
        {
            "id": candidate_id,
            "result_hash": result_hash,
            "result_text": result_text,
            "profile_id": profile_id,
            "producer_runtime": producer_runtime,
            "producer_agent": "agents-os",
            "task_id": task_id,
            "run_id": run_id,
            "state": "candidate",
            "feedback": "",
            "object_id": None,
        },
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
