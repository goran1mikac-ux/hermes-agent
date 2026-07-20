"""Minimal local persistence foundation for Agents OS features."""

from __future__ import annotations

import os
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents_os_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ready','in_progress','review','blocked','completed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    workflow TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('queued','running','succeeded','failed')),
    input TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    run_id TEXT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class AgentsOSPaths:
    home: Path
    root: Path
    db: Path
    artifacts: Path
    outbox: Path


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log_event(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    task_id: str | None = None,
    run_id: str | None = None,
    payload: dict[str, object] | None = None,
) -> str:
    event_id = f"event-{uuid.uuid4().hex[:12]}"
    conn.execute(
        "INSERT INTO events(id,task_id,run_id,event_type,payload,created_at) VALUES(?,?,?,?,?,?)",
        (event_id, task_id, run_id, event_type, json.dumps(payload or {}, sort_keys=True), utc_now()),
    )
    return event_id


def resolve_paths(*, home: str | Path | None = None) -> AgentsOSPaths:
    """Resolve profile-local paths without touching the filesystem."""
    profile_home = Path(home or os.environ.get("HERMES_HOME", "~/.hermes")).expanduser()
    root = Path(os.environ.get("AGENTS_OS_HOME", profile_home / "agents_os")).expanduser()
    return AgentsOSPaths(
        home=profile_home,
        root=root,
        db=root / "state.sqlite",
        artifacts=root / "artifacts",
        outbox=root / "outbox",
    )


def connect(paths: AgentsOSPaths | None = None) -> sqlite3.Connection:
    """Open and initialize the local SQLite store."""
    resolved = paths or resolve_paths()
    resolved.root.mkdir(parents=True, exist_ok=True)
    resolved.artifacts.mkdir(parents=True, exist_ok=True)
    resolved.outbox.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(resolved.db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO agents_os_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (SCHEMA_VERSION,),
    )
    conn.commit()
    return conn
