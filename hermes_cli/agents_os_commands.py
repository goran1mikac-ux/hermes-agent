"""Minimal durable command state machine for local Agents OS execution."""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from hermes_cli.agents_os import utc_now


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents_os_commands (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    transcript TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('draft','queued','running','succeeded','failed')),
    version INTEGER NOT NULL,
    run_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    error_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
"""


class CommandConflict(RuntimeError):
    pass


def ensure_schema(conn: sqlite3.Connection) -> None:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_commands'"
    ).fetchone()
    if not exists:
        conn.executescript(SCHEMA)


def _decode(value: str | None) -> Any:
    return None if value is None else json.loads(value)


def get_command(conn: sqlite3.Connection, command_id: str) -> dict[str, Any]:
    ensure_schema(conn)
    row = conn.execute("SELECT * FROM agents_os_commands WHERE id=?", (command_id,)).fetchone()
    if row is None:
        raise KeyError(command_id)
    item = dict(row)
    item["metadata"] = _decode(item.pop("metadata_json"))
    item["result"] = _decode(item.pop("result_json"))
    item["error"] = _decode(item.pop("error_json"))
    return item


def create_command(
    conn: sqlite3.Connection,
    *,
    transcript: str,
    idempotency_key: str,
    metadata: dict[str, Any] | None = None,
    command_id: str | None = None,
) -> dict[str, Any]:
    ensure_schema(conn)
    if not transcript.strip() or not idempotency_key.strip():
        raise ValueError("transcript and idempotency_key are required")
    existing = conn.execute(
        "SELECT id,transcript FROM agents_os_commands WHERE idempotency_key=?", (idempotency_key,)
    ).fetchone()
    if existing:
        if existing["transcript"] != transcript:
            raise CommandConflict("idempotency key reused")
        return get_command(conn, existing["id"])
    now = utc_now()
    command_id = command_id or f"command-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO agents_os_commands
           (id,idempotency_key,transcript,state,version,metadata_json,created_at,updated_at)
           VALUES(?,?,?,'draft',1,?,?,?)""",
        (command_id, idempotency_key, transcript, json.dumps(metadata or {}, sort_keys=True), now, now),
    )
    return get_command(conn, command_id)


def _transition(
    conn: sqlite3.Connection,
    command_id: str,
    *,
    expected_version: int,
    allowed_from: str,
    state: str,
    run_id: str | None = None,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    completed_at = now if state in {"succeeded", "failed"} else None
    changed = conn.execute(
        """UPDATE agents_os_commands
           SET state=?,version=version+1,run_id=COALESCE(?,run_id),result_json=?,error_json=?,
               updated_at=?,completed_at=?
           WHERE id=? AND version=? AND state=?""",
        (state, run_id, json.dumps(result, sort_keys=True) if result is not None else None,
         json.dumps(error, sort_keys=True) if error is not None else None, now, completed_at,
         command_id, expected_version, allowed_from),
    ).rowcount
    if changed != 1:
        raise CommandConflict("invalid or concurrent command transition")
    return get_command(conn, command_id)


def confirm_command(conn: sqlite3.Connection, command_id: str, *, expected_version: int) -> dict[str, Any]:
    return _transition(conn, command_id, expected_version=expected_version, allowed_from="draft", state="queued")


def mark_running(
    conn: sqlite3.Connection, command_id: str, *, expected_version: int, run_id: str
) -> dict[str, Any]:
    return _transition(
        conn, command_id, expected_version=expected_version, allowed_from="queued", state="running", run_id=run_id
    )


def complete_command(
    conn: sqlite3.Connection,
    command_id: str,
    *,
    expected_version: int,
    succeeded: bool,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _transition(
        conn, command_id, expected_version=expected_version, allowed_from="running",
        state="succeeded" if succeeded else "failed", result=result, error=error,
    )
