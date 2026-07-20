"""Minimal local persistence foundation for Agents OS features."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents_os_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class AgentsOSPaths:
    home: Path
    root: Path
    db: Path
    artifacts: Path
    outbox: Path


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
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO agents_os_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (SCHEMA_VERSION,),
    )
    conn.commit()
    return conn
