"""Local Executive Board domain records on the Agents OS SQLite foundation."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

EXECUTIVE_BOARD_SCHEMA_VERSION = "1"
_SCHEMA_META_KEY = "executive_board_schema_version"
_TABLE = "executive_board_items"
_LOCAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class BoardItemKind(str, Enum):
    RECOMMENDATION = "recommendation"
    ACTION_REQUEST = "action_request"


def canonical_board_id(kind: BoardItemKind, local_id: str) -> str:
    """Build the stable, kind-scoped identity for a local Board record."""
    try:
        normalized_kind = BoardItemKind(kind)
    except ValueError as exc:
        raise ValueError(f"unsupported Board item kind: {kind!r}") from exc
    if not isinstance(local_id, str) or not _LOCAL_ID.fullmatch(local_id):
        raise ValueError("local_id must contain only letters, digits, '.', '_' or '-'")
    return f"executive-board:{normalized_kind.value}:{local_id}"


@dataclass(frozen=True)
class BoardItem:
    canonical_id: str
    kind: BoardItemKind
    title: str
    body: str
    created_at: str

    def __post_init__(self) -> None:
        kind = BoardItemKind(self.kind)
        object.__setattr__(self, "kind", kind)
        prefix = f"executive-board:{kind.value}:"
        if not self.canonical_id.startswith(prefix):
            raise ValueError("canonical_id does not match the Board item kind")
        canonical_board_id(kind, self.canonical_id.removeprefix(prefix))
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.body.strip():
            raise ValueError("body must not be empty")
        if not self.created_at:
            raise ValueError("created_at must not be empty")

    @classmethod
    def create(
        cls,
        *,
        kind: BoardItemKind,
        local_id: str,
        title: str,
        body: str,
        created_at: str | None = None,
    ) -> BoardItem:
        normalized_kind = BoardItemKind(kind)
        timestamp = created_at or datetime.now(timezone.utc).isoformat()
        return cls(
            canonical_id=canonical_board_id(normalized_kind, local_id),
            kind=normalized_kind,
            title=title,
            body=body,
            created_at=timestamp,
        )


@dataclass(frozen=True)
class ExecutiveBoardRollbackPlan:
    """Read-only description of schema owned by this feature slice."""

    tables: tuple[str, ...]
    meta_keys: tuple[str, ...]
    present_tables: tuple[str, ...]
    present_meta_keys: tuple[str, ...]


def migrate(conn: sqlite3.Connection) -> None:
    """Add the Executive Board schema without changing foundation data."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS executive_board_items (
                canonical_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK (kind IN ('recommendation', 'action_request')),
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO agents_os_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_SCHEMA_META_KEY, EXECUTIVE_BOARD_SCHEMA_VERSION),
        )


class ExecutiveBoardStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        migrate(conn)

    def save(self, item: BoardItem) -> None:
        """Insert or replace the payload belonging to one canonical identity."""
        if not isinstance(item, BoardItem):
            raise TypeError("item must be a BoardItem")
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO executive_board_items
                    (canonical_id, kind, title, body, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(canonical_id) DO UPDATE SET
                    kind=excluded.kind,
                    title=excluded.title,
                    body=excluded.body,
                    created_at=excluded.created_at
                """,
                (item.canonical_id, item.kind.value, item.title, item.body, item.created_at),
            )

    def get(self, canonical_id: str) -> BoardItem | None:
        row = self.conn.execute(
            "SELECT canonical_id, kind, title, body, created_at "
            "FROM executive_board_items WHERE canonical_id = ?",
            (canonical_id,),
        ).fetchone()
        if row is None:
            return None
        return BoardItem(
            canonical_id=row["canonical_id"],
            kind=BoardItemKind(row["kind"]),
            title=row["title"],
            body=row["body"],
            created_at=row["created_at"],
        )


def rollback_plan(conn: sqlite3.Connection) -> ExecutiveBoardRollbackPlan:
    """Inspect what rollback would remove; this function performs no writes."""
    table_present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
    ).fetchone()
    meta_table_present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
    ).fetchone()
    meta_present = None
    if meta_table_present:
        meta_present = conn.execute(
            "SELECT 1 FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,)
        ).fetchone()
    return ExecutiveBoardRollbackPlan(
        tables=(_TABLE,),
        meta_keys=(_SCHEMA_META_KEY,),
        present_tables=(_TABLE,) if table_present else (),
        present_meta_keys=(_SCHEMA_META_KEY,) if meta_present else (),
    )


def rollback(conn: sqlite3.Connection) -> None:
    """Idempotently remove only schema and metadata owned by this slice."""
    with conn:
        conn.execute(f"DROP TABLE IF EXISTS {_TABLE}")
        meta_table_present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone()
        if meta_table_present:
            conn.execute("DELETE FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,))
