"""Fail-closed migration verification for Executive Board release copies."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Sequence

from hermes_cli.agents_os_executive_board import (
    EXECUTIVE_BOARD_SCHEMA_VERSION,
    migrate,
    rollback,
)

EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE = (
    "EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE"
)


class DatabaseVerificationError(RuntimeError):
    """Raised whenever a database verification gate is not exactly green."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integrity_check_value(row: Sequence[Any]) -> str:
    """Return PRAGMA's first column for tuple and sqlite3.Row results."""
    try:
        value = row[0]
    except (IndexError, KeyError, TypeError) as exc:
        raise DatabaseVerificationError("integrity_check returned no first column") from exc
    if not isinstance(value, str):
        raise DatabaseVerificationError("integrity_check first column is not text")
    return value


def verify_connection(conn: Any) -> dict[str, Any]:
    integrity_rows = conn.execute("PRAGMA integrity_check").fetchall()
    integrity_values = [integrity_check_value(row) for row in integrity_rows]
    if integrity_values != ["ok"]:
        raise DatabaseVerificationError(
            f"integrity_check failed: {integrity_values!r}"
        )
    foreign_key_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_rows:
        raise DatabaseVerificationError(
            f"foreign_key_check failed: {len(foreign_key_rows)} violation(s)"
        )
    return {"integrity_check": "ok", "foreign_key_violations": 0}


def classify_backup_restore_hash(
    *,
    original_raw_hash: str,
    restored_raw_hash: str,
    restored_matches_backup: bool,
    integrity_ok: bool,
    foreign_key_violations: int,
    schema_matches: bool,
    logical_data_matches: bool,
) -> str:
    if original_raw_hash == restored_raw_hash:
        return "BYTE_IDENTICAL_RESTORE"
    if all(
        (
            restored_matches_backup,
            integrity_ok,
            foreign_key_violations == 0,
            schema_matches,
            logical_data_matches,
        )
    ):
        return EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE
    raise DatabaseVerificationError(
        "raw SQLite hash differs without complete backup/integrity/schema/logical parity"
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    return value


def logical_snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    schema = [
        tuple(row)
        for row in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )
    ]
    data: dict[str, list[list[Any]]] = {}
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for table in tables:
        quoted = table.replace('"', '""')
        rows = conn.execute(f'SELECT * FROM "{quoted}"').fetchall()
        normalized = [[_json_value(value) for value in tuple(row)] for row in rows]
        normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        data[table] = normalized
    return {
        "schema": schema,
        "data": data,
        "user_version": conn.execute("PRAGMA user_version").fetchone()[0],
    }


def verify_migration_copy(
    db_path: Path,
    *,
    rollback_after: bool = False,
) -> dict[str, Any]:
    before_hash = sha256(db_path)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    before_snapshot = logical_snapshot(conn)
    had_meta_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
    ).fetchone() is not None

    with conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS agents_os_meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
    migrate(conn)
    migrated_checks = verify_connection(conn)
    version_row = conn.execute(
        "SELECT value FROM agents_os_meta "
        "WHERE key='executive_board_schema_version'"
    ).fetchone()
    if version_row is None or version_row[0] != EXECUTIVE_BOARD_SCHEMA_VERSION:
        raise DatabaseVerificationError("Executive Board schema version mismatch")
    board_tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'executive_board_%' ORDER BY name"
        )
    ]
    expected_tables = [
        "executive_board_challenges",
        "executive_board_consumed_nonces",
        "executive_board_items",
        "executive_board_lifecycle_events",
        "executive_board_meetings",
        "executive_board_proposals",
    ]
    if board_tables != expected_tables:
        raise DatabaseVerificationError(f"Executive Board table mismatch: {board_tables!r}")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(FULL)")
    migrated_hash = sha256(db_path)

    result: dict[str, Any] = {
        "status": "pass",
        "db": str(db_path),
        "sha256_before": before_hash,
        "sha256_after_migration": migrated_hash,
        "executive_board_schema_version": version_row[0],
        "board_tables": board_tables,
        "migrated_checks": migrated_checks,
        "rollback_requested": rollback_after,
    }
    if rollback_after:
        rollback(conn)
        if not had_meta_table:
            with conn:
                conn.execute("DROP TABLE agents_os_meta")
        rolled_back_checks = verify_connection(conn)
        after_snapshot = logical_snapshot(conn)
        if after_snapshot != before_snapshot:
            raise DatabaseVerificationError("rollback logical snapshot mismatch")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(FULL)")
        conn.close()
        rollback_hash = sha256(db_path)
        classification = classify_backup_restore_hash(
            original_raw_hash=before_hash,
            restored_raw_hash=rollback_hash,
            restored_matches_backup=True,
            integrity_ok=rolled_back_checks["integrity_check"] == "ok",
            foreign_key_violations=rolled_back_checks["foreign_key_violations"],
            schema_matches=True,
            logical_data_matches=True,
        )
        result.update(
            {
                "rolled_back_checks": rolled_back_checks,
                "rollback_schema_matches": True,
                "rollback_logical_data_matches": True,
                "sha256_after_rollback": rollback_hash,
                "rollback_hash_classification": classification,
            }
        )
    else:
        conn.close()
        result["sha256_after_migration"] = sha256(db_path)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rollback-after", action="store_true")
    args = parser.parse_args()
    if not args.db.is_file():
        raise SystemExit(f"database does not exist: {args.db}")
    try:
        result = verify_migration_copy(args.db, rollback_after=args.rollback_after)
    except DatabaseVerificationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
