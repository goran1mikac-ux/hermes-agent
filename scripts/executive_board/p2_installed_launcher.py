#!/usr/bin/env python3
"""Installed-only launcher/adapter entrypoint for Executive Board RC2 P2."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable
from wsgiref.simple_server import make_server

EXPECTED_VERSION = "0.19.0"
MODULES = (
    "hermes_cli.agents_os",
    "hermes_cli.agents_os_commands",
    "hermes_cli.agents_os_execution",
    "hermes_cli.agents_os_executive_board",
    "hermes_cli.agents_os_memory",
    "hermes_cli.agents_os_orchestrator",
    "hermes_cli.agents_os_web",
    "scripts.executive_board.authenticated_ledger",
    "scripts.executive_board.canonical_adapter",
)

# Test/failure-injection seam. The production default stays ``None`` so no
# application module is imported before ``verify_package`` completes.
verify_migrated_schema: Callable[[sqlite3.Connection], None] | None = None


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_package(manifest_path: Path, wheel: Path) -> dict[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    distribution = importlib.metadata.distribution("hermes-agent")
    if distribution.version != EXPECTED_VERSION:
        raise SystemExit("installed package version mismatch")
    if digest(wheel) != manifest["wheel"]["sha256"]:
        raise SystemExit("wheel hash mismatch")
    root = Path(str(distribution.locate_file(""))).resolve()
    origins: dict[str, str] = {}
    for name in MODULES:
        relative = Path(*name.split(".")).with_suffix(".py")
        origin = Path(str(distribution.locate_file(relative))).resolve()
        if not origin.is_relative_to(root) or "site-packages" not in origin.parts:
            raise SystemExit(f"source shadowing detected for {name}: {origin}")
        if origin.is_symlink() or not origin.is_file():
            raise SystemExit(f"installed module is missing or unsafe: {name}")
        expected = manifest["modules"][name]["sha256"]
        if digest(origin) != expected:
            raise SystemExit(f"installed module hash mismatch: {name}")
        origins[name] = str(origin)
    return origins


def database_checks(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("database integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise SystemExit("database foreign-key check failed")


def migrate_installed_database(
    database: Path,
    *,
    expected_fingerprint: str | None = None,
    nonce_digest: str | None = None,
    approval_digest: str | None = None,
    deployment_id: str | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Own the full installed migration transaction and fail closed."""
    canonical_module = importlib.import_module(
        "scripts.executive_board.canonical_adapter"
    )
    board_module = importlib.import_module("hermes_cli.agents_os_executive_board")
    migrate_schema = board_module.migrate_schema
    schema_verifier = verify_migrated_schema or board_module.verify_migrated_schema
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        connection.execute("BEGIN IMMEDIATE")
        if (
            expected_fingerprint is not None
            and canonical_module.database_fingerprint_connection(connection)
            != expected_fingerprint
        ):
            raise SystemExit("database changed after verified backup")
        nonce_fields = (nonce_digest, approval_digest, deployment_id)
        if any(value is not None for value in nonce_fields):
            if not all(isinstance(value, str) and value for value in nonce_fields):
                raise SystemExit("approval nonce transaction binding is incomplete")
            nonce_value = str(nonce_digest)
            approval_value = str(approval_digest)
            deployment_value = str(deployment_id)
            if any(
                len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
                for value in (nonce_value, approval_value)
            ):
                raise SystemExit("approval nonce transaction digest is invalid")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS p2_approval_nonces(
                       nonce_digest TEXT PRIMARY KEY,
                       approval_digest TEXT NOT NULL,
                       deployment_id TEXT NOT NULL,
                       consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                   )"""
            )
            try:
                connection.execute(
                    "INSERT INTO p2_approval_nonces"
                    "(nonce_digest,approval_digest,deployment_id) VALUES(?,?,?)",
                    (nonce_value, approval_value, deployment_value),
                )
            except sqlite3.IntegrityError as exc:
                raise SystemExit("approval nonce replay detected") from exc
            if fault_hook is not None:
                fault_hook("after:approval_nonce")
        migrate_schema(connection, fault_hook=fault_hook)
        schema_verifier(connection)
        connection.commit()
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
    return {"committed": True, "transaction_owner": "p2_installed_adapter"}


def rollback_installed_database(
    database: Path,
    *,
    baseline_meta_present: bool,
    baseline_version: str | None,
) -> dict[str, object]:
    """Own the full baseline-aware rollback transaction and fail closed."""
    board_module = importlib.import_module("hermes_cli.agents_os_executive_board")
    rollback_schema = board_module.rollback_schema
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        connection.execute("BEGIN IMMEDIATE")
        rollback_schema(
            connection,
            baseline_meta_present=baseline_meta_present,
            baseline_version=baseline_version,
        )
        database_checks(connection)
        connection.commit()
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
    return {"committed": True, "transaction_owner": "p2_installed_adapter"}


def lifecycle_e2e(database: Path) -> None:
    from hermes_cli.agents_os_executive_board import (
        BoardItem,
        BoardItemKind,
        ExecutiveBoardStore,
    )

    with tempfile.TemporaryDirectory(prefix="p2-board-e2e-") as raw:
        copy = Path(raw) / "state.sqlite"
        source = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        target = sqlite3.connect(copy)
        try:
            source.backup(target)
            target.commit()
        finally:
            target.close()
            source.close()
        connection = sqlite3.connect(copy)
        connection.row_factory = sqlite3.Row
        try:
            store = ExecutiveBoardStore(connection)
            recommendation = BoardItem.create(
                kind=BoardItemKind.RECOMMENDATION,
                local_id="p2-production-e2e-recommendation",
                title="P2 reversible launch",
                body="Installed lifecycle contract.",
            )
            action = BoardItem.create(
                kind=BoardItemKind.ACTION_REQUEST,
                local_id="p2-production-e2e-action",
                title="P2 controlled transition",
                body="Installed action lifecycle contract.",
            )
            store.save(recommendation)
            store.save(action)
            if store.get(recommendation.canonical_id) != recommendation:
                raise SystemExit("recommendation lifecycle mismatch")
            if store.get(action.canonical_id) != action:
                raise SystemExit("action lifecycle mismatch")
            database_checks(connection)
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--operation",
        required=True,
        choices=("package-verify", "migrate", "verify", "rollback", "lifecycle-e2e", "serve"),
    )
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18791)
    parser.add_argument("--baseline-meta-present", choices=("0", "1"))
    parser.add_argument("--baseline-version")
    parser.add_argument("--expected-fingerprint")
    parser.add_argument("--nonce-digest")
    parser.add_argument("--approval-digest")
    parser.add_argument("--deployment-id")
    args = parser.parse_args()

    origins = verify_package(args.manifest, args.wheel)
    if args.operation == "package-verify":
        print(json.dumps({"marker": "P2_PACKAGE_VERIFY_PASS", "origins": origins}, sort_keys=True))
        return

    if args.operation == "migrate":
        migrate_installed_database(
            args.db,
            expected_fingerprint=args.expected_fingerprint,
            nonce_digest=args.nonce_digest,
            approval_digest=args.approval_digest,
            deployment_id=args.deployment_id,
        )
        print("P2_MIGRATE=PASS")
        return

    if args.operation == "verify":
        from hermes_cli.agents_os_executive_board import EXECUTIVE_BOARD_SCHEMA_VERSION

        connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        try:
            database_checks(connection)
            row = connection.execute(
                "SELECT value FROM agents_os_meta WHERE key='executive_board_schema_version'"
            ).fetchone()
        finally:
            connection.close()
        if row is None or str(row[0]) != str(EXECUTIVE_BOARD_SCHEMA_VERSION):
            raise SystemExit("Executive Board schema version mismatch")
        print("P2_VERIFY=PASS")
        return

    if args.operation == "rollback":
        if args.baseline_meta_present is None:
            raise SystemExit("rollback baseline metadata receipt is required")
        rollback_installed_database(
            args.db,
            baseline_meta_present=args.baseline_meta_present == "1",
            baseline_version=args.baseline_version or None,
        )
        print("P2_ROLLBACK=PASS")
        return

    if args.operation == "lifecycle-e2e":
        lifecycle_e2e(args.db)
        print("P2_BOARD_LIFECYCLE_E2E=PASS")
        return

    if args.host != "127.0.0.1":
        raise SystemExit("refusing non-loopback bind")
    from hermes_cli.agents_os import AgentsOSPaths
    from hermes_cli.agents_os_web import create_app

    root = args.db.parent
    paths = AgentsOSPaths(root.parent, root, args.db, root / "artifacts", root / "outbox")
    app = create_app(paths)
    with make_server(args.host, args.port, app) as server:
        print(f"Executive Board P2 listening on http://{args.host}:{args.port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
