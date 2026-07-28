from __future__ import annotations

import ast
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

import scripts.executive_board.p2_installed_launcher as installed_launcher

from hermes_cli.agents_os_executive_board import (
    EXECUTIVE_BOARD_SCHEMA_VERSION,
    ExecutiveBoardMigrationError,
    migrate_schema,
    verify_migrated_schema,
)
from scripts.executive_board.canonical_adapter import database_fingerprint
from scripts.executive_board.p2_installed_launcher import (
    migrate_installed_database,
    rollback_installed_database,
)
from scripts.executive_board.managed_runtime import (
    ManagedRuntimeController,
    RuntimeControllerError,
)


META_KEY = "executive_board_schema_version"


def test_installed_launcher_has_no_top_level_application_or_security_imports() -> None:
    source = Path(installed_launcher.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            forbidden.extend(
                alias.name
                for alias in node.names
                if alias.name.startswith(("hermes_cli", "scripts.executive_board"))
            )
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            ("hermes_cli", "scripts.executive_board")
        ):
            forbidden.append(node.module or "")
    assert forbidden == []


def test_package_verification_finishes_before_any_application_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_packages = tmp_path / "site-packages"
    module_hashes: dict[str, dict[str, str]] = {}
    for name in installed_launcher.MODULES:
        path = site_packages.joinpath(*name.split(".")).with_suffix(".py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"MODULE = {name!r}\n", encoding="utf-8")
        module_hashes[name] = {"sha256": installed_launcher.digest(path)}
    wheel = tmp_path / "hermes.whl"
    wheel.write_bytes(b"verified-wheel")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        __import__("json").dumps(
            {
                "wheel": {"sha256": installed_launcher.digest(wheel)},
                "modules": module_hashes,
            }
        ),
        encoding="utf-8",
    )

    class Distribution:
        version = installed_launcher.EXPECTED_VERSION

        @staticmethod
        def locate_file(relative: object) -> Path:
            return site_packages / Path(str(relative))

    monkeypatch.setattr(installed_launcher.importlib.metadata, "distribution", lambda _name: Distribution())

    def forbidden_import(name: str):
        raise AssertionError(f"application import occurred before verification: {name}")

    monkeypatch.setattr(installed_launcher.importlib, "import_module", forbidden_import)
    origins = installed_launcher.verify_package(manifest, wheel)
    assert set(origins) == set(installed_launcher.MODULES)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _has_table(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _schema_version(connection: sqlite3.Connection) -> str | None:
    if not _has_table(connection, "agents_os_meta"):
        return None
    row = connection.execute(
        "SELECT value FROM agents_os_meta WHERE key=?", (META_KEY,)
    ).fetchone()
    return None if row is None else str(row[0])


def test_installed_migration_creates_missing_meta_and_preserves_foundation(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("CREATE TABLE foundation(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
    connection.execute("INSERT INTO foundation(payload) VALUES ('preserve-me')")
    connection.commit()
    connection.close()

    result = migrate_installed_database(database)

    connection = _connect(database)
    try:
        assert result["committed"] is True
        assert _schema_version(connection) == EXECUTIVE_BOARD_SCHEMA_VERSION
        assert connection.execute("SELECT payload FROM foundation").fetchone()[0] == "preserve-me"
        verify_migrated_schema(connection)
    finally:
        connection.close()


def test_installed_migration_preserves_existing_meta_rows(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("CREATE TABLE agents_os_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.execute("INSERT INTO agents_os_meta VALUES ('foundation_schema_version', '41')")
    connection.commit()
    connection.close()

    migrate_installed_database(database)

    connection = _connect(database)
    try:
        assert connection.execute(
            "SELECT value FROM agents_os_meta WHERE key='foundation_schema_version'"
        ).fetchone()[0] == "41"
        assert _schema_version(connection) == EXECUTIVE_BOARD_SCHEMA_VERSION
    finally:
        connection.close()


def test_installed_migration_is_repeatable(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    sqlite3.connect(database).close()
    first = migrate_installed_database(database)
    second = migrate_installed_database(database)
    assert first["committed"] is True
    assert second["committed"] is True
    connection = _connect(database)
    try:
        verify_migrated_schema(connection)
    finally:
        connection.close()


def test_installed_rollback_removes_meta_table_created_by_migration(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE foundation(value TEXT NOT NULL)")
    connection.execute("INSERT INTO foundation VALUES ('keep')")
    connection.commit()
    connection.close()
    migrate_installed_database(database)

    rollback_installed_database(
        database, baseline_meta_present=False, baseline_version=None
    )

    connection = sqlite3.connect(database)
    try:
        assert not _has_table(connection, "agents_os_meta")
        assert not _has_table(connection, "executive_board_items")
        assert connection.execute("SELECT value FROM foundation").fetchone()[0] == "keep"
    finally:
        connection.close()


def test_installed_rollback_preserves_preexisting_meta_table_and_rows(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE agents_os_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.execute("INSERT INTO agents_os_meta VALUES ('foundation', 'keep')")
    connection.commit()
    connection.close()
    migrate_installed_database(database)

    rollback_installed_database(
        database, baseline_meta_present=True, baseline_version=None
    )

    connection = sqlite3.connect(database)
    try:
        assert _has_table(connection, "agents_os_meta")
        assert connection.execute(
            "SELECT value FROM agents_os_meta WHERE key='foundation'"
        ).fetchone()[0] == "keep"
        assert _schema_version(connection) is None
    finally:
        connection.close()


def test_migration_primitive_never_commits_owners_transaction(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("BEGIN IMMEDIATE")
    migrate_schema(connection)
    assert connection.in_transaction is True
    connection.rollback()
    assert not _has_table(connection, "agents_os_meta")
    assert not _has_table(connection, "executive_board_items")
    connection.close()


def test_mid_migration_failure_rolls_back_every_additive_change(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("CREATE TABLE foundation(value TEXT NOT NULL)")
    connection.execute("INSERT INTO foundation VALUES ('baseline')")
    connection.commit()
    connection.close()

    def fail(stage: str) -> None:
        if stage == "after:executive_board_meetings":
            raise RuntimeError("injected migration fault")

    with pytest.raises(RuntimeError, match="injected"):
        migrate_installed_database(database, fault_hook=fail)

    connection = _connect(database)
    try:
        assert connection.execute("SELECT value FROM foundation").fetchone()[0] == "baseline"
        assert not _has_table(connection, "agents_os_meta")
        assert not _has_table(connection, "executive_board_items")
        assert not _has_table(connection, "executive_board_meetings")
    finally:
        connection.close()


@pytest.mark.parametrize(
    "failure_stage", ["after:approval_nonce", "after:executive_board_meetings"]
)
def test_approval_nonce_and_migration_share_one_transaction(
    tmp_path: Path, failure_stage: str
) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("CREATE TABLE foundation(value TEXT NOT NULL)")
    connection.execute("INSERT INTO foundation VALUES ('baseline')")
    connection.commit()
    connection.close()
    nonce_digest = "a" * 64
    approval_digest = "b" * 64

    def fail(stage: str) -> None:
        if stage == failure_stage:
            raise RuntimeError(f"injected at {stage}")

    with pytest.raises(RuntimeError, match="injected"):
        migrate_installed_database(
            database,
            nonce_digest=nonce_digest,
            approval_digest=approval_digest,
            deployment_id="atomic-migration",
            fault_hook=fail,
        )

    connection = _connect(database)
    try:
        assert connection.execute("SELECT value FROM foundation").fetchone()[0] == "baseline"
        assert not _has_table(connection, "p2_approval_nonces")
        assert not _has_table(connection, "executive_board_items")
    finally:
        connection.close()

    migrate_installed_database(
        database,
        nonce_digest=nonce_digest,
        approval_digest=approval_digest,
        deployment_id="atomic-migration",
    )
    connection = _connect(database)
    try:
        assert _has_table(connection, "p2_approval_nonces")
        assert connection.execute(
            "SELECT approval_digest FROM p2_approval_nonces WHERE nonce_digest=?",
            (nonce_digest,),
        ).fetchone()[0] == approval_digest
        assert _has_table(connection, "executive_board_items")
    finally:
        connection.close()

    with pytest.raises(SystemExit, match="nonce replay"):
        migrate_installed_database(
            database,
            nonce_digest=nonce_digest,
            approval_digest=approval_digest,
            deployment_id="atomic-migration",
        )


def test_schema_mismatch_fails_closed_without_metadata_write(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = _connect(database)
    connection.execute("CREATE TABLE executive_board_items(wrong TEXT)")
    connection.commit()
    connection.close()

    with pytest.raises(ExecutiveBoardMigrationError, match="metadata|mismatch"):
        migrate_installed_database(database)

    connection = _connect(database)
    try:
        assert not _has_table(connection, "agents_os_meta")
        assert connection.execute("PRAGMA table_info(executive_board_items)").fetchone()[1] == "wrong"
    finally:
        connection.close()


def test_foreign_key_failure_rolls_back_migration(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
    connection.execute("CREATE TABLE child(parent_id INTEGER REFERENCES parent(id))")
    connection.execute("INSERT INTO child VALUES (999)")
    connection.commit()
    connection.close()

    with pytest.raises(ExecutiveBoardMigrationError, match="foreign-key"):
        migrate_installed_database(database)

    connection = sqlite3.connect(database)
    try:
        assert not _has_table(connection, "agents_os_meta")
        assert not _has_table(connection, "executive_board_items")
    finally:
        connection.close()


def test_integrity_verifier_failure_rolls_back_owner_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "state.sqlite"
    sqlite3.connect(database).close()

    def fail_integrity(_connection: sqlite3.Connection) -> None:
        raise ExecutiveBoardMigrationError("database integrity check failed")

    monkeypatch.setattr(
        "scripts.executive_board.p2_installed_launcher.verify_migrated_schema",
        fail_integrity,
    )
    with pytest.raises(ExecutiveBoardMigrationError, match="integrity"):
        migrate_installed_database(database)
    connection = sqlite3.connect(database)
    try:
        assert not _has_table(connection, "agents_os_meta")
        assert not _has_table(connection, "executive_board_items")
    finally:
        connection.close()


def test_migration_rejects_database_change_after_verified_backup(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE foundation(value TEXT NOT NULL)")
    connection.execute("INSERT INTO foundation VALUES ('verified')")
    connection.commit()
    connection.close()
    expected = database_fingerprint(database)

    connection = sqlite3.connect(database)
    connection.execute("INSERT INTO foundation VALUES ('changed-after-backup')")
    connection.commit()
    connection.close()

    with pytest.raises(SystemExit, match="changed after verified backup"):
        migrate_installed_database(database, expected_fingerprint=expected)
    connection = sqlite3.connect(database)
    try:
        assert not _has_table(connection, "executive_board_items")
        assert connection.execute("SELECT COUNT(*) FROM foundation").fetchone()[0] == 2
    finally:
        connection.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _runtime_command(port: int) -> list[str]:
    script = (
        "import json; from http.server import BaseHTTPRequestHandler,HTTPServer; "
        "H=type('H',(BaseHTTPRequestHandler,),{"
        "'do_GET':lambda s:(s.send_response(200),s.send_header('Content-Type','application/json'),"
        "s.end_headers(),s.wfile.write(json.dumps({'status':'ok'}).encode())),"
        "'log_message':lambda *a:None}); "
        f"HTTPServer(('127.0.0.1',{port}),H).serve_forever()"
    )
    return [sys.executable, "-I", "-c", script]


def test_runtime_controller_attributes_pid_listener_health_and_shutdown() -> None:
    port = _free_port()
    controller = ManagedRuntimeController(
        host="127.0.0.1",
        port=port,
        command=_runtime_command(port),
        expected_executable=Path(sys.executable),
    )
    receipt = controller.start()
    try:
        assert controller._process is not None
        assert controller._process.stdout is None
        assert controller._process.stderr is None
        assert receipt.pid > 0
        assert receipt.port == port
        assert receipt.executable == str(Path(sys.executable).resolve())
        assert receipt.process_start_ticks > 0
        assert receipt.listener_inode > 0
        health = controller.health(receipt)
        assert health["status"] == "ok"
        assert health["pid"] == receipt.pid
        assert health["listener_attributed"] is True
    finally:
        stopped = controller.shutdown(receipt)
    assert stopped["stopped"] is True
    assert controller.shutdown(receipt)["already_stopped"] is True
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_runtime_controller_rejects_executable_mismatch_without_orphan() -> None:
    port = _free_port()
    controller = ManagedRuntimeController(
        host="127.0.0.1",
        port=port,
        command=_runtime_command(port),
        expected_executable=Path("/bin/false"),
    )
    with pytest.raises(RuntimeControllerError, match="executable"):
        controller.start()
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_runtime_controller_module_has_no_sqlite_write_capability() -> None:
    module = Path(__file__).parents[2] / "scripts/executive_board/managed_runtime.py"
    source = module.read_text(encoding="utf-8")
    assert "import sqlite3" not in source
    assert "sqlite3.connect" not in source
