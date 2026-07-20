from __future__ import annotations

import sqlite3

from hermes_cli.agents_os import SCHEMA_VERSION, connect, resolve_paths


def test_resolve_paths_is_profile_local_and_neutral(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    monkeypatch.delenv("AGENTS_OS_HOME", raising=False)

    paths = resolve_paths()

    assert paths.home == tmp_path / "profile"
    assert paths.root == paths.home / "agents_os"
    assert paths.db == paths.root / "state.sqlite"
    assert paths.artifacts == paths.root / "artifacts"
    assert paths.outbox == paths.root / "outbox"


def test_connect_creates_minimal_versioned_schema(tmp_path):
    paths = resolve_paths(home=tmp_path / "profile")

    with connect(paths) as conn:
        assert isinstance(conn, sqlite3.Connection)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        }
        version = conn.execute(
            "SELECT value FROM agents_os_meta WHERE key='schema_version'"
        ).fetchone()[0]

    assert tables == {"agents_os_meta", "tasks", "runs", "events"}
    assert version == SCHEMA_VERSION
    assert paths.db.is_file()
    assert paths.artifacts.is_dir()
    assert paths.outbox.is_dir()
