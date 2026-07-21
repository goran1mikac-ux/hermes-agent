from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from scripts.executive_board.verify_migration import (
    EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE,
    DatabaseVerificationError,
    classify_backup_restore_hash,
    integrity_check_value,
    sha256,
    verify_connection,
    verify_migration_copy,
)


REPO = Path(__file__).resolve().parents[2]
LAUNCHER = REPO / "scripts" / "executive_board" / "start_installed_executive_board.sh"


def test_integrity_check_value_accepts_tuple_result():
    assert integrity_check_value(("ok",)) == "ok"


def test_integrity_check_value_accepts_sqlite_row_result():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT 'ok' AS integrity_check").fetchone()
    assert integrity_check_value(row) == "ok"
    conn.close()


class _BadIntegrityConnection:
    def execute(self, sql):
        if sql == "PRAGMA integrity_check":
            return _Rows([("database disk image is malformed",)])
        if sql == "PRAGMA foreign_key_check":
            return _Rows([])
        raise AssertionError(sql)


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)


def test_verify_connection_fails_closed_on_bad_integrity_result():
    with pytest.raises(DatabaseVerificationError, match="integrity_check"):
        verify_connection(_BadIntegrityConnection())


def test_backup_restore_raw_hash_difference_is_expected_when_logically_equal():
    result = classify_backup_restore_hash(
        original_raw_hash="a" * 64,
        restored_raw_hash="b" * 64,
        restored_matches_backup=True,
        integrity_ok=True,
        foreign_key_violations=0,
        schema_matches=True,
        logical_data_matches=True,
    )
    assert result == EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE


def test_backup_restore_classification_stays_fail_closed_without_logical_parity():
    with pytest.raises(DatabaseVerificationError):
        classify_backup_restore_hash(
            original_raw_hash="a" * 64,
            restored_raw_hash="b" * 64,
            restored_matches_backup=True,
            integrity_ok=True,
            foreign_key_violations=0,
            schema_matches=True,
            logical_data_matches=False,
        )


def test_rollback_result_reports_post_close_hash_and_expected_physical_difference(tmp_path):
    db = tmp_path / "phase0b-copy.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE preexisting_data (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO preexisting_data(value) VALUES ('keep me');
        """
    )
    conn.close()

    result = verify_migration_copy(db, rollback_after=True)

    assert result["sha256_after_rollback"] == sha256(db)
    assert result["rollback_hash_classification"] in {
        "BYTE_IDENTICAL_RESTORE",
        EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE,
    }


def test_release_launcher_has_no_dirty_source_copy_or_pythonpath():
    text = LAUNCHER.read_text(encoding="utf-8")
    assert "/mnt/d/HermesAgent/app" not in text
    assert "PYTHONPATH=" not in text
    assert "unset PYTHONPATH PYTHONHOME" in text
    assert " cp " not in text


def test_release_launcher_forwards_verify_only_without_touching_root(tmp_path):
    venv = tmp_path / "venv"
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True)
    capture = tmp_path / "args.txt"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    root = tmp_path / "agents_os"
    root.mkdir()
    sentinel = root / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    wheel = tmp_path / "candidate.whl"
    wheel.write_bytes(b"fixture")

    env = os.environ.copy()
    env["CAPTURE"] = str(capture)
    result = subprocess.run(
        [str(LAUNCHER), str(venv), str(root), str(manifest), str(wheel), "--verify-only"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--verify-only" in capture.read_text(encoding="utf-8").splitlines()
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
