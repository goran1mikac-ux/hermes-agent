#!/usr/bin/env python3
"""Production canonical/runtime adapter for Executive Board RC2 P2.

The adapter is inert unless called explicitly by the P2 driver.  All public
operations validate artifact/path/listener contracts before touching a target.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import stat as stat_module
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


class AdapterError(RuntimeError):
    pass


class TrustedHMACKey(bytes):
    """Verifier key loaded from a permission-checked, owner-provisioned file."""


MAINTENANCE_MAX_TTL_SECONDS = 600


def load_trusted_hmac_key(path: Path) -> TrustedHMACKey:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise AdapterError("HMAC trust-store key is missing or unsafe")
    stat = candidate.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise AdapterError("HMAC trust-store key ownership or permissions are unsafe")
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino):
            raise AdapterError("HMAC trust-store key changed during open")
        key = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(key) != 32:
        raise AdapterError("HMAC trust-store key must contain exactly 32 bytes")
    return TrustedHMACKey(key)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class CanonicalAdapterSpec:
    hermes_home: Path
    database: Path
    venv: Path
    launcher: Path
    launcher_sha256: str
    adapter: Path
    adapter_sha256: str
    rollback_reference: Path
    rollback_reference_sha256: str
    wheel: Path
    wheel_sha256: str
    manifest: Path
    manifest_sha256: str
    host: str
    port: int
    simulation: bool = False

    @classmethod
    def from_plan(cls, plan: Any) -> "CanonicalAdapterSpec":
        canonical = Path(plan.canonical_db).resolve()
        hermes_home = canonical.parent.parent
        return cls(
            hermes_home=hermes_home,
            database=canonical,
            venv=Path(plan.target_venv).resolve(),
            launcher=Path(plan.staged_launcher).resolve(),
            launcher_sha256=plan.staged_launcher_sha256,
            adapter=Path(plan.canonical_adapter).resolve(),
            adapter_sha256=plan.canonical_adapter_sha256,
            rollback_reference=Path(plan.rollback_reference).resolve(),
            rollback_reference_sha256=plan.rollback_reference_sha256,
            wheel=Path(plan.wheel).resolve(),
            wheel_sha256=plan.wheel_sha256,
            manifest=Path(plan.manifest).resolve(),
            manifest_sha256=plan.manifest_sha256,
            host=plan.host,
            port=plan.port,
            simulation=plan.simulation,
        )


def _verify_file(path: Path, expected: str, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"{label} is not a regular file: {path}")
    if len(expected) != 64 or sha256_file(path) != expected:
        raise AdapterError(f"{label} hash mismatch")


def validate_adapter_spec(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    if spec.host != "127.0.0.1":
        raise AdapterError("listener must be loopback-only")
    if not (1024 <= spec.port <= 65535):
        raise AdapterError("invalid target port")
    if spec.simulation and spec.port == 18791:
        raise AdapterError("simulation must never use production port 18791")
    if not spec.simulation and spec.port != 18791:
        raise AdapterError("production adapter must target port 18791")
    expected_db = spec.hermes_home.resolve() / "agents_os/state.sqlite"
    if not spec.simulation and spec.database.resolve() != expected_db:
        raise AdapterError("canonical database is outside current HERMES_HOME")
    if not spec.simulation and "hermes-agent-0.19.0-rc2-p2" not in spec.venv.name:
        raise AdapterError("production target venv is not P2-versioned")
    if spec.venv.resolve() == Path("/home/goran/.venvs/hermes-agent-0.14.0").resolve():
        raise AdapterError("target venv aliases active legacy venv")
    _verify_file(spec.launcher, spec.launcher_sha256, "staged launcher")
    _verify_file(spec.adapter, spec.adapter_sha256, "canonical adapter")
    _verify_file(
        spec.rollback_reference,
        spec.rollback_reference_sha256,
        "rollback reference",
    )
    _verify_file(spec.wheel, spec.wheel_sha256, "release wheel")
    _verify_file(spec.manifest, spec.manifest_sha256, "release manifest")
    return {
        "host": spec.host,
        "port": spec.port,
        "simulation": spec.simulation,
        "database": str(spec.database),
        "venv": str(spec.venv),
        "adapter_sha256": spec.adapter_sha256,
        "launcher_sha256": spec.launcher_sha256,
        "rollback_reference_sha256": spec.rollback_reference_sha256,
        "wheel_sha256": spec.wheel_sha256,
        "manifest_sha256": spec.manifest_sha256,
    }


def writer_gate(database: Path, *, timeout_seconds: float = 1.0) -> None:
    if database.is_symlink() or not database.is_file():
        raise AdapterError("canonical database is not a regular file")
    connection = sqlite3.connect(str(database), timeout=timeout_seconds)
    try:
        connection.execute(f"PRAGMA busy_timeout={max(1, int(timeout_seconds * 1000))}")
        connection.execute("BEGIN IMMEDIATE")
        connection.rollback()
    except sqlite3.OperationalError as exc:
        raise AdapterError(f"unknown or active database writer: {exc}") from exc
    finally:
        connection.close()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def database_fingerprint_connection(connection: sqlite3.Connection) -> str:
    """Hash schema and logical rows using the caller-owned SQLite snapshot."""
    hasher = hashlib.sha256()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if integrity != "ok" or foreign_keys:
        raise AdapterError("database integrity or foreign-key check failed")
    tables = connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    for name, sql in tables:
        hasher.update(_canonical_json([name, sql]))
        quoted = '"' + str(name).replace('"', '""') + '"'
        for row in connection.execute(f"SELECT * FROM {quoted}"):
            normalized = [
                {"bytes_hex": value.hex()} if isinstance(value, bytes) else value
                for value in row
            ]
            hasher.update(_canonical_json(normalized))
    return hasher.hexdigest()


def database_fingerprint(database: Path) -> str:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
    try:
        return database_fingerprint_connection(connection)
    finally:
        connection.close()


def _port_open(host: str, port: int) -> bool:
    targets: list[tuple[socket.AddressFamily, str]] = [(socket.AF_INET, host)]
    if socket.has_ipv6:
        targets.append((socket.AF_INET6, "::1"))
    for family, address in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.1)
                if probe.connect_ex((address, port)) == 0:
                    return True
        except OSError:
            if family == socket.AF_INET:
                raise
    return False

def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_exchange(left: Path, right: Path) -> None:
    """Atomically exchange same-filesystem paths; fail closed without renameat2."""
    rename_exchange = 2
    at_fdcwd = -100
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise AdapterError("atomic rename exchange is unavailable on this platform")
    result = function(
        at_fdcwd,
        os.fsencode(left),
        at_fdcwd,
        os.fsencode(right),
        rename_exchange,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise AdapterError(f"atomic rename exchange failed with errno {error}")


def create_maintenance_approval(
    spec: CanonicalAdapterSpec,
    key: bytes,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 300,
    nonce: str,
) -> dict[str, Any]:
    if not key:
        raise AdapterError("maintenance approval key is empty")
    if not nonce:
        raise AdapterError("maintenance approval nonce is empty")
    if not (1 <= ttl_seconds <= MAINTENANCE_MAX_TTL_SECONDS):
        raise AdapterError("maintenance approval TTL is outside the permitted range")
    issued = now or datetime.now(timezone.utc)
    payload = {
        "kind": "P2_PHYSICAL_RESTORE_MAINTENANCE",
        "database": str(spec.database.resolve()),
        "rollback_reference_sha256": spec.rollback_reference_sha256,
        "database_fingerprint": database_fingerprint(spec.database),
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "nonce": nonce,
    }
    return {
        "algorithm": "P2-MAINTENANCE-HMAC-SHA256",
        "payload": payload,
        "signature": hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest(),
    }


def physical_restore(
    spec: CanonicalAdapterSpec,
    approval: Mapping[str, Any],
    key: bytes,
    *,
    now: datetime | None = None,
    maintenance_mode: bool,
    fault_hook: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if not key:
        raise AdapterError("maintenance approval key is empty")
    if not spec.simulation and not isinstance(key, TrustedHMACKey):
        raise AdapterError("production maintenance verification requires a trust-store key")
    if not maintenance_mode:
        raise AdapterError("physical restore requires explicit maintenance mode")
    validate_adapter_spec(spec)
    if _port_open(spec.host, spec.port):
        raise AdapterError("physical restore requires no listener")
    payload = approval.get("payload")
    signature = approval.get("signature")
    if approval.get("algorithm") != "P2-MAINTENANCE-HMAC-SHA256" or not isinstance(payload, dict) or not isinstance(signature, str):
        raise AdapterError("separate signed maintenance approval is required")
    expected = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise AdapterError("maintenance approval signature mismatch")
    bindings = {
        "kind": "P2_PHYSICAL_RESTORE_MAINTENANCE",
        "database": str(spec.database.resolve()),
        "rollback_reference_sha256": spec.rollback_reference_sha256,
    }
    if any(payload.get(name) != value for name, value in bindings.items()):
        raise AdapterError("maintenance approval binding mismatch")
    current = now or datetime.now(timezone.utc)
    try:
        issued = datetime.fromisoformat(payload["issued_at"])
        expires = datetime.fromisoformat(payload["expires_at"])
        database_baseline = str(payload["database_fingerprint"])
        if issued.tzinfo is None or expires.tzinfo is None or len(database_baseline) != 64:
            raise ValueError("invalid maintenance approval fields")
    except (KeyError, TypeError, ValueError) as exc:
        raise AdapterError("malformed maintenance approval timestamp or baseline") from exc
    ttl = (expires - issued).total_seconds()
    if (
        not payload.get("nonce")
        or expires <= issued
        or ttl > MAINTENANCE_MAX_TTL_SECONDS
        or current < issued
        or current >= expires
    ):
        raise AdapterError("maintenance approval expired or invalid")

    nonce_digest = hashlib.sha256(str(payload["nonce"]).encode("utf-8")).hexdigest()
    approval_digest = hashlib.sha256(_canonical_json(approval)).hexdigest()

    def inject(stage: str) -> None:
        if fault_hook is not None:
            fault_hook(stage)

    database_parent = spec.database.parent
    work = Path(tempfile.mkdtemp(prefix=".p2-physical-restore-", dir=database_parent))
    os.chmod(work, 0o700)
    source_snapshot = work / "rollback-source.sqlite"
    candidate = work / "restore-candidate.sqlite"
    lock_connection: sqlite3.Connection | None = None
    swapped = False
    restore_committed = False
    original_mode = 0o600
    try:
        source_stat = os.lstat(spec.rollback_reference)
        if (
            stat_module.S_ISLNK(source_stat.st_mode)
            or not stat_module.S_ISREG(source_stat.st_mode)
            or source_stat.st_nlink != 1
        ):
            raise AdapterError("rollback reference is not a safe private regular file")
        source_fd = os.open(spec.rollback_reference, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        destination_fd = os.open(
            source_snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        copied_hash = hashlib.sha256()
        try:
            opened = os.fstat(source_fd)
            if (opened.st_dev, opened.st_ino) != (source_stat.st_dev, source_stat.st_ino):
                raise AdapterError("rollback reference changed during secure open")
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                copied_hash.update(chunk)
                if os.write(destination_fd, chunk) != len(chunk):
                    raise AdapterError("short write while staging rollback reference")
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
            os.close(source_fd)
        if not hmac.compare_digest(copied_hash.hexdigest(), spec.rollback_reference_sha256):
            raise AdapterError("rollback reference changed or hash mismatch")
        inject("after_source_snapshot")

        source = sqlite3.connect(f"file:{source_snapshot}?mode=ro", uri=True)
        destination = sqlite3.connect(candidate)
        try:
            source.backup(destination)
            destination.commit()
        finally:
            destination.close()
            source.close()
        candidate_fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(candidate_fd)
        finally:
            os.close(candidate_fd)
        expected_restore_fingerprint = database_fingerprint(source_snapshot)
        if database_fingerprint(candidate) != expected_restore_fingerprint:
            raise AdapterError("private restore candidate logical fingerprint mismatch")
        candidate_check = sqlite3.connect(f"file:{candidate}?mode=ro", uri=True)
        try:
            if candidate_check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise AdapterError("private restore candidate integrity check failed")
            if candidate_check.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise AdapterError("private restore candidate foreign key check failed")
        finally:
            candidate_check.close()
        inject("after_candidate_validation")

        before = os.lstat(spec.database)
        if stat_module.S_ISLNK(before.st_mode) or not stat_module.S_ISREG(before.st_mode):
            raise AdapterError("canonical database is not a safe regular file")
        original_mode = stat_module.S_IMODE(before.st_mode)
        lock_connection = sqlite3.connect(spec.database, isolation_level=None, timeout=0)
        try:
            lock_connection.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError as exc:
            raise AdapterError("canonical database has an active or unverified writer") from exc
        inject("after_exclusive_lock")
        locked_stat = os.lstat(spec.database)
        if (locked_stat.st_dev, locked_stat.st_ino) != (before.st_dev, before.st_ino):
            raise AdapterError("canonical database inode changed before restore")
        nonce_table_before_baseline = lock_connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='p2_physical_restore_nonces'"
        ).fetchone()
        if nonce_table_before_baseline is not None:
            try:
                replay = lock_connection.execute(
                    "SELECT 1 FROM p2_physical_restore_nonces WHERE nonce_digest=?",
                    (nonce_digest,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise AdapterError("physical restore nonce receipt schema is invalid") from exc
            if replay is not None:
                raise AdapterError("physical restore approval replay detected")
        locked_fingerprint = database_fingerprint_connection(lock_connection)
        if not hmac.compare_digest(locked_fingerprint, database_baseline):
            raise AdapterError("canonical database changed after maintenance approval")
        existing_nonce_rows: list[tuple[str, str, str, str]] = []
        nonce_table_exists = lock_connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='p2_physical_restore_nonces'"
        ).fetchone()
        if nonce_table_exists is not None:
            try:
                existing_nonce_rows = [
                    (str(row[0]), str(row[1]), str(row[2]), str(row[3]))
                    for row in lock_connection.execute(
                        "SELECT nonce_digest,approval_digest,database_path_sha256,consumed_at "
                        "FROM p2_physical_restore_nonces ORDER BY nonce_digest"
                    )
                ]
            except sqlite3.Error as exc:
                raise AdapterError("physical restore nonce receipt schema is invalid") from exc
            if any(row[0] == nonce_digest for row in existing_nonce_rows):
                raise AdapterError("physical restore approval replay detected")
        candidate_connection = sqlite3.connect(candidate, isolation_level=None)
        try:
            candidate_connection.execute("BEGIN IMMEDIATE")
            candidate_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS p2_physical_restore_nonces (
                    nonce_digest TEXT PRIMARY KEY,
                    approval_digest TEXT NOT NULL,
                    database_path_sha256 TEXT NOT NULL,
                    consumed_at TEXT NOT NULL
                )
                """
            )
            candidate_connection.executemany(
                "INSERT OR IGNORE INTO p2_physical_restore_nonces "
                "(nonce_digest,approval_digest,database_path_sha256,consumed_at) "
                "VALUES(?,?,?,?)",
                existing_nonce_rows,
            )
            candidate_connection.execute(
                "INSERT INTO p2_physical_restore_nonces "
                "(nonce_digest,approval_digest,database_path_sha256,consumed_at) "
                "VALUES(?,?,?,?)",
                (
                    nonce_digest,
                    approval_digest,
                    hashlib.sha256(str(spec.database.resolve()).encode()).hexdigest(),
                    current.isoformat(),
                ),
            )
            candidate_connection.commit()
        except sqlite3.Error as exc:
            candidate_connection.rollback()
            raise AdapterError("physical restore nonce receipt transaction failed") from exc
        finally:
            candidate_connection.close()
        candidate_fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(candidate_fd)
        finally:
            os.close(candidate_fd)
        expected_restore_fingerprint = database_fingerprint(candidate)
        inject("after_locked_baseline")

        if _port_open(spec.host, spec.port):
            raise AdapterError("physical restore listener appeared during ownership race")
        candidate_before = os.lstat(candidate)
        os.chmod(candidate, 0o400)
        inject("before_atomic_exchange")
        _rename_exchange(spec.database, candidate)
        swapped = True
        _fsync_directory(database_parent)
        inject("after_atomic_exchange")
        installed = os.lstat(spec.database)
        if (installed.st_dev, installed.st_ino) != (candidate_before.st_dev, candidate_before.st_ino):
            raise AdapterError("restored canonical database inode mismatch")
        restored = sqlite3.connect(f"file:{spec.database}?mode=ro", uri=True)
        try:
            if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise AdapterError("restored canonical database integrity check failed")
            if restored.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise AdapterError("restored canonical database foreign key check failed")
        finally:
            restored.close()
        if database_fingerprint(spec.database) != expected_restore_fingerprint:
            raise AdapterError("restored canonical database fingerprint mismatch")
        inject("after_restored_validation")
        lock_connection.rollback()
        lock_connection.close()
        lock_connection = None
        os.chmod(spec.database, original_mode)
        _fsync_directory(database_parent)
        restore_committed = True
        swapped = False
        inject("after_restore_commit")
        return {
            "logical": False,
            "physical_restore": True,
            "restored_sha256": sha256_file(spec.database),
            "ownership_scope": "BEGIN_EXCLUSIVE_THROUGH_ATOMIC_EXCHANGE_AND_VALIDATION",
            "atomic_exchange": True,
        }
    except BaseException:
        if swapped and not restore_committed:
            _rename_exchange(spec.database, candidate)
            _fsync_directory(database_parent)
            swapped = False
        if lock_connection is not None:
            lock_connection.rollback()
            lock_connection.close()
        if spec.database.exists() and not spec.database.is_symlink():
            os.chmod(spec.database, original_mode)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
