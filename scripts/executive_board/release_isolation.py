#!/usr/bin/env python3
"""Fail-closed ownership and isolation boundary for RC release runs."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any


class ReleaseIsolationError(RuntimeError):
    pass


_RUN_ID = re.compile(r"^codex-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$")
_SAFE_MODES = {"test", "simulation"}


@dataclass(frozen=True)
class ReleaseRunSpec:
    run_id: str
    technical_owner: str
    worktree: Path
    venv: Path
    temp_root: Path
    database: Path
    canonical_database: Path | None
    canonical_inode: int | None
    mode: str
    lock_file: Path
    ownership_file: Path


def _safe_directory(path: Path, label: str, run_id: str) -> Path:
    resolved = path.resolve(strict=True)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseIsolationError(f"{label} is not a safe directory")
    if run_id not in resolved.parts and run_id not in resolved.name:
        raise ReleaseIsolationError(f"{label} must be run-scoped")
    return resolved


def _safe_worktree(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseIsolationError("worktree is not a safe directory")
    normalized = str(resolved).casefold()
    if "codex" not in normalized or "doni" in normalized or "donibot" in normalized:
        raise ReleaseIsolationError("worktree must be Codex-specific")
    return resolved

def assert_safe_database_target(
    database: Path,
    *,
    mode: str,
    canonical_database: Path | None,
    canonical_inode: int | None,
) -> None:
    if mode not in _SAFE_MODES:
        return
    if canonical_database is None or canonical_inode is None:
        raise ReleaseIsolationError("canonical identity is required in test and simulation mode")
    canonical = canonical_database.resolve(strict=True)
    canonical_stat = os.lstat(canonical_database)
    if (
        stat.S_ISLNK(canonical_stat.st_mode)
        or not stat.S_ISREG(canonical_stat.st_mode)
        or canonical_stat.st_ino != canonical_inode
    ):
        raise ReleaseIsolationError("canonical identity changed or is unsafe")
    target = database.resolve(strict=False)
    if target == canonical:
        raise ReleaseIsolationError("canonical database path is denied")
    try:
        target_stat = os.lstat(database)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(target_stat.st_mode):
        raise ReleaseIsolationError("database target symlink is denied")
    if target_stat.st_ino == canonical_inode and target_stat.st_dev == canonical_stat.st_dev:
        raise ReleaseIsolationError("canonical inode is denied")


def current_run_identity() -> dict[str, str]:
    names = (
        "P2_RUN_ID",
        "P2_TECHNICAL_OWNER",
        "P2_RUN_OWNERSHIP_TOKEN",
        "P2_RUN_OWNERSHIP_TOKEN_SHA256",
    )
    values = {name: os.environ.get(name) for name in names}
    if all(value is None for value in values.values()):
        return {}
    if any(value is None for value in values.values()):
        raise ReleaseIsolationError("incomplete run ownership environment")
    run_id = str(values["P2_RUN_ID"])
    owner = str(values["P2_TECHNICAL_OWNER"])
    token = str(values["P2_RUN_OWNERSHIP_TOKEN"])
    token_digest = str(values["P2_RUN_OWNERSHIP_TOKEN_SHA256"])
    if not _RUN_ID.fullmatch(run_id) or owner != "codex":
        raise ReleaseIsolationError("invalid run ownership identity")
    if not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), token_digest):
        raise ReleaseIsolationError("run ownership token mismatch")
    return {
        "run_id": run_id,
        "technical_owner": owner,
        "ownership_token_sha256": token_digest,
    }

class ReleaseRunGuard:
    def __init__(self, spec: ReleaseRunSpec):
        self.spec = spec
        self._lock_handle: IO[bytes] | None = None
        self._previous_environment: dict[str, str | None] = {}

    def _validate(self) -> dict[str, Any]:
        spec = self.spec
        if spec.technical_owner != "codex":
            raise ReleaseIsolationError("single technical owner must be codex")
        if not _RUN_ID.fullmatch(spec.run_id):
            raise ReleaseIsolationError("run ID is invalid or not unique")
        canonical_database = spec.canonical_database
        canonical_inode = spec.canonical_inode
        if canonical_database is None or canonical_inode is None:
            raise ReleaseIsolationError("canonical identity is required for a release run")
        worktree = _safe_worktree(spec.worktree)
        venv = _safe_directory(spec.venv, "venv", spec.run_id)
        temp_root = _safe_directory(spec.temp_root, "temp root", spec.run_id)
        if len({worktree, venv, temp_root}) != 3:
            raise ReleaseIsolationError("worktree, venv and temp root must be separate")
        assert_safe_database_target(
            spec.database,
            mode=spec.mode,
            canonical_database=canonical_database,
            canonical_inode=canonical_inode,
        )
        database = spec.database.resolve(strict=False)
        if temp_root not in database.parents:
            raise ReleaseIsolationError("test database must be inside the run temp root")
        ownership = spec.ownership_file.resolve(strict=False)
        if temp_root not in ownership.parents:
            raise ReleaseIsolationError("ownership evidence must be inside the run temp root")
        return {
            "run_id": spec.run_id,
            "technical_owner": spec.technical_owner,
            "worktree": str(worktree),
            "venv": str(venv),
            "temp_root": str(temp_root),
            "database": str(database),
            "mode": spec.mode,
            "canonical_path_sha256": hashlib.sha256(str(canonical_database.resolve()).encode()).hexdigest(),
            "canonical_inode": canonical_inode,
            "pid": os.getpid(),
        }

    def __enter__(self) -> dict[str, Any]:
        ownership = self._validate()
        self.spec.lock_file.parent.mkdir(parents=True, exist_ok=True)
        handle = self.spec.lock_file.open("a+b")
        os.chmod(self.spec.lock_file, 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise ReleaseIsolationError("parallel release run is forbidden") from exc
        self._lock_handle = handle
        token = secrets.token_urlsafe(32)
        ownership["ownership_token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
        self.spec.ownership_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.spec.ownership_file.with_name(
            f".{self.spec.ownership_file.name}.{os.getpid()}.tmp"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            payload = json.dumps(ownership, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            if os.write(descriptor, payload) != len(payload):
                raise ReleaseIsolationError("short ownership evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.spec.ownership_file)
        os.chmod(self.spec.ownership_file, 0o600)
        for name, value in {
            "P2_RUN_ID": self.spec.run_id,
            "P2_TECHNICAL_OWNER": self.spec.technical_owner,
            "P2_RUN_OWNERSHIP_TOKEN": token,
            "P2_RUN_OWNERSHIP_TOKEN_SHA256": ownership["ownership_token_sha256"],
        }.items():
            self._previous_environment[name] = os.environ.get(name)
            os.environ[name] = value
        return ownership

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        for name, previous in self._previous_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        self._previous_environment.clear()
        if self._lock_handle is not None:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()
            self._lock_handle = None