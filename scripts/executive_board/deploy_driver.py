#!/usr/bin/env python3
"""Fail-closed Executive Board RC2 deploy/rollback state-machine driver.

The driver is intentionally standalone and stores every checkpoint outside the
canonical SQLite database. ``--execute`` is approval-gated and hard-disabled in
P1; plan, dry-run and verify-only modes never start a listener or mutate the
canonical database.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

DRIVER_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1
APPROVAL_SCHEMA_VERSION = 1
DEFAULT_STEP_TIMEOUT = 600
ACTIVE_VENV = Path("/home/goran/.venvs/hermes-agent-0.14.0")
FORBIDDEN_SOURCE_ROOTS = (
    Path("/mnt/d/HermesAgent/app"),
    Path("/home/goran/worktrees"),
)
MODULES = (
    "hermes_cli.agents_os",
    "hermes_cli.agents_os_commands",
    "hermes_cli.agents_os_execution",
    "hermes_cli.agents_os_executive_board",
    "hermes_cli.agents_os_memory",
    "hermes_cli.agents_os_orchestrator",
    "hermes_cli.agents_os_web",
)
BOARD_SCHEMA_META_KEY = "executive_board_schema_version"


class DriverError(RuntimeError):
    """A fail-closed deployment error."""


class StateError(DriverError):
    """An illegal state-machine transition."""


class StepTimeout(DriverError):
    """A bounded state operation exceeded its deadline."""


class State(str, Enum):
    PREFLIGHT = "PREFLIGHT"
    ARTIFACT_VERIFY = "ARTIFACT_VERIFY"
    SERVICE_AND_PORT_CHECK = "SERVICE_AND_PORT_CHECK"
    DATABASE_BACKUP = "DATABASE_BACKUP"
    BACKUP_RESTORE_VERIFY = "BACKUP_RESTORE_VERIFY"
    STAGED_VENV_INSTALL = "STAGED_VENV_INSTALL"
    INSTALLED_PARITY_VERIFY = "INSTALLED_PARITY_VERIFY"
    MIGRATION_DRY_RUN = "MIGRATION_DRY_RUN"
    ROLLBACK_DRY_RUN = "ROLLBACK_DRY_RUN"
    CANONICAL_MIGRATION = "CANONICAL_MIGRATION"
    VERIFY_ONLY = "VERIFY_ONLY"
    CONTROLLED_START = "CONTROLLED_START"
    HEALTH_CHECK = "HEALTH_CHECK"
    SECURITY_E2E = "SECURITY_E2E"
    BOARD_LIFECYCLE_E2E = "BOARD_LIFECYCLE_E2E"
    COMMIT_DEPLOY = "COMMIT_DEPLOY"
    ROLLBACK = "ROLLBACK"
    COMPLETE = "COMPLETE"


class DeployMode(str, Enum):
    PLAN = "plan"
    DRY_RUN = "dry-run"
    VERIFY_ONLY = "verify-only"
    EXECUTE = "execute"


STATE_CONTRACTS: dict[State, dict[str, Any]] = {
    State.PREFLIGHT: {
        "entry": ["deployment id is new", "checkpoint root writable", "clean Python environment"],
        "acceptance": ["plan schema valid", "active venv differs from target", "mode permitted"],
        "rollback": "external evidence only",
    },
    State.ARTIFACT_VERIFY: {
        "entry": ["PREFLIGHT verified"],
        "acceptance": ["wheel, manifest and runbook SHA-256 match plan", "manifest binds wheel"],
        "rollback": "external evidence only",
    },
    State.SERVICE_AND_PORT_CHECK: {
        "entry": ["ARTIFACT_VERIFY verified"],
        "acceptance": ["18791 unoccupied", "gateway/dashboard fingerprints captured"],
        "rollback": "external evidence only",
    },
    State.DATABASE_BACKUP: {
        "entry": ["service/port gate verified"],
        "acceptance": ["current online SQLite backup exists", "active writer gate passes"],
        "rollback": "discard incomplete backup artifact",
    },
    State.BACKUP_RESTORE_VERIFY: {
        "entry": ["backup checkpoint verified"],
        "acceptance": ["restore integrity_check=ok", "foreign_key_check=0", "logical parity"],
        "rollback": "retain evidence; do not touch canonical database",
    },
    State.STAGED_VENV_INSTALL: {
        "entry": ["restore test verified", "target path absent or matching staged marker"],
        "acceptance": ["separate venv", "non-editable wheel install", "pip check passes"],
        "rollback": "mark staged venv unused; no automatic destructive cleanup",
    },
    State.INSTALLED_PARITY_VERIFY: {
        "entry": ["staged venv verified"],
        "acceptance": ["7/7 installed origins and hashes match manifest", "no source shadowing"],
        "rollback": "mark staged venv unused",
    },
    State.MIGRATION_DRY_RUN: {
        "entry": ["installed parity verified", "fresh backup copy"],
        "acceptance": ["schema 3", "six Board tables", "integrity/FK/logical checks pass"],
        "rollback": "discard isolated migration copy",
    },
    State.ROLLBACK_DRY_RUN: {
        "entry": ["migration copy verified", "separate fresh backup copy"],
        "acceptance": ["logical baseline restored", "physical difference classified"],
        "rollback": "discard isolated rollback copy",
    },
    State.CANONICAL_MIGRATION: {
        "entry": ["all dry-run gates verified", "fresh single-use owner approval"],
        "acceptance": ["additive schema-only migration", "post-migration integrity/FK pass"],
        "rollback": "logical Board-owned rollback; never physical restore with active writers",
    },
    State.VERIFY_ONLY: {
        "entry": ["migration checkpoint verified or safely simulated"],
        "acceptance": ["installed launcher verification marker", "no listener", "no DB side effect"],
        "rollback": "logical rollback if execute mode already migrated",
    },
    State.CONTROLLED_START: {
        "entry": ["VERIFY_ONLY verified", "owner approval revalidated", "18791 still free"],
        "acceptance": ["new PID belongs to versioned venv", "listener only 127.0.0.1:18791"],
        "rollback": "stop only new RC PID then logical rollback",
    },
    State.HEALTH_CHECK: {
        "entry": ["controlled start verified"],
        "acceptance": ["bounded loopback health response is ok"],
        "rollback": "stop new RC PID then logical rollback",
    },
    State.SECURITY_E2E: {
        "entry": ["health verified"],
        "acceptance": ["approval, binding, replay, expiry and listener gates pass"],
        "rollback": "stop new RC PID then logical rollback",
    },
    State.BOARD_LIFECYCLE_E2E: {
        "entry": ["security E2E verified"],
        "acceptance": ["meeting through closure lifecycle passes with evidence binding"],
        "rollback": "stop new RC PID then logical rollback",
    },
    State.COMMIT_DEPLOY: {
        "entry": ["all live E2E gates verified", "legacy services unchanged"],
        "acceptance": ["external commit marker written", "rollback evidence retained"],
        "rollback": "stop new RC PID then logical rollback",
    },
    State.ROLLBACK: {
        "entry": ["failure or explicit rollback request"],
        "acceptance": ["new PID stopped", "logical Board rollback verified", "old services unchanged"],
        "rollback": "BLOCKED; physical restore requires separate maintenance approval",
    },
    State.COMPLETE: {
        "entry": ["COMMIT_DEPLOY or ROLLBACK verified"],
        "acceptance": ["terminal status and evidence persisted"],
        "rollback": "none",
    },
}

NORMAL_NEXT: dict[State, State | None] = {
    State.PREFLIGHT: State.ARTIFACT_VERIFY,
    State.ARTIFACT_VERIFY: State.SERVICE_AND_PORT_CHECK,
    State.SERVICE_AND_PORT_CHECK: State.DATABASE_BACKUP,
    State.DATABASE_BACKUP: State.BACKUP_RESTORE_VERIFY,
    State.BACKUP_RESTORE_VERIFY: State.STAGED_VENV_INSTALL,
    State.STAGED_VENV_INSTALL: State.INSTALLED_PARITY_VERIFY,
    State.INSTALLED_PARITY_VERIFY: State.MIGRATION_DRY_RUN,
    State.MIGRATION_DRY_RUN: State.ROLLBACK_DRY_RUN,
    State.ROLLBACK_DRY_RUN: State.CANONICAL_MIGRATION,
    State.CANONICAL_MIGRATION: State.VERIFY_ONLY,
    State.VERIFY_ONLY: State.CONTROLLED_START,
    State.CONTROLLED_START: State.HEALTH_CHECK,
    State.HEALTH_CHECK: State.SECURITY_E2E,
    State.SECURITY_E2E: State.BOARD_LIFECYCLE_E2E,
    State.BOARD_LIFECYCLE_E2E: State.COMMIT_DEPLOY,
    State.COMMIT_DEPLOY: State.COMPLETE,
    State.ROLLBACK: State.COMPLETE,
    State.COMPLETE: None,
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise DriverError("approval timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DeployPlan:
    release: Path
    wheel: Path
    manifest: Path
    runbook: Path
    wheel_sha256: str
    manifest_sha256: str
    runbook_sha256: str
    canonical_db: Path
    target_venv: Path
    host: str
    port: int
    target_environment: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "driver_schema_version": DRIVER_SCHEMA_VERSION,
            "driver_path": str(Path(__file__).resolve()),
            "driver_sha256": _sha256_file(Path(__file__).resolve()),
            "release": str(self.release.resolve()),
            "wheel": str(self.wheel.resolve()),
            "manifest": str(self.manifest.resolve()),
            "runbook": str(self.runbook.resolve()),
            "wheel_sha256": self.wheel_sha256,
            "manifest_sha256": self.manifest_sha256,
            "runbook_sha256": self.runbook_sha256,
            "canonical_db": str(self.canonical_db.resolve()),
            "target_venv": str(self.target_venv.resolve()),
            "host": self.host,
            "port": self.port,
            "target_environment": self.target_environment,
            "states": [state.value for state in State],
            "state_contracts": {state.value: STATE_CONTRACTS[state] for state in State},
            "transition_map": {
                state.value: next_state.value if next_state else None
                for state, next_state in NORMAL_NEXT.items()
            },
            "failure_transition": "ROLLBACK",
            "execution_policy": "CANONICAL_EXECUTION_DISABLED_IN_P1",
            "physical_restore_policy": "SEPARATE_MAINTENANCE_APPROVAL_WHEN_NO_ACTIVE_WRITERS",
        }

    @property
    def canonical_hash(self) -> str:
        return _sha256_bytes(_canonical_json(self.to_dict()))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DeployPlan":
        return cls(
            release=Path(value["release"]),
            wheel=Path(value["wheel"]),
            manifest=Path(value["manifest"]),
            runbook=Path(value["runbook"]),
            wheel_sha256=value["wheel_sha256"],
            manifest_sha256=value["manifest_sha256"],
            runbook_sha256=value["runbook_sha256"],
            canonical_db=Path(value["canonical_db"]),
            target_venv=Path(value["target_venv"]),
            host=value["host"],
            port=int(value["port"]),
            target_environment=value["target_environment"],
        )


def create_approval(
    plan: DeployPlan,
    deployment_id: str,
    key: bytes,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 300,
    nonce: str | None = None,
) -> dict[str, Any]:
    if not key:
        raise DriverError("approval key is empty")
    if ttl_seconds < 1:
        raise DriverError("approval TTL must be positive")
    issued = now or _utc_now()
    nonce_value = nonce or hashlib.sha256(os.urandom(32)).hexdigest()
    payload = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "plan_hash": plan.canonical_hash,
        "wheel_sha256": plan.wheel_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "runbook_sha256": plan.runbook_sha256,
        "target_environment": plan.target_environment,
        "target_venv": str(plan.target_venv.resolve()),
        "issued_at": _iso(issued),
        "expires_at": _iso(issued + timedelta(seconds=ttl_seconds)),
        "nonce": nonce_value,
    }
    signature = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature, "algorithm": "HMAC-SHA256"}


def verify_approval(
    approval: Mapping[str, Any],
    plan: DeployPlan,
    deployment_id: str,
    key: bytes,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if approval.get("algorithm") != "HMAC-SHA256":
        raise DriverError("unsupported approval algorithm")
    payload = approval.get("payload")
    signature = approval.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise DriverError("malformed approval envelope")
    expected = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise DriverError("approval signature mismatch")
    bindings = {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "plan_hash": plan.canonical_hash,
        "wheel_sha256": plan.wheel_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "runbook_sha256": plan.runbook_sha256,
        "target_environment": plan.target_environment,
        "target_venv": str(plan.target_venv.resolve()),
    }
    for name, expected_value in bindings.items():
        if payload.get(name) != expected_value:
            raise DriverError(f"approval binding mismatch: {name}")
    current = now or _utc_now()
    issued = _parse_time(payload["issued_at"])
    expires = _parse_time(payload["expires_at"])
    if current < issued - timedelta(seconds=30):
        raise DriverError("approval issued in the future")
    if current >= expires:
        raise DriverError("approval expired")
    if not payload.get("nonce"):
        raise DriverError("approval nonce missing")
    return dict(payload)


def validate_import_origins(
    origins: Sequence[Path], target_venv: Path, *, forbidden_roots: Sequence[Path]
) -> None:
    site_packages_marker = str(target_venv.resolve()) + os.sep
    for origin in origins:
        resolved = str(origin.resolve())
        for root in forbidden_roots:
            if resolved == str(root.resolve()) or resolved.startswith(str(root.resolve()) + os.sep):
                raise DriverError(f"source shadowing detected: {origin}")
        if not resolved.startswith(site_packages_marker) or "site-packages" not in resolved:
            raise DriverError(f"import-origin mismatch: {origin}")


def validate_listener(host: str, port: int, *, expected_pid: int, observed_pid: int) -> None:
    if host != "127.0.0.1" or port != 18791:
        raise DriverError("listener must be loopback-only on 127.0.0.1:18791")
    if expected_pid != observed_pid:
        raise DriverError("listener pid does not belong to controlled RC process")


def validate_service_snapshot(before: Mapping[int, Any], after: Mapping[int, Any]) -> None:
    if dict(before) != dict(after):
        raise DriverError("legacy service fingerprint changed")


def _verify_record_chain(checkpoint: Mapping[str, Any]) -> None:
    previous = ""
    passed_states: list[str] = []
    expected_state: State | None = State.PREFLIGHT
    previous_state: State | None = None
    explicit_rollback_seen = False
    for sequence, record in enumerate(checkpoint.get("records", []), start=1):
        candidate = dict(record)
        record_hash = candidate.pop("record_hash", None)
        if candidate.get("sequence") != sequence or candidate.get("previous_record_hash") != previous:
            raise DriverError("checkpoint record hash-chain mismatch")
        expected = _sha256_bytes(_canonical_json(candidate))
        if not isinstance(record_hash, str) or not hmac.compare_digest(record_hash, expected):
            raise DriverError("checkpoint record tamper detected")
        if candidate.get("deployment_id") != checkpoint.get("deployment_id"):
            raise DriverError("checkpoint record deployment binding mismatch")
        if candidate.get("plan_hash") != checkpoint.get("plan_hash"):
            raise DriverError("checkpoint record plan binding mismatch")
        if candidate.get("state") not in {state.value for state in State}:
            raise DriverError("checkpoint record contains unknown state")
        state = State(candidate["state"])
        explicit_post_complete_rollback = (
            expected_state is None
            and previous_state == State.COMPLETE
            and state == State.ROLLBACK
        )
        explicit_operator_rollback = (
            checkpoint.get("rollback_trigger") == "EXPLICIT"
            and state == State.ROLLBACK
            and not explicit_rollback_seen
        )
        if explicit_operator_rollback:
            explicit_rollback_seen = True
        if (
            state != expected_state
            and not explicit_post_complete_rollback
            and not explicit_operator_rollback
        ):
            raise DriverError(
                f"checkpoint state-sequence mismatch: expected "
                f"{expected_state.value if expected_state else None}, got {state.value}"
            )
        if candidate.get("status") == "PASS":
            passed_states.append(candidate["state"])
            if state == State.ROLLBACK:
                expected_state = State.COMPLETE
            else:
                expected_state = NORMAL_NEXT[state]
        elif candidate.get("status") != "FAIL":
            raise DriverError("checkpoint record contains unknown status")
        else:
            expected_state = (
                None
                if state == State.ROLLBACK
                or (state == State.COMPLETE and previous_state == State.ROLLBACK)
                else State.ROLLBACK
            )
        previous_state = state
        previous = record_hash
    if passed_states != checkpoint.get("completed_states", []):
        raise DriverError("checkpoint completed-state reconciliation mismatch")
    actual_next = checkpoint.get("next_state")
    if (
        checkpoint.get("mode") == DeployMode.VERIFY_ONLY.value
        and checkpoint.get("status") == "VERIFY_ONLY_COMPLETE"
        and previous_state == State.VERIFY_ONLY
    ):
        expected_state = None
    expected_next = expected_state.value if expected_state else None
    if actual_next != expected_next:
        raise DriverError(
            f"checkpoint next-state reconciliation mismatch: expected {expected_next}, got {actual_next}"
        )


def load_checkpoint(path: Path) -> dict[str, Any]:
    try:
        checkpoint = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DriverError(f"cannot load checkpoint: {exc}") from exc
    stored_hmac = checkpoint.pop("checkpoint_hmac", None)
    key = _read_checkpoint_auth_key(path.parent.parent)
    expected_hmac = hmac.new(key, _canonical_json(checkpoint), hashlib.sha256).hexdigest()
    if not isinstance(stored_hmac, str) or not hmac.compare_digest(stored_hmac, expected_hmac):
        raise DriverError("checkpoint HMAC authentication failed")
    stored_hash = checkpoint.pop("checkpoint_hash", None)
    if checkpoint.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise DriverError("checkpoint schema version mismatch")
    expected = _sha256_bytes(_canonical_json(checkpoint))
    if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, expected):
        raise DriverError("checkpoint tamper or hash mismatch")
    checkpoint["checkpoint_hash"] = stored_hash
    checkpoint["checkpoint_hmac"] = stored_hmac
    _verify_record_chain(checkpoint)
    return checkpoint


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_checkpoint_auth_key(root: Path) -> bytes:
    path = root / ".checkpoint-auth.key"
    if path.is_symlink() or not path.is_file():
        raise DriverError("checkpoint authentication key is missing or unsafe")
    if path.stat().st_mode & 0o077:
        raise DriverError("checkpoint authentication key permissions must be 0600")
    key = path.read_bytes()
    if len(key) != 32:
        raise DriverError("checkpoint authentication key must contain 32 bytes")
    return key


def _ensure_checkpoint_auth_key(root: Path) -> bytes:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / ".checkpoint-auth.key"
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        return _read_checkpoint_auth_key(root)
    key = os.urandom(32)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return _read_checkpoint_auth_key(root)


def _save_checkpoint(path: Path, checkpoint: dict[str, Any]) -> None:
    value = dict(checkpoint)
    value.pop("checkpoint_hash", None)
    value.pop("checkpoint_hmac", None)
    value["checkpoint_hash"] = _sha256_bytes(_canonical_json(value))
    key = _read_checkpoint_auth_key(path.parent.parent)
    value["checkpoint_hmac"] = hmac.new(
        key, _canonical_json(value), hashlib.sha256
    ).hexdigest()
    checkpoint["checkpoint_hash"] = value["checkpoint_hash"]
    checkpoint["checkpoint_hmac"] = value["checkpoint_hmac"]
    _atomic_write_json(path, value)


class ApprovalLedger:
    def __init__(self, root: Path):
        self.path = root / "approval-ledger.json"
        self.lock_path = root / ".approval-ledger.lock"

    def consume(self, approval: Mapping[str, Any], deployment_id: str) -> str:
        payload = approval["payload"]
        nonce = payload["nonce"]
        digest = _sha256_bytes(_canonical_json(approval))
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            ledger = {"schema_version": 1, "consumed": {}}
            if self.path.exists():
                ledger = json.loads(self.path.read_text(encoding="utf-8"))
            prior = ledger["consumed"].get(nonce)
            if prior is not None:
                if prior.get("deployment_id") == deployment_id and prior.get("approval_digest") == digest:
                    return digest
                raise DriverError("approval replay detected")
            ledger["consumed"][nonce] = {
                "deployment_id": deployment_id,
                "approval_digest": digest,
                "consumed_at": _iso(_utc_now()),
            }
            _atomic_write_json(self.path, ledger)
            return digest

    def verify_consumed(self, approval: Mapping[str, Any], deployment_id: str) -> None:
        payload = approval["payload"]
        digest = _sha256_bytes(_canonical_json(approval))
        if not self.path.exists():
            raise DriverError("approval was not consumed at canonical migration")
        ledger = json.loads(self.path.read_text(encoding="utf-8"))
        prior = ledger.get("consumed", {}).get(payload["nonce"])
        if prior is None or prior.get("deployment_id") != deployment_id or prior.get("approval_digest") != digest:
            raise DriverError("approval replay or ledger binding mismatch")


class FakeBackend:
    """Deterministic failure-injection backend used by the driver tests."""

    def __init__(
        self,
        *,
        failures: Mapping[State, str] | None = None,
        timeouts: set[State] | None = None,
        stop_after: State | None = None,
        use_real_artifact_verify: bool = False,
    ):
        self.failures = dict(failures or {})
        self.timeouts = set(timeouts or set())
        self.stop_after = stop_after
        self.use_real_artifact_verify = use_real_artifact_verify
        self.calls: list[State] = []

    def run_state(self, state: State, context: Mapping[str, Any]) -> dict[str, Any]:
        self.calls.append(state)
        if state in self.timeouts:
            raise StepTimeout(f"timeout in {state.value}")
        if state in self.failures:
            raise DriverError(self.failures[state])
        if state == State.ARTIFACT_VERIFY and self.use_real_artifact_verify:
            verify_artifacts(context["plan"])
        if state == State.ROLLBACK:
            return {"logical": True, "physical_restore": False}
        if state == State.CONTROLLED_START:
            return {"simulated": True, "listener_started": False}
        return {"verified": True, "state": state.value}


def verify_artifacts(plan: DeployPlan) -> dict[str, Any]:
    checks = (
        ("wheel", plan.wheel, plan.wheel_sha256),
        ("manifest", plan.manifest, plan.manifest_sha256),
        ("runbook", plan.runbook, plan.runbook_sha256),
    )
    for name, path, expected in checks:
        if not path.is_file():
            raise DriverError(f"{name} artifact missing: {path}")
        actual = _sha256_file(path)
        if not hmac.compare_digest(actual, expected):
            raise DriverError(f"{name} hash mismatch: expected {expected}, got {actual}")
    try:
        manifest = json.loads(plan.manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DriverError(f"manifest JSON invalid: {exc}") from exc
    declared = manifest.get("wheel", {}).get("sha256")
    if declared != plan.wheel_sha256:
        raise DriverError("manifest wheel binding mismatch")
    return {"wheel": plan.wheel_sha256, "manifest": plan.manifest_sha256, "runbook": plan.runbook_sha256}


def _db_checks(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        connection.execute("BEGIN")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        logical_hasher = hashlib.sha256()
        for name, sql in tables:
            if name.startswith("sqlite_"):
                continue
            quoted_name = _quote_sql_identifier(name)
            columns = [
                row[1]
                for row in connection.execute("PRAGMA table_info(" + quoted_name + ")")
            ]
            order = ",".join(_quote_sql_identifier(column) for column in columns)
            rows = connection.execute(
                "SELECT * FROM " + quoted_name + (f" ORDER BY {order}" if order else "")
            )
            logical_hasher.update(
                _canonical_json({"table": name, "sql": sql, "columns": columns})
            )
            for row in rows:
                normalized = [
                    {"bytes_hex": value.hex()} if isinstance(value, bytes) else value
                    for value in row
                ]
                logical_hasher.update(_canonical_json(normalized))
    finally:
        connection.close()
    if integrity != "ok":
        raise DriverError(f"database integrity failure: {integrity}")
    if foreign_keys:
        raise DriverError(f"database foreign-key failure: {len(foreign_keys)}")
    return {
        "integrity_check": integrity,
        "foreign_key_violations": 0,
        "logical_fingerprint": logical_hasher.hexdigest(),
    }


def _board_baseline(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        connection.execute("BEGIN")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name LIKE 'executive_board_%' ORDER BY name"
            )
        ]
        meta_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone() is not None
        version = None
        if meta_exists:
            row = connection.execute(
                "SELECT value FROM agents_os_meta WHERE key=?", (BOARD_SCHEMA_META_KEY,)
            ).fetchone()
            version = None if row is None else str(row[0])
    finally:
        connection.close()
    return {"tables": tables, "schema_version": version, "meta_table_existed": meta_exists}


def _restore_absent_meta_table(
    path: Path, baseline: Mapping[str, Any]
) -> None:
    if baseline.get("meta_table_existed"):
        return
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.execute("BEGIN IMMEDIATE")
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone()
        if exists is None:
            connection.commit()
            return
        remaining = connection.execute("SELECT COUNT(*) FROM agents_os_meta").fetchone()[0]
        if remaining:
            raise DriverError(
                "cannot remove migration-created agents_os_meta: non-Board rows remain"
            )
        connection.execute("DROP TABLE agents_os_meta")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _checkpoint_output(checkpoint: Mapping[str, Any], state: State) -> Mapping[str, Any]:
    for record in checkpoint.get("records", []):
        if record.get("state") == state.value and record.get("status") == "PASS":
            return record.get("output", {})
    raise DriverError(f"required checkpoint evidence missing: {state.value}")


def _quote_sql_identifier(identifier: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
        raise DriverError(f"unsafe SQLite identifier: {identifier!r}")
    return '"' + identifier.replace('"', '""') + '"'


def _online_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise DriverError(f"backup destination already exists: {destination}")
    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=10)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    except Exception:
        destination_connection.close()
        source_connection.close()
        if destination.exists():
            destination.unlink()
        raise
    destination_connection.close()
    source_connection.close()


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def _listener_observation(port: int) -> tuple[str, int] | None:
    result = subprocess.run(
        ["ss", "-H", "-ltnp", f"sport = :{port}"],
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    if len(lines) != 1:
        raise DriverError(f"ambiguous listener attribution on port {port}")
    line = lines[0]
    address_match = re.search(r"\s(\S+:%d)\s" % port, line)
    pid_match = re.search(r"pid=(\d+)", line)
    if not address_match or not pid_match:
        raise DriverError(f"cannot attribute listener on port {port}: {line}")
    address = address_match.group(1)
    host = address.rsplit(":", 1)[0].strip("[]")
    return host, int(pid_match.group(1))


def _service_snapshot(ports: Sequence[int] = (18789, 18790, 38789)) -> dict[int, Any]:
    snapshot: dict[int, Any] = {}
    command = ["ss", "-H", "-ltnp"]
    output = subprocess.run(command, check=True, text=True, capture_output=True, timeout=10).stdout
    for port in ports:
        lines = sorted(line for line in output.splitlines() if f":{port} " in line or line.rstrip().endswith(f":{port}"))
        snapshot[port] = {"listener_hash": _sha256_bytes("\n".join(lines).encode()), "present": bool(lines)}
    return snapshot


def _active_writer_lock(db_path: Path) -> bool:
    try:
        stat = db_path.stat()
        inode = str(stat.st_ino)
        for line in Path("/proc/locks").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) > 5 and fields[3] == "WRITE" and fields[5].endswith(f":{inode}"):
                return True
    except (OSError, IndexError):
        return False
    return False


class RealBackend:
    """Filesystem/process backend. Unsafe effects are enabled only in execute mode."""

    def __init__(self, timeout: int = DEFAULT_STEP_TIMEOUT):
        self.timeout = timeout

    def run_state(self, state: State, context: Mapping[str, Any]) -> dict[str, Any]:
        method = getattr(self, f"_state_{state.value.lower()}")
        return method(context)

    @staticmethod
    def _paths(context: Mapping[str, Any]) -> tuple[DeployPlan, Path, Path, Path]:
        plan: DeployPlan = context["plan"]
        deployment_dir = Path(context["deployment_dir"])
        sandbox = deployment_dir / "sandbox"
        mode = DeployMode(context["mode"])
        canonical = (
            plan.canonical_db
            if mode in {DeployMode.EXECUTE, DeployMode.VERIFY_ONLY}
            else sandbox / "canonical.sqlite"
        )
        venv = (
            plan.target_venv
            if mode == DeployMode.EXECUTE
            else plan.release / "venv-installed"
            if mode == DeployMode.VERIFY_ONLY
            else sandbox / "venv"
        )
        return plan, deployment_dir, canonical, venv

    def _state_preflight(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, deployment_dir, canonical, _venv = self._paths(context)
        if DeployMode(context["mode"]) == DeployMode.EXECUTE:
            raise DriverError(
                "CANONICAL_EXECUTION_DISABLED_IN_P1: transactional canonical adapter "
                "and hash-pinned dependency lock are not yet verified"
            )
        if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME"):
            raise DriverError("PYTHONPATH/PYTHONHOME must be unset")
        if plan.target_venv.resolve() == ACTIVE_VENV.resolve():
            raise DriverError("target venv aliases active venv")
        if plan.host != "127.0.0.1" or plan.port != 18791:
            raise DriverError("target listener is not 127.0.0.1:18791")
        deployment_dir.mkdir(parents=True, exist_ok=True)
        if DeployMode(context["mode"]) == DeployMode.DRY_RUN:
            canonical.parent.mkdir(parents=True, exist_ok=True)
            if not canonical.exists():
                _online_backup(plan.canonical_db, canonical)
        return {"canonical_target": str(canonical), "target_venv": str(_venv)}

    def _state_artifact_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        return verify_artifacts(context["plan"])

    def _state_service_and_port_check(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan: DeployPlan = context["plan"]
        if _port_open(plan.host, plan.port):
            raise DriverError("port 18791 occupied by unknown or pre-existing process")
        return {"legacy_services": _service_snapshot(), "port_18791": "closed"}

    def _state_database_backup(self, context: Mapping[str, Any]) -> dict[str, Any]:
        _plan, deployment_dir, canonical, _venv = self._paths(context)
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            return {"read_only": True, "board_baseline": _board_baseline(canonical), **_db_checks(canonical)}
        if _active_writer_lock(canonical):
            raise DriverError("active DB writer detected")
        backup = deployment_dir / "predeploy/state.predeploy.sqlite"
        _online_backup(canonical, backup)
        return {
            "backup": str(backup),
            "sha256": _sha256_file(backup),
            "board_baseline": _board_baseline(backup),
            **_db_checks(backup),
        }

    def _state_backup_restore_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            return {"not_applicable": True, "reason": "verify-only performs no database copies"}
        deployment_dir = Path(context["deployment_dir"])
        backup = deployment_dir / "predeploy/state.predeploy.sqlite"
        restore = deployment_dir / "restore-test/state.restore-test.sqlite"
        _online_backup(backup, restore)
        before = _db_checks(backup)
        after = _db_checks(restore)
        if before["logical_fingerprint"] != after["logical_fingerprint"]:
            raise DriverError("restore-test logical mismatch")
        return {"restore": str(restore), "sha256": _sha256_file(restore), **after}

    def _state_staged_venv_install(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, _deployment_dir, _canonical, venv = self._paths(context)
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            if not (venv / "bin/python").is_file():
                raise DriverError(f"verified installed venv missing: {venv}")
            return {"venv": str(venv), "read_only_reuse": True}
        marker = venv / ".executive-board-wheel-sha256"
        if venv.exists():
            if marker.is_file() and marker.read_text().strip() == plan.wheel_sha256:
                return {"venv": str(venv), "idempotent_reuse": True}
            raise DriverError(f"target venv already exists without matching marker: {venv}")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=self.timeout)
        clean_env = dict(os.environ)
        clean_env.pop("PYTHONPATH", None)
        clean_env.pop("PYTHONHOME", None)
        clean_env["PYTHONNOUSERSITE"] = "1"
        subprocess.run(
            [str(venv / "bin/pip"), "install", "--disable-pip-version-check", str(plan.wheel)],
            check=True,
            timeout=self.timeout,
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        subprocess.run(
            [str(venv / "bin/pip"), "check"],
            check=True,
            timeout=60,
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        marker.write_text(plan.wheel_sha256 + "\n", encoding="utf-8")
        return {"venv": str(venv), "python": str(venv / "bin/python")}

    def _state_installed_parity_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, deployment_dir, _canonical, venv = self._paths(context)
        script = deployment_dir / "installed-parity-check.py"
        script.write_text(
            "import hashlib,importlib,json,os,pathlib,sys\n"
            f"manifest=json.loads(pathlib.Path({str(plan.manifest)!r}).read_text())\n"
            f"venv=pathlib.Path({str(venv)!r}).resolve()\n"
            f"mods={list(MODULES)!r}\n"
            "out=[]\n"
            "for name in mods:\n"
            " m=importlib.import_module(name); p=pathlib.Path(m.__file__).resolve()\n"
            " if not str(p).startswith(str(venv)+os.sep) or 'site-packages' not in str(p): raise SystemExit('import-origin mismatch: '+str(p))\n"
            " h=hashlib.sha256(p.read_bytes()).hexdigest(); e=manifest['modules'][name]['sha256']\n"
            " if h!=e: raise SystemExit('installed hash mismatch: '+name)\n"
            " out.append({'module':name,'origin':str(p),'sha256':h})\n"
            "print(json.dumps(out,sort_keys=True))\n",
            encoding="utf-8",
        )
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"}
        result = subprocess.run(
            [str(venv / "bin/python"), "-I", str(script)],
            cwd="/tmp",
            env=env,
            check=True,
            text=True,
            capture_output=True,
            timeout=60,
        )
        origins = [Path(item["origin"]) for item in json.loads(result.stdout)]
        validate_import_origins(origins, venv, forbidden_roots=FORBIDDEN_SOURCE_ROOTS)
        return {"module_count": len(origins), "repo_on_sys_path": False}

    def _migration_copy(self, context: Mapping[str, Any], *, rollback_after: bool) -> dict[str, Any]:
        plan, deployment_dir, _canonical, venv = self._paths(context)
        name = "rollback" if rollback_after else "migration"
        source = deployment_dir / "predeploy/state.predeploy.sqlite"
        target = deployment_dir / f"staging/{name}.sqlite"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise DriverError(f"staged {name} copy already exists")
        shutil.copy2(source, target)
        output = deployment_dir / f"staging/{name}-result.json"
        command = [
            str(venv / "bin/python"),
            "-I",
            str(plan.release / "scripts/verify_migration.py"),
            "--db",
            str(target),
            "--output",
            str(output),
        ]
        if rollback_after:
            command.append("--rollback-after")
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"}
        subprocess.run(
            command,
            cwd="/tmp",
            env=env,
            check=True,
            timeout=self.timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        result = json.loads(output.read_text(encoding="utf-8"))
        if result.get("status") != "pass":
            raise DriverError(f"{name} verifier did not pass")
        return result

    def _state_migration_dry_run(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            return {"not_applicable": True, "reason": "verify-only performs no database copies"}
        return self._migration_copy(context, rollback_after=False)

    def _state_rollback_dry_run(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            return {"not_applicable": True, "reason": "verify-only performs no database copies"}
        result = self._migration_copy(context, rollback_after=True)
        # Runbook C4 must pass before canonical migration.  The explicit
        # VERIFY_ONLY state later repeats the same gate immediately before start.
        result["precanonical_verify_only"] = self._state_verify_only(context)
        return result

    def _state_canonical_migration(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, deployment_dir, canonical, venv = self._paths(context)
        if DeployMode(context["mode"]) == DeployMode.VERIFY_ONLY:
            return {"not_applicable": True, "database_changed": False}
        if DeployMode(context["mode"]) != DeployMode.EXECUTE:
            # The dry-run canonical target is the same isolated copy that a later
            # explicit or failure rollback must reconcile; never use the live DB.
            target = canonical
            if not target.exists():
                raise DriverError("isolated canonical copy missing before simulated migration")
            output = deployment_dir / "sandbox/canonical-migration-result.json"
            env = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"}
            subprocess.run(
                [str(venv / "bin/python"), "-I", str(plan.release / "scripts/verify_migration.py"), "--db", str(target), "--output", str(output)],
                cwd="/tmp", env=env, check=True, timeout=self.timeout,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            return {"simulated": True, "database": str(target), **json.loads(output.read_text())}
        raise DriverError("CANONICAL_EXECUTION_DISABLED_IN_P1")

    def _state_verify_only(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, deployment_dir, canonical, venv = self._paths(context)
        if _port_open(plan.host, plan.port):
            raise DriverError("port 18791 occupied before verify-only")
        before_hash = _sha256_file(canonical)
        data_root = deployment_dir / "verify-only-data"
        env = dict(os.environ)
        env["PYTHONPATH"] = "/mnt/d/HermesAgent/app"
        command = [
            str(plan.release / "scripts/start_installed_executive_board.sh"),
            str(venv),
            str(data_root),
            str(plan.manifest),
            str(plan.wheel),
            "--host", plan.host,
            "--port", str(plan.port),
            "--verify-only",
        ]
        result = subprocess.run(command, cwd="/tmp", env=env, check=True, text=True, capture_output=True, timeout=30)
        if "EXECUTIVE_BOARD_0_19_0_LAUNCHER_VERIFICATION=PASS" not in result.stdout:
            raise DriverError("verify-only marker missing")
        if _port_open(plan.host, plan.port):
            raise DriverError("verify-only unexpectedly opened listener")
        if _sha256_file(canonical) != before_hash:
            raise DriverError("verify-only changed database")
        return {"marker": "PASS", "listener_started": False, "database_changed": False}

    def _state_controlled_start(self, context: Mapping[str, Any]) -> dict[str, Any]:
        mode = DeployMode(context["mode"])
        if mode != DeployMode.EXECUTE:
            return {"simulated": True, "listener_started": False}
        raise DriverError("CONTROLLED_START_DISABLED_IN_P1")

    def _state_health_check(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) != DeployMode.EXECUTE:
            return {"simulated": True, "status": "ok"}
        plan: DeployPlan = context["plan"]
        with urllib.request.urlopen(f"http://{plan.host}:{plan.port}/health", timeout=5) as response:
            payload = json.loads(response.read())
        if response.status != 200 or payload.get("status") != "ok":
            raise DriverError("health check failed")
        return {"status": "ok", "http_status": 200}

    def _state_security_e2e(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) != DeployMode.EXECUTE:
            return {"simulated": True, "approval_binding": True, "loopback_only": True}
        plan: DeployPlan = context["plan"]
        if plan.host != "127.0.0.1" or not _port_open(plan.host, plan.port):
            raise DriverError("security E2E listener gate failed")
        return {"approval_binding": True, "loopback_only": True}

    def _state_board_lifecycle_e2e(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) != DeployMode.EXECUTE:
            return {"simulated": True, "installed_lifecycle_contract": True}
        # Actual deploy must supply an installed, release-owned E2E command in the manifest.
        plan: DeployPlan = context["plan"]
        manifest = json.loads(plan.manifest.read_text(encoding="utf-8"))
        command = manifest.get("deploy_driver", {}).get("board_lifecycle_e2e_command")
        if not command:
            raise DriverError("manifest lacks installed Board lifecycle E2E command")
        subprocess.run(command, check=True, timeout=self.timeout, cwd="/tmp", env={"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"})
        return {"installed_lifecycle_contract": True}

    def _state_commit_deploy(self, context: Mapping[str, Any]) -> dict[str, Any]:
        deployment_dir = Path(context["deployment_dir"])
        baseline = self._baseline_services(context["checkpoint"])
        if baseline is None:  # required=True is fail-closed; narrows the type for static checkers
            raise DriverError("legacy service baseline missing from checkpoint")
        validate_service_snapshot(baseline, _service_snapshot())
        marker = deployment_dir / "DEPLOY-COMMITTED.json"
        _atomic_write_json(marker, {"deployment_id": context["deployment_id"], "plan_hash": context["plan"].canonical_hash, "committed_at": _iso(_utc_now())})
        return {"commit_marker": str(marker)}

    @staticmethod
    def _baseline_services(
        checkpoint: Mapping[str, Any], *, required: bool = True
    ) -> Mapping[int, Any] | None:
        for record in checkpoint.get("records", []):
            if record.get("state") == State.SERVICE_AND_PORT_CHECK.value and record.get("status") == "PASS":
                services = record.get("output", {}).get("legacy_services")
                if services is not None:
                    return {int(key): value for key, value in services.items()}
        if required:
            raise DriverError("legacy service baseline missing from checkpoint")
        return None

    def _state_rollback(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan, deployment_dir, canonical, venv = self._paths(context)
        checkpoint = context["checkpoint"]
        pid = None
        for record in checkpoint.get("records", []):
            if record.get("state") == State.CONTROLLED_START.value and record.get("status") == "PASS":
                pid = record.get("output", {}).get("pid")
        if pid and DeployMode(context["mode"]) == DeployMode.EXECUTE:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        logical = DeployMode(context["mode"]) != DeployMode.VERIFY_ONLY and (
            State.CANONICAL_MIGRATION.value in checkpoint.get("completed_states", [])
            or checkpoint.get("failed_state") == State.CANONICAL_MIGRATION.value
        )
        if logical:
            if not venv.exists():
                raise DriverError("logical rollback cannot run: staged venv missing")
            script = deployment_dir / "logical-rollback.py"
            script.write_text(
                "import sqlite3,sys\nfrom hermes_cli.agents_os_executive_board import rollback\n"
                "c=sqlite3.connect(sys.argv[1]); rollback(c); c.close()\n",
                encoding="utf-8",
            )
            subprocess.run([str(venv / "bin/python"), "-I", str(script), str(canonical)], cwd="/tmp", check=True, timeout=60, env={"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"})
            baseline = _checkpoint_output(checkpoint, State.DATABASE_BACKUP)
            _restore_absent_meta_table(canonical, baseline.get("board_baseline", {}))
            after = _db_checks(canonical)
            if after["logical_fingerprint"] != baseline.get("logical_fingerprint"):
                raise DriverError("logical rollback did not restore database baseline")
            if _board_baseline(canonical) != baseline.get("board_baseline"):
                raise DriverError("logical rollback did not restore Board schema baseline")
        baseline = self._baseline_services(checkpoint, required=False)
        if baseline is not None:
            validate_service_snapshot(baseline, _service_snapshot())
        return {"logical": logical, "physical_restore": False, "new_pid_stopped": bool(pid)}

    def _state_complete(self, context: Mapping[str, Any]) -> dict[str, Any]:
        return {"terminal": True}


class DeploymentDriver:
    def __init__(
        self,
        plan: DeployPlan,
        checkpoint_root: Path,
        backend: FakeBackend | RealBackend,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ):
        self.plan = plan
        self.root = Path(checkpoint_root)
        self.backend = backend
        self.clock = clock
        self.ledger = ApprovalLedger(self.root)

    def _deployment_dir(self, deployment_id: str) -> Path:
        if not deployment_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in deployment_id):
            raise DriverError("invalid deployment id")
        return self.root / deployment_id

    @contextmanager
    def _lease(self, deployment_id: str):
        self._deployment_dir(deployment_id)  # validates before creating lease paths
        lease_dir = self.root / ".leases"
        lease_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lease_path = lease_dir / f"{deployment_id}.lock"
        descriptor = os.open(
            lease_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DriverError(f"deployment lease already held: {deployment_id}") from exc
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def initialize(self, mode: DeployMode, deployment_id: str) -> dict[str, Any]:
        if mode == DeployMode.PLAN:
            raise DriverError("plan mode does not create checkpoints")
        _ensure_checkpoint_auth_key(self.root)
        directory = self._deployment_dir(deployment_id)
        if directory.exists():
            raise DriverError(f"deployment already exists: {deployment_id}")
        directory.mkdir(parents=True, mode=0o700)
        now = _iso(self.clock())
        checkpoint: dict[str, Any] = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "deployment_id": deployment_id,
            "mode": mode.value,
            "plan_hash": self.plan.canonical_hash,
            "status": "IN_PROGRESS",
            "current_state": None,
            "next_state": State.PREFLIGHT.value,
            "completed_states": [],
            "records": [],
            "created_at": now,
            "updated_at": now,
            "failed_state": None,
            "error": None,
            "rollback": {"logical": False, "physical_restore": False},
            "rollback_trigger": None,
            "approval_digest": None,
        }
        _save_checkpoint(directory / "checkpoint.json", checkpoint)
        return checkpoint

    def transition(self, checkpoint: dict[str, Any], target: State, *, failure: bool = False) -> None:
        if target == State.ROLLBACK and failure:
            return
        expected = checkpoint.get("next_state")
        if expected != target.value:
            raise StateError(f"illegal transition: expected {expected}, got {target.value}")

    def _context(self, checkpoint: dict[str, Any], approval: Mapping[str, Any] | None) -> dict[str, Any]:
        return {
            "plan": self.plan,
            "deployment_id": checkpoint["deployment_id"],
            "deployment_dir": str(self._deployment_dir(checkpoint["deployment_id"])),
            "mode": checkpoint["mode"],
            "checkpoint": checkpoint,
            "approval": approval,
        }

    def _record(
        self,
        checkpoint: dict[str, Any],
        state: State,
        status: str,
        *,
        output: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        previous = checkpoint["records"][-1]["record_hash"] if checkpoint["records"] else ""
        record: dict[str, Any] = {
            "sequence": len(checkpoint["records"]) + 1,
            "deployment_id": checkpoint["deployment_id"],
            "plan_hash": checkpoint["plan_hash"],
            "state": state.value,
            "status": status,
            "timestamp": _iso(self.clock()),
            "output": dict(output or {}),
            "error": error,
            "previous_record_hash": previous,
        }
        record["record_hash"] = _sha256_bytes(_canonical_json(record))
        checkpoint["records"].append(record)
        checkpoint["updated_at"] = _iso(self.clock())

    def _persist(self, checkpoint: dict[str, Any]) -> None:
        _save_checkpoint(self._deployment_dir(checkpoint["deployment_id"]) / "checkpoint.json", checkpoint)

    def _verify_approval_for_state(
        self,
        state: State,
        checkpoint: dict[str, Any],
        approval: Mapping[str, Any] | None,
        approval_key: bytes | None,
    ) -> None:
        if DeployMode(checkpoint["mode"]) != DeployMode.EXECUTE or state not in {State.CANONICAL_MIGRATION, State.CONTROLLED_START}:
            return
        if approval is None or not approval_key:
            raise DriverError("valid owner approval is required")
        verify_approval(approval, self.plan, checkpoint["deployment_id"], approval_key, now=self.clock())
        if state == State.CANONICAL_MIGRATION:
            digest = self.ledger.consume(approval, checkpoint["deployment_id"])
            checkpoint["approval_digest"] = digest
        else:
            self.ledger.verify_consumed(approval, checkpoint["deployment_id"])

    def _run_from_checkpoint(
        self,
        checkpoint: dict[str, Any],
        *,
        approval: Mapping[str, Any] | None = None,
        approval_key: bytes | None = None,
    ) -> dict[str, Any]:
        mode = DeployMode(checkpoint["mode"])
        while checkpoint.get("next_state"):
            state = State(checkpoint["next_state"])
            self.transition(checkpoint, state)
            if mode == DeployMode.VERIFY_ONLY and state == State.CONTROLLED_START:
                checkpoint["status"] = "VERIFY_ONLY_COMPLETE"
                checkpoint["next_state"] = None
                self._persist(checkpoint)
                break
            try:
                if state == State.PREFLIGHT and (os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME")):
                    raise DriverError("PYTHONPATH/PYTHONHOME must be unset")
                self._verify_approval_for_state(state, checkpoint, approval, approval_key)
                output = self.backend.run_state(state, self._context(checkpoint, approval))
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                self._record(checkpoint, state, "FAIL", error=error)
                checkpoint["failed_state"] = state.value
                checkpoint["error"] = str(exc)
                checkpoint["current_state"] = state.value
                checkpoint["next_state"] = State.ROLLBACK.value
                checkpoint["rollback_trigger"] = "FAILURE"
                self._persist(checkpoint)
                if state == State.ROLLBACK:
                    checkpoint["status"] = "BLOCKED"
                    checkpoint["next_state"] = None
                    self._persist(checkpoint)
                    return checkpoint
                return self._run_rollback(checkpoint, approval=approval)
            self._record(checkpoint, state, "PASS", output=output)
            checkpoint["completed_states"].append(state.value)
            checkpoint["current_state"] = state.value
            if state == State.COMPLETE:
                if checkpoint.get("error"):
                    checkpoint["status"] = "ROLLED_BACK"
                elif mode == DeployMode.DRY_RUN:
                    checkpoint["status"] = "DRY_RUN_COMPLETE"
                elif mode == DeployMode.EXECUTE:
                    checkpoint["status"] = "DEPLOYED"
                else:
                    checkpoint["status"] = "COMPLETE"
                checkpoint["next_state"] = None
            else:
                next_state = NORMAL_NEXT[state]
                checkpoint["next_state"] = next_state.value if next_state else None
            self._persist(checkpoint)
            if getattr(self.backend, "stop_after", None) == state:
                checkpoint["status"] = "PAUSED"
                self._persist(checkpoint)
                return checkpoint
        return checkpoint

    def _run_rollback(
        self, checkpoint: dict[str, Any], *, approval: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            output = self.backend.run_state(State.ROLLBACK, self._context(checkpoint, approval))
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record(checkpoint, State.ROLLBACK, "FAIL", error=error)
            checkpoint["failed_state"] = State.ROLLBACK.value
            checkpoint["error"] = str(exc)
            checkpoint["status"] = "BLOCKED"
            checkpoint["current_state"] = State.ROLLBACK.value
            checkpoint["next_state"] = None
            self._persist(checkpoint)
            return checkpoint
        self._record(checkpoint, State.ROLLBACK, "PASS", output=output)
        checkpoint["completed_states"].append(State.ROLLBACK.value)
        checkpoint["rollback"] = dict(output)
        checkpoint["current_state"] = State.ROLLBACK.value
        checkpoint["next_state"] = State.COMPLETE.value
        self._persist(checkpoint)
        try:
            output = self.backend.run_state(State.COMPLETE, self._context(checkpoint, approval))
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record(checkpoint, State.COMPLETE, "FAIL", error=error)
            checkpoint["failed_state"] = State.COMPLETE.value
            checkpoint["error"] = str(exc)
            checkpoint["status"] = "BLOCKED"
            checkpoint["current_state"] = State.COMPLETE.value
            checkpoint["next_state"] = None
            self._persist(checkpoint)
            return checkpoint
        self._record(checkpoint, State.COMPLETE, "PASS", output=output)
        checkpoint["completed_states"].append(State.COMPLETE.value)
        checkpoint["current_state"] = State.COMPLETE.value
        checkpoint["next_state"] = None
        checkpoint_mode = DeployMode(checkpoint["mode"])
        canonical_may_have_changed = checkpoint_mode != DeployMode.VERIFY_ONLY and (
            State.CANONICAL_MIGRATION.value in checkpoint.get("completed_states", [])
            or (
                checkpoint.get("failed_state") == State.CANONICAL_MIGRATION.value
                and (
                    checkpoint_mode == DeployMode.DRY_RUN
                    or checkpoint.get("approval_digest") is not None
                )
            )
        )
        listener_may_have_started = (
            State.CONTROLLED_START.value in checkpoint.get("completed_states", [])
            or checkpoint.get("failed_state") == State.CONTROLLED_START.value
        )
        checkpoint["status"] = (
            "ROLLED_BACK" if canonical_may_have_changed or listener_may_have_started else "BLOCKED"
        )
        self._persist(checkpoint)
        return checkpoint

    def run(
        self,
        mode: DeployMode,
        deployment_id: str,
        *,
        approval: Mapping[str, Any] | None = None,
        approval_key: bytes | None = None,
    ) -> dict[str, Any]:
        if mode == DeployMode.EXECUTE and (approval is None or not approval_key):
            raise DriverError("owner approval is required for execute")
        with self._lease(deployment_id):
            checkpoint = self.initialize(mode, deployment_id)
            return self._run_from_checkpoint(checkpoint, approval=approval, approval_key=approval_key)

    def resume(
        self,
        deployment_id: str,
        *,
        approval: Mapping[str, Any] | None = None,
        approval_key: bytes | None = None,
    ) -> dict[str, Any]:
        with self._lease(deployment_id):
            path = self._deployment_dir(deployment_id) / "checkpoint.json"
            checkpoint = load_checkpoint(path)
            if checkpoint["plan_hash"] != self.plan.canonical_hash:
                raise DriverError("checkpoint plan hash mismatch")
            if checkpoint["status"] not in {"PAUSED", "IN_PROGRESS"}:
                raise DriverError(f"checkpoint is not resumable: {checkpoint['status']}")
            if checkpoint["mode"] == DeployMode.EXECUTE.value and (approval is None or not approval_key):
                raise DriverError("owner approval is required to resume execute mode")
            return self._run_from_checkpoint(checkpoint, approval=approval, approval_key=approval_key)

    def rollback(self, deployment_id: str) -> dict[str, Any]:
        with self._lease(deployment_id):
            checkpoint = load_checkpoint(self._deployment_dir(deployment_id) / "checkpoint.json")
            if checkpoint["plan_hash"] != self.plan.canonical_hash:
                raise DriverError("checkpoint plan hash mismatch")
            if checkpoint["status"] in {"ROLLED_BACK", "BLOCKED"}:
                raise DriverError(f"checkpoint cannot be rolled back again: {checkpoint['status']}")
            checkpoint["error"] = checkpoint.get("error") or "explicit rollback requested"
            checkpoint["failed_state"] = checkpoint.get("current_state")
            checkpoint["next_state"] = State.ROLLBACK.value
            checkpoint["rollback_trigger"] = "EXPLICIT"
            self._persist(checkpoint)
            return self._run_rollback(checkpoint)

    def status(self, deployment_id: str) -> dict[str, Any]:
        checkpoint = load_checkpoint(self._deployment_dir(deployment_id) / "checkpoint.json")
        if checkpoint["plan_hash"] != self.plan.canonical_hash:
            raise DriverError("checkpoint plan hash mismatch")
        return checkpoint

    def plan_document(self) -> dict[str, Any]:
        return {"plan": self.plan.to_dict(), "deploy_plan_canonical_hash": self.plan.canonical_hash}


def _default_plan(release: Path) -> DeployPlan:
    return DeployPlan(
        release=release,
        wheel=release / "wheel-final/hermes_agent-0.19.0-py3-none-any.whl",
        manifest=release / "manifest.json",
        runbook=release / "INSTALL-DEPLOY-RUNBOOK.md",
        wheel_sha256="5b7c06de1dee5cbfb10a8140f1fd14bc2295f84c98358b5457fa04f65f1020f3",
        manifest_sha256="6924b4069294ad0caa28144642067e8ab79bcc8b53ccae1726e5625bddc7a7ff",
        runbook_sha256="acaaf139e2e33e63f701ef6eaefb06d43701cd9e187f31c2067df1536a6861e7",
        canonical_db=Path("/home/goran/.hermes-doni-clean/agents_os/state.sqlite"),
        target_venv=Path("/home/goran/.venvs/hermes-agent-0.19.0-executive-board-rc2-f2ec8fa0"),
        host="127.0.0.1",
        port=18791,
        target_environment="doni-default-wsl-localhost",
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_approval_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise DriverError("approval key file must be a regular non-symlink file")
    if path.stat().st_mode & 0o077:
        raise DriverError("approval key file permissions must be 0600 or stricter")
    key = path.read_bytes()
    if not key:
        raise DriverError("approval key file is empty")
    return key


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, default=Path("/home/goran/releases/executive-board-v0.19.0-rc2-p0-20260721T152152Z"))
    parser.add_argument("--checkpoint-root", type=Path)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume", metavar="DEPLOYMENT_ID")
    parser.add_argument("--rollback", metavar="DEPLOYMENT_ID")
    parser.add_argument("--status", metavar="DEPLOYMENT_ID")
    parser.add_argument("--deployment-id")
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--approval-key-file", type=Path)
    args = parser.parse_args(argv)
    actions = [args.plan, args.dry_run, args.verify_only, args.execute, bool(args.resume), bool(args.rollback), bool(args.status)]
    if sum(bool(action) for action in actions) != 1:
        parser.error("select exactly one mode/action")
    plan = _default_plan(args.release)
    root = args.checkpoint_root or args.release / "deploy-driver-state"
    driver = DeploymentDriver(plan, root, RealBackend())
    if args.plan:
        print(json.dumps(driver.plan_document(), indent=2, sort_keys=True))
        return 0
    try:
        if args.status:
            print(json.dumps(driver.status(args.status), indent=2, sort_keys=True))
            return 0
        if args.rollback:
            result = driver.rollback(args.rollback)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "ROLLED_BACK" else 2
        approval = _load_json(args.approval) if args.approval else None
        key = _read_approval_key(args.approval_key_file) if args.approval_key_file else None
        if args.resume:
            result = driver.resume(args.resume, approval=approval, approval_key=key)
        else:
            deployment_id = args.deployment_id or f"rc2-{int(time.time())}"
            mode = DeployMode.DRY_RUN if args.dry_run else DeployMode.VERIFY_ONLY if args.verify_only else DeployMode.EXECUTE
            result = driver.run(mode, deployment_id, approval=approval, approval_key=key)
    except (DriverError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    successful = {"DRY_RUN_COMPLETE", "VERIFY_ONLY_COMPLETE", "DEPLOYED", "COMPLETE"}
    return 0 if result["status"] in successful else 2


if __name__ == "__main__":
    raise SystemExit(main())
