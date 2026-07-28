#!/usr/bin/env python3
"""Installed-wheel operation runner for Executive Board RC2 P2."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from scripts.executive_board.canonical_adapter import (
    AdapterError,
    CanonicalAdapterSpec,
    database_fingerprint,
    validate_adapter_spec,
    writer_gate,
)


def clean_runtime_env() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"}
    for name in (
        "P2_RUN_ID",
        "P2_TECHNICAL_OWNER",
        "P2_RUN_OWNERSHIP_TOKEN",
        "P2_RUN_OWNERSHIP_TOKEN_SHA256",
    ):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    return environment


def launcher_command(
    spec: CanonicalAdapterSpec, operation: str, *extra: str
) -> list[str]:
    python = spec.venv / "bin/python"
    if python.is_symlink():
        if not spec.simulation:
            raise AdapterError("production venv interpreter must not be a symlink")
    elif not python.is_file():
        raise AdapterError("installed venv Python is missing")
    return [
        str(python),
        "-I",
        str(spec.launcher),
        "--operation",
        operation,
        "--db",
        str(spec.database),
        "--manifest",
        str(spec.manifest),
        "--wheel",
        str(spec.wheel),
        *extra,
    ]


def _run(
    spec: CanonicalAdapterSpec, operation: str, *extra: str
) -> subprocess.CompletedProcess[str]:
    validate_adapter_spec(spec)
    try:
        return subprocess.run(
            launcher_command(spec, operation, *extra),
            cwd="/tmp",
            env=clean_runtime_env(),
            check=True,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdapterError(
            f"installed launcher {operation} failed (child details redacted)"
        ) from exc


def verify_installed_package(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    result = _run(spec, "package-verify")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("installed package verification output is invalid") from exc
    if payload.get("marker") != "P2_PACKAGE_VERIFY_PASS":
        raise AdapterError("installed package verification marker missing")
    origins = payload.get("origins")
    if not isinstance(origins, dict) or not origins:
        raise AdapterError("installed import-origin evidence missing")
    if any("site-packages" not in Path(value).parts for value in origins.values()):
        raise AdapterError("source shadowing detected")
    return {"marker": "PASS", "origins": origins, "source_shadowing": False}


def migrate_installed(
    spec: CanonicalAdapterSpec,
    *,
    expected_baseline_fingerprint: str | None = None,
    nonce_digest: str | None = None,
    approval_digest: str | None = None,
    deployment_id: str | None = None,
) -> dict[str, Any]:
    validate_adapter_spec(spec)
    writer_gate(spec.database)
    before = database_fingerprint(spec.database)
    if (
        expected_baseline_fingerprint is not None
        and before != expected_baseline_fingerprint
    ):
        raise AdapterError("canonical database changed after verified backup")
    baseline_connection = sqlite3.connect(
        f"file:{spec.database}?mode=ro", uri=True
    )
    try:
        baseline_meta_present = baseline_connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone() is not None
        baseline_version = None
        if baseline_meta_present:
            row = baseline_connection.execute(
                "SELECT value FROM agents_os_meta WHERE key='executive_board_schema_version'"
            ).fetchone()
            baseline_version = None if row is None else str(row[0])
    finally:
        baseline_connection.close()
    extra: tuple[str, ...] = ()
    if expected_baseline_fingerprint is not None:
        extra += ("--expected-fingerprint", expected_baseline_fingerprint)
    nonce_fields = (nonce_digest, approval_digest, deployment_id)
    if any(value is not None for value in nonce_fields):
        if not all(isinstance(value, str) and value for value in nonce_fields):
            raise AdapterError("approval nonce transaction binding is incomplete")
        extra += (
            "--nonce-digest",
            str(nonce_digest),
            "--approval-digest",
            str(approval_digest),
            "--deployment-id",
            str(deployment_id),
        )
    result = _run(spec, "migrate", *extra)
    if "P2_MIGRATE=PASS" not in result.stdout:
        raise AdapterError("installed migration marker missing")
    after = database_fingerprint(spec.database)
    return {
        "logical_fingerprint": before,
        "migrated_fingerprint": after,
        "changed": after != before,
        "entrypoint": "p2_installed_launcher:migrate",
        "baseline_meta_present": baseline_meta_present,
        "baseline_version": baseline_version,
    }


def verify_installed_approval_nonce(
    spec: CanonicalAdapterSpec,
    *,
    nonce_digest: str,
    approval_digest: str,
    deployment_id: str,
) -> dict[str, Any]:
    validate_adapter_spec(spec)
    connection = sqlite3.connect(f"file:{spec.database}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT approval_digest,deployment_id "
            "FROM p2_approval_nonces WHERE nonce_digest=?",
            (nonce_digest,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise AdapterError("atomic approval nonce receipt is missing") from exc
    finally:
        connection.close()
    if row is None or tuple(row) != (approval_digest, deployment_id):
        raise AdapterError("atomic approval nonce receipt binding mismatch")
    return {"atomic_nonce_receipt": True, "nonce_digest": nonce_digest}


def verify_installed_database(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    before = database_fingerprint(spec.database)
    result = _run(spec, "verify")
    if "P2_VERIFY=PASS" not in result.stdout:
        raise AdapterError("installed launcher verification marker missing")
    if database_fingerprint(spec.database) != before:
        raise AdapterError("verify operation changed target database")
    return {"marker": "PASS", "database_changed": False, "logical_fingerprint": before}


def run_installed_lifecycle_e2e(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    before = database_fingerprint(spec.database)
    result = _run(spec, "lifecycle-e2e")
    if "P2_BOARD_LIFECYCLE_E2E=PASS" not in result.stdout:
        raise AdapterError("installed Board lifecycle marker missing")
    if database_fingerprint(spec.database) != before:
        raise AdapterError("Board lifecycle E2E changed target database")
    return {"marker": "PASS", "target_database_changed": False}


def rollback_installed(
    spec: CanonicalAdapterSpec, baseline: dict[str, Any]
) -> dict[str, Any]:
    if not baseline.get("changed", True):
        actual = database_fingerprint(spec.database)
        if actual != baseline.get("logical_fingerprint"):
            raise AdapterError("idempotent migration baseline drifted")
        return {"logical": True, "physical_restore": False, "logical_fingerprint": actual}
    writer_gate(spec.database)
    result = _run(
        spec,
        "rollback",
        "--baseline-meta-present",
        "1" if baseline.get("baseline_meta_present") else "0",
        "--baseline-version",
        str(baseline.get("baseline_version") or ""),
    )
    if "P2_ROLLBACK=PASS" not in result.stdout:
        raise AdapterError("installed rollback marker missing")
    actual = database_fingerprint(spec.database)
    if actual != baseline.get("logical_fingerprint"):
        raise AdapterError("logical rollback did not restore baseline")
    return {"logical": True, "physical_restore": False, "logical_fingerprint": actual}


def _sqlite_clone(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def migration_dry_run(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="p2-migration-dry-run-") as raw:
        clone = Path(raw) / "state.sqlite"
        _sqlite_clone(spec.database, clone)
        clone_spec = replace(spec, database=clone, hermes_home=clone.parent.parent)
        migrated = migrate_installed(clone_spec)
        verified = verify_installed_database(clone_spec)
        return {
            "dry_run": True,
            "source_unchanged": database_fingerprint(spec.database),
            "entrypoint": migrated["entrypoint"],
            "changed": migrated["changed"],
            "verified": verified["marker"] == "PASS",
        }


def rollback_dry_run(spec: CanonicalAdapterSpec) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="p2-rollback-dry-run-") as raw:
        clone = Path(raw) / "state.sqlite"
        _sqlite_clone(spec.rollback_reference, clone)
        clone_spec = replace(spec, database=clone, hermes_home=clone.parent.parent)
        baseline = migrate_installed(clone_spec)
        verify_installed_database(clone_spec)
        rolled_back = rollback_installed(clone_spec, baseline)
        return {
            "dry_run": True,
            "entrypoint": baseline["entrypoint"],
            "logical_rollback": rolled_back["logical"],
            "physical_restore": False,
        }
