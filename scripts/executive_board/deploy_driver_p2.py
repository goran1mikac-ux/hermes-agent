#!/usr/bin/env python3
"""Executive Board RC2 P2 production-capable deploy driver.

P2 extends the verified P1 checkpoint/state-machine core without modifying the
P1 driver.  Canonical execution is enabled only through P2 plan/approval and
adapter gates; this module does not execute anything at import time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from scripts.executive_board.artifact_snapshot import (
    SnapshotInputs,
    VerifiedArtifactSnapshot,
    create_verified_snapshot,
    remove_verified_snapshot,
)
from scripts.executive_board.authenticated_ledger import (
    AuthenticatedApprovalLedger,
    LedgerError,
)

from scripts.executive_board.canonical_adapter import (
    CanonicalAdapterSpec,
    TrustedHMACKey,
    database_fingerprint,
    validate_adapter_spec,
    writer_gate,
)
from scripts.executive_board.installed_adapter import (
    clean_runtime_env,
    launcher_command,
    migrate_installed,
    migration_dry_run,
    rollback_dry_run,
    rollback_installed,
    run_installed_lifecycle_e2e,
    verify_installed_approval_nonce,
    verify_installed_database,
    verify_installed_package,
)
from scripts.executive_board.managed_runtime import (
    ManagedRuntimeController,
    RuntimeReceipt,
)
from scripts.executive_board.redaction import redact_error_text, redact_value
from scripts.executive_board.release_isolation import current_run_identity
from scripts.executive_board.release_provenance import (
    TrustedEd25519PublicKey,
    VerifiedProvenance,
    verify_release_provenance,
    verify_snapshot_provenance,
)
from scripts.executive_board.dependency_lock import (
    ensure_offline_venv,
    verify_dependency_bundle,
)

from scripts.executive_board.deploy_driver import (
    DeploymentDriver,
    DeployMode,
    DeployPlan,
    DriverError,
    RealBackend,
    State,
    _service_snapshot,
    validate_service_snapshot,
    verify_artifacts,
    _canonical_json,
    _iso,
    load_checkpoint,
    _parse_time,
    _sha256_bytes,
)

P2_PLAN_SCHEMA_VERSION = 2
P2_APPROVAL_SCHEMA_VERSION = 2
P2_MAX_APPROVAL_TTL_SECONDS = 600
P1_PLAN_HASH = "32d32dc17be2560d2914827ab7d5c97d035c8f529aad217e3b1e5fce18a6713e"
P1_DRIVER_SHA256 = "d5335725363d8b3502eac53451dfb91b623c45cc109d33f98fe82f44e76bb76f"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _approval_transaction_binding(
    context: Mapping[str, Any],
) -> tuple[str, str, str]:
    approval = context.get("approval")
    deployment_id = context.get("deployment_id")
    if not isinstance(approval, Mapping) or not isinstance(deployment_id, str):
        raise DriverError("verified approval transaction binding is missing")
    payload = approval.get("payload")
    if not isinstance(payload, Mapping) or not isinstance(payload.get("nonce"), str):
        raise DriverError("verified approval nonce is missing")
    nonce_digest = hashlib.sha256(str(payload["nonce"]).encode()).hexdigest()
    approval_digest = hashlib.sha256(_canonical_json(dict(approval))).hexdigest()
    return nonce_digest, approval_digest, deployment_id


@dataclass(frozen=True)
class P2DeployPlan(DeployPlan):
    p2_driver: Path
    p2_driver_sha256: str
    dependency_lock: Path
    dependency_lock_sha256: str
    wheelhouse: Path
    wheelhouse_manifest: Path
    wheelhouse_manifest_sha256: str
    canonical_adapter: Path
    canonical_adapter_sha256: str
    staged_launcher: Path
    staged_launcher_sha256: str
    rollback_reference: Path
    rollback_reference_sha256: str
    parent_p1_plan_hash: str
    simulation: bool = False
    root_manifest: Path | None = None
    root_manifest_signature: Path | None = None
    release_plan: Path | None = None
    release_plan_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = super().to_dict()
        value.update(
            {
                "p2_plan_schema_version": P2_PLAN_SCHEMA_VERSION,
                "p2_driver_path": str(self.p2_driver.resolve()),
                "p2_driver_sha256": self.p2_driver_sha256,
                "dependency_lock": str(self.dependency_lock.resolve()),
                "dependency_lock_sha256": self.dependency_lock_sha256,
                "wheelhouse": str(self.wheelhouse.resolve()),
                "wheelhouse_manifest": str(self.wheelhouse_manifest.resolve()),
                "wheelhouse_manifest_sha256": self.wheelhouse_manifest_sha256,
                "canonical_adapter": str(self.canonical_adapter.resolve()),
                "canonical_adapter_sha256": self.canonical_adapter_sha256,
                "staged_launcher": str(self.staged_launcher.resolve()),
                "staged_launcher_sha256": self.staged_launcher_sha256,
                "rollback_reference": str(self.rollback_reference.resolve()),
                "rollback_reference_sha256": self.rollback_reference_sha256,
                "parent_p1_plan_hash": self.parent_p1_plan_hash,
                "simulation": self.simulation,
                "root_manifest": (
                    str(self.root_manifest.resolve()) if self.root_manifest else None
                ),
                "root_manifest_signature": (
                    str(self.root_manifest_signature.resolve())
                    if self.root_manifest_signature
                    else None
                ),
                "release_plan": (
                    str(self.release_plan.resolve()) if self.release_plan else None
                ),
                "release_plan_sha256": self.release_plan_sha256,
                "execution_policy": "P2_FAIL_CLOSED_PRODUCTION_GATES",
            }
        )
        return value

    @property
    def canonical_hash(self) -> str:
        return _sha256_bytes(_canonical_json(self.to_dict()))


def create_p2_approval(
    plan: P2DeployPlan,
    deployment_id: str,
    key: bytes,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 300,
    nonce: str | None = None,
) -> dict[str, Any]:
    if not key:
        raise DriverError("approval key is empty")
    if not (1 <= ttl_seconds <= P2_MAX_APPROVAL_TTL_SECONDS):
        raise DriverError("approval TTL is outside the permitted range")
    issued = now or datetime.now(timezone.utc)
    payload = {
        "schema_version": P2_APPROVAL_SCHEMA_VERSION,
        "approval_kind": "EXECUTIVE_BOARD_RC2_P2_PRODUCTION",
        "deployment_id": deployment_id,
        "p2_plan_hash": plan.canonical_hash,
        "p2_driver_sha256": plan.p2_driver_sha256,
        "wheel_sha256": plan.wheel_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "dependency_lock_sha256": plan.dependency_lock_sha256,
        "wheelhouse_manifest_sha256": plan.wheelhouse_manifest_sha256,
        "canonical_adapter_sha256": plan.canonical_adapter_sha256,
        "staged_launcher_sha256": plan.staged_launcher_sha256,
        "target_venv": str(plan.target_venv.resolve()),
        "target_db": str(plan.canonical_db.resolve()),
        "target_host": plan.host,
        "target_port": plan.port,
        "target_environment": plan.target_environment,
        "rollback_reference": str(plan.rollback_reference.resolve()),
        "rollback_reference_sha256": plan.rollback_reference_sha256,
        "issued_at": _iso(issued),
        "expires_at": _iso(issued + timedelta(seconds=ttl_seconds)),
        "nonce": nonce or hashlib.sha256(__import__("os").urandom(32)).hexdigest(),
    }
    signature = hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()
    return {
        "algorithm": "P2-HMAC-SHA256",
        "payload": payload,
        "signature": signature,
    }


def verify_p2_approval(
    approval: Mapping[str, Any],
    plan: P2DeployPlan,
    deployment_id: str,
    key: bytes,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not key:
        raise DriverError("approval key is empty")
    if approval.get("algorithm") != "P2-HMAC-SHA256":
        raise DriverError("P2 approval envelope is required; P1 approval rejected")
    payload = approval.get("payload")
    signature = approval.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise DriverError("malformed P2 approval envelope")
    expected_signature = hmac.new(
        key, _canonical_json(payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise DriverError("P2 approval signature mismatch")
    bindings = {
        "schema_version": P2_APPROVAL_SCHEMA_VERSION,
        "approval_kind": "EXECUTIVE_BOARD_RC2_P2_PRODUCTION",
        "deployment_id": deployment_id,
        "p2_plan_hash": plan.canonical_hash,
        "p2_driver_sha256": plan.p2_driver_sha256,
        "wheel_sha256": plan.wheel_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "dependency_lock_sha256": plan.dependency_lock_sha256,
        "wheelhouse_manifest_sha256": plan.wheelhouse_manifest_sha256,
        "canonical_adapter_sha256": plan.canonical_adapter_sha256,
        "staged_launcher_sha256": plan.staged_launcher_sha256,
        "target_venv": str(plan.target_venv.resolve()),
        "target_db": str(plan.canonical_db.resolve()),
        "target_host": plan.host,
        "target_port": plan.port,
        "target_environment": plan.target_environment,
        "rollback_reference": str(plan.rollback_reference.resolve()),
        "rollback_reference_sha256": plan.rollback_reference_sha256,
    }
    for field, expected in bindings.items():
        if payload.get(field) != expected:
            raise DriverError(f"P2 approval binding mismatch: {field}")
    try:
        issued = _parse_time(payload["issued_at"])
        expires = _parse_time(payload["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DriverError("malformed P2 approval timestamp") from exc
    current = now or datetime.now(timezone.utc)
    ttl = (expires - issued).total_seconds()
    if (
        expires <= issued
        or ttl > P2_MAX_APPROVAL_TTL_SECONDS
        or current < issued
        or current > expires
    ):
        raise DriverError("P2 approval expired or outside its validity window")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise DriverError("P2 approval nonce is missing")
    return dict(payload)


def _file_check(path: Path, expected: str, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise DriverError(f"{label} is missing or unsafe")
    if not hmac.compare_digest(_sha256_file(path), expected):
        raise DriverError(f"{label} hash mismatch")


def verify_runtime_code_binding(
    plan: P2DeployPlan,
    *,
    module_files: Mapping[str, Path] | None = None,
) -> dict[str, str]:
    """Bind the code loaded by this process to the signed release manifest."""
    try:
        manifest = json.loads(plan.manifest.read_text(encoding="utf-8"))
        source_artifacts = manifest["source_artifacts"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise DriverError("release manifest lacks runtime source bindings") from exc
    actual_files = dict(
        module_files
        or {
            "deploy_driver_p2.py": Path(__file__),
            "canonical_adapter.py": Path(validate_adapter_spec.__code__.co_filename),
            "installed_adapter.py": Path(migrate_installed.__code__.co_filename),
            "managed_runtime.py": Path(ManagedRuntimeController.__init__.__code__.co_filename),
        }
    )
    expected_names = {
        "deploy_driver_p2.py",
        "canonical_adapter.py",
        "installed_adapter.py",
        "managed_runtime.py",
    }
    if set(actual_files) != expected_names:
        raise DriverError("runtime code binding set mismatch")
    verified: dict[str, str] = {}
    for name in sorted(expected_names):
        entry = source_artifacts.get(name)
        expected = entry.get("sha256") if isinstance(entry, dict) else None
        path = Path(actual_files[name])
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or path.is_symlink()
            or not path.is_file()
            or not hmac.compare_digest(_sha256_file(path), expected)
        ):
            raise DriverError(f"runtime code binding mismatch: {name}")
        verified[name] = expected
    if verified["deploy_driver_p2.py"] != plan.p2_driver_sha256:
        raise DriverError("runtime code binding mismatch: P2 plan")
    if verified["canonical_adapter.py"] != plan.canonical_adapter_sha256:
        raise DriverError("runtime code binding mismatch: canonical adapter plan")
    return verified


class P2RealBackend(RealBackend):
    """P2 backend replacing P1 live hardblocks with fail-closed adapters."""

    def __init__(
        self,
        timeout: int = 60,
        *,
        failures: Mapping[State, str] | None = None,
        service_snapshot: Callable[[], Mapping[int, Any]] = _service_snapshot,
        provenance_trust_key: TrustedEd25519PublicKey | None = None,
    ):
        super().__init__(timeout=timeout)
        self.failures = dict(failures or {})
        self.service_snapshot = service_snapshot
        self.runtime_controller: ManagedRuntimeController | None = None
        self.runtime_receipt: RuntimeReceipt | None = None
        self.migration_baseline: dict[str, Any] | None = None
        self.canonical_effect_started = False
        self.legacy_services: Mapping[int, Any] | None = None
        self.backup_snapshot: Path | None = None
        self.backup_source_fingerprint: str | None = None
        self.artifact_snapshot: VerifiedArtifactSnapshot | None = None
        self.provenance_trust_key = provenance_trust_key
        self.verified_provenance: VerifiedProvenance | None = None

    def run_state(self, state: State, context: Mapping[str, Any]) -> dict[str, Any]:
        if DeployMode(context["mode"]) != DeployMode.EXECUTE:
            return super().run_state(state, context)
        method = getattr(self, f"_p2_state_{state.value.lower()}", None)
        if method is None:
            raise DriverError(f"P2 execute state has no fail-closed implementation: {state.value}")
        if state == State.PREFLIGHT and state in self.failures:
            raise DriverError(self.failures[state])
        output = method(context)
        if state in self.failures:
            raise DriverError(self.failures[state])
        return output

    @staticmethod
    def _plan(context: Mapping[str, Any]) -> P2DeployPlan:
        plan = context.get("plan")
        if not isinstance(plan, P2DeployPlan):
            raise DriverError("P2DeployPlan is required; P1 plan rejected")
        return plan

    def _spec(self, context: Mapping[str, Any]) -> CanonicalAdapterSpec:
        plan = self._plan(context)
        if self.artifact_snapshot is None:
            return CanonicalAdapterSpec.from_plan(plan)
        snapshot = self.artifact_snapshot
        effective = replace(
            plan,
            wheel=snapshot.files["wheel.whl"],
            manifest=snapshot.files["manifest.json"],
            runbook=snapshot.files["runbook.md"],
            p2_driver=snapshot.files["p2-driver.py"],
            dependency_lock=snapshot.files["dependency.lock"],
            wheelhouse=snapshot.wheelhouse,
            wheelhouse_manifest=snapshot.wheelhouse_manifest,
            canonical_adapter=snapshot.files["canonical-adapter.py"],
            staged_launcher=snapshot.files["installed-launcher.py"],
            rollback_reference=snapshot.files["rollback.sqlite"],
        )
        return CanonicalAdapterSpec.from_plan(effective)

    def _p2_state_preflight(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(context)
        if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME"):
            raise DriverError("PYTHONPATH/PYTHONHOME must be unset")
        if plan.parent_p1_plan_hash != P1_PLAN_HASH:
            raise DriverError("P1 parent plan binding mismatch")
        p1_driver = Path(__file__).with_name("deploy_driver.py")
        if _sha256_file(p1_driver) != P1_DRIVER_SHA256:
            raise DriverError("P1 driver artifact mismatch")
        validated = validate_adapter_spec(self._spec(context))
        return {"p2": True, **validated}

    def _p2_state_artifact_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(context)
        base = verify_artifacts(plan)
        for path, digest, label in (
            (plan.p2_driver, plan.p2_driver_sha256, "P2 driver"),
            (plan.dependency_lock, plan.dependency_lock_sha256, "dependency lock"),
            (plan.wheelhouse_manifest, plan.wheelhouse_manifest_sha256, "wheelhouse manifest"),
            (plan.canonical_adapter, plan.canonical_adapter_sha256, "canonical adapter"),
            (plan.staged_launcher, plan.staged_launcher_sha256, "staged launcher"),
            (plan.rollback_reference, plan.rollback_reference_sha256, "rollback reference"),
        ):
            _file_check(path, digest, label)
        bundle = verify_dependency_bundle(
            plan.dependency_lock, plan.wheelhouse, plan.wheelhouse_manifest
        )
        runtime_binding = verify_runtime_code_binding(plan)
        provenance_required = not plan.simulation or any(
            (
                plan.root_manifest,
                plan.root_manifest_signature,
                plan.release_plan,
                plan.release_plan_sha256,
                self.provenance_trust_key,
            )
        )
        if provenance_required:
            if (
                plan.root_manifest is None
                or plan.root_manifest_signature is None
                or plan.release_plan is None
                or plan.release_plan_sha256 is None
            ):
                raise DriverError("complete signed release provenance is mandatory")
            expected_domain = "simulation" if plan.simulation else "production"
            self.verified_provenance = verify_release_provenance(
                plan.root_manifest,
                plan.root_manifest_signature,
                self.provenance_trust_key,
                expected_domain=expected_domain,
            )
            _file_check(plan.release_plan, plan.release_plan_sha256, "release plan")

        snapshot_files: dict[str, Path] = {
            "wheel.whl": plan.wheel,
            "manifest.json": plan.manifest,
            "runbook.md": plan.runbook,
            "p2-driver.py": plan.p2_driver,
            "dependency.lock": plan.dependency_lock,
            "canonical-adapter.py": plan.canonical_adapter,
            "installed-launcher.py": plan.staged_launcher,
            "rollback.sqlite": plan.rollback_reference,
        }
        snapshot_hashes: dict[str, str] = {
            "wheel.whl": plan.wheel_sha256,
            "manifest.json": plan.manifest_sha256,
            "runbook.md": plan.runbook_sha256,
            "p2-driver.py": plan.p2_driver_sha256,
            "dependency.lock": plan.dependency_lock_sha256,
            "canonical-adapter.py": plan.canonical_adapter_sha256,
            "installed-launcher.py": plan.staged_launcher_sha256,
            "rollback.sqlite": plan.rollback_reference_sha256,
        }
        if provenance_required:
            assert plan.release_plan is not None
            assert plan.release_plan_sha256 is not None
            snapshot_files["release-plan.json"] = plan.release_plan
            snapshot_hashes["release-plan.json"] = plan.release_plan_sha256

        deployment_dir = Path(str(context["deployment_dir"]))
        self.artifact_snapshot = create_verified_snapshot(
            SnapshotInputs(
                files=snapshot_files,
                expected_hashes=snapshot_hashes,
                wheelhouse=plan.wheelhouse,
                wheelhouse_manifest=plan.wheelhouse_manifest,
                wheelhouse_manifest_sha256=plan.wheelhouse_manifest_sha256,
            ),
            deployment_dir,
        )
        if self.verified_provenance is not None:
            verify_snapshot_provenance(
                self.verified_provenance, self.artifact_snapshot.hashes
            )
        return {
            **base,
            **bundle,
            "runtime_code_binding": runtime_binding,
            "verified_snapshot": str(self.artifact_snapshot.root),
            "verified_snapshot_hashes": dict(self.artifact_snapshot.hashes),
            "provenance": (
                {
                    "algorithm": "Ed25519",
                    "key_id": self.verified_provenance.key_id,
                    "trust_domain": self.verified_provenance.trust_domain,
                    "root_manifest_sha256": self.verified_provenance.manifest_sha256,
                    "signature_sha256": self.verified_provenance.signature_sha256,
                }
                if self.verified_provenance is not None
                else None
            ),
        }

    def _p2_state_service_and_port_check(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(context)
        with socket.socket() as probe:
            if probe.connect_ex((plan.host, plan.port)) == 0:
                raise DriverError("target port occupied")
        self.legacy_services = dict(self.service_snapshot())
        return {"legacy_services": dict(self.legacy_services), "target_port": "closed"}

    def _p2_state_database_backup(self, context: Mapping[str, Any]) -> dict[str, Any]:
        spec = self._spec(context)
        writer_gate(spec.database)
        deployment_dir = Path(str(context["deployment_dir"])).resolve()
        backup_dir = deployment_dir / "predeploy-backup"
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if backup_dir.is_symlink() or not backup_dir.is_dir():
            raise DriverError("unsafe predeploy backup directory")
        snapshot = backup_dir / "state.predeploy.sqlite"
        if snapshot.exists() or snapshot.is_symlink():
            raise DriverError("predeploy backup snapshot already exists")
        source = sqlite3.connect(f"file:{spec.database}?mode=ro", uri=True)
        destination = sqlite3.connect(snapshot)
        try:
            source.backup(destination)
            destination.commit()
        finally:
            destination.close()
            source.close()
        snapshot_fingerprint = database_fingerprint(snapshot)
        source_fingerprint = database_fingerprint(spec.database)
        if snapshot_fingerprint != source_fingerprint:
            snapshot.unlink(missing_ok=True)
            raise DriverError("canonical database changed during predeploy backup")
        self.backup_snapshot = snapshot
        self.backup_source_fingerprint = source_fingerprint
        return {
            "database": str(spec.database),
            "writer_gate": "PASS",
            "snapshot": str(snapshot),
            "snapshot_sha256": _sha256_file(snapshot),
            "source_logical_fingerprint": source_fingerprint,
            "snapshot_logical_fingerprint": snapshot_fingerprint,
        }

    def _p2_state_backup_restore_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.backup_snapshot is None or self.backup_source_fingerprint is None:
            raise DriverError("fresh predeploy backup evidence missing")
        restore = self.backup_snapshot.parent / "state.restore-test.sqlite"
        if restore.exists() or restore.is_symlink():
            raise DriverError("restore-test target already exists")
        source = sqlite3.connect(f"file:{self.backup_snapshot}?mode=ro", uri=True)
        destination = sqlite3.connect(restore)
        try:
            source.backup(destination)
            destination.commit()
        finally:
            destination.close()
            source.close()
        connection = sqlite3.connect(f"file:{restore}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_key_violations = len(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            )
        finally:
            connection.close()
        restore_fingerprint = database_fingerprint(restore)
        logical_parity = restore_fingerprint == self.backup_source_fingerprint
        if integrity != "ok" or foreign_key_violations or not logical_parity:
            raise DriverError("predeploy backup restore verification failed")
        return {
            "restore_test": str(restore),
            "integrity": integrity,
            "foreign_key_violations": foreign_key_violations,
            "logical_parity": logical_parity,
            "restore_logical_fingerprint": restore_fingerprint,
        }

    def _p2_state_staged_venv_install(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(context)
        if self.artifact_snapshot is None:
            raise DriverError("verified artifact snapshot missing")
        snapshot = self.artifact_snapshot
        result = ensure_offline_venv(
            plan.target_venv,
            snapshot.files["dependency.lock"],
            snapshot.wheelhouse,
            snapshot.wheelhouse_manifest,
            snapshot.files["wheel.whl"],
            simulation=plan.simulation,
        )
        python = plan.target_venv / "bin/python"
        if python.is_symlink() and not plan.simulation:
            raise DriverError("production installed venv Python must not be a symlink")
        return {**result, "offline_bundle_verified": True}

    def _p2_state_installed_parity_verify(self, context: Mapping[str, Any]) -> dict[str, Any]:
        spec = self._spec(context)
        validate_adapter_spec(spec)
        result = verify_installed_package(spec)
        return {"installed_python": str(spec.venv / "bin/python"), **result}

    def _p2_state_migration_dry_run(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.backup_snapshot is None:
            raise DriverError("fresh predeploy backup evidence missing")
        spec = self._spec(context)
        snapshot_spec = replace(
            spec,
            database=self.backup_snapshot,
            hermes_home=self.backup_snapshot.parent.parent,
        )
        result = migration_dry_run(snapshot_spec)
        return {**result, "source_snapshot": str(self.backup_snapshot)}

    def _p2_state_rollback_dry_run(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.backup_snapshot is None:
            raise DriverError("fresh predeploy backup evidence missing")
        spec = self._spec(context)
        snapshot_spec = replace(
            spec,
            rollback_reference=self.backup_snapshot,
            rollback_reference_sha256=_sha256_file(self.backup_snapshot),
        )
        return rollback_dry_run(snapshot_spec)

    def _p2_state_canonical_migration(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.backup_source_fingerprint is None:
            raise DriverError("fresh predeploy backup evidence missing")
        self.canonical_effect_started = True
        nonce_digest, approval_digest, deployment_id = _approval_transaction_binding(
            context
        )
        self.migration_baseline = migrate_installed(
            self._spec(context),
            expected_baseline_fingerprint=self.backup_source_fingerprint,
            nonce_digest=nonce_digest,
            approval_digest=approval_digest,
            deployment_id=deployment_id,
        )
        return dict(self.migration_baseline)

    def _p2_state_verify_only(self, context: Mapping[str, Any]) -> dict[str, Any]:
        return verify_installed_database(self._spec(context))

    def _p2_state_controlled_start(self, context: Mapping[str, Any]) -> dict[str, Any]:
        spec = self._spec(context)
        nonce_digest, approval_digest, deployment_id = _approval_transaction_binding(
            context
        )
        verify_installed_approval_nonce(
            spec,
            nonce_digest=nonce_digest,
            approval_digest=approval_digest,
            deployment_id=deployment_id,
        )
        command = launcher_command(
            spec, "serve", "--host", spec.host, "--port", str(spec.port)
        )
        self.runtime_controller = ManagedRuntimeController(
            host=spec.host,
            port=spec.port,
            command=command,
            expected_executable=spec.venv / "bin/python",
            env=clean_runtime_env(),
        )
        self.runtime_receipt = self.runtime_controller.start()
        return {
            "pid": self.runtime_receipt.pid,
            "listener_started": True,
            "listener_inode": self.runtime_receipt.listener_inode,
            "process_start_ticks": self.runtime_receipt.process_start_ticks,
            "executable": self.runtime_receipt.executable,
        }

    def _p2_state_health_check(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.runtime_controller is None or self.runtime_receipt is None:
            raise DriverError("controlled process evidence missing")
        return self.runtime_controller.health(self.runtime_receipt)

    def _p2_state_security_e2e(self, context: Mapping[str, Any]) -> dict[str, Any]:
        plan = self._plan(context)
        if plan.host != "127.0.0.1" or self.runtime_controller is None or self.runtime_receipt is None:
            raise DriverError("P2 security listener gate failed")
        health = self.runtime_controller.health(self.runtime_receipt)
        return {"approval_binding": True, "loopback_only": True, "pid": self.runtime_receipt.pid, "listener_attributed": health["listener_attributed"]}

    def _p2_state_board_lifecycle_e2e(self, context: Mapping[str, Any]) -> dict[str, Any]:
        result = run_installed_lifecycle_e2e(self._spec(context))
        return {"installed_lifecycle_contract": True, **result}

    def _p2_state_commit_deploy(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if self.legacy_services is None:
            raise DriverError("legacy service snapshot missing")
        validate_service_snapshot(self.legacy_services, self.service_snapshot())
        marker = Path(context["deployment_dir"]) / "DEPLOY-COMMITTED.json"
        marker.write_text(json.dumps({"deployment_id": context["deployment_id"]}) + "\n")
        plan = self._plan(context)
        if plan.simulation and self.runtime_controller is not None and self.runtime_receipt is not None:
            self.runtime_controller.shutdown(self.runtime_receipt)
        if self.artifact_snapshot is not None:
            remove_verified_snapshot(self.artifact_snapshot, Path(str(context["deployment_dir"])))
            self.artifact_snapshot = None
        return {"commit_marker": str(marker), "simulation_listener_stopped": plan.simulation}

    def _p2_state_rollback(self, context: Mapping[str, Any]) -> dict[str, Any]:
        stopped = False
        if self.runtime_controller is not None and self.runtime_receipt is not None:
            stopped = self.runtime_controller.shutdown(self.runtime_receipt)["stopped"]
        logical = False
        if self.migration_baseline is not None:
            rollback_installed(self._spec(context), self.migration_baseline)
            logical = True
        if self.legacy_services is not None:
            validate_service_snapshot(self.legacy_services, self.service_snapshot())
        if self.artifact_snapshot is not None:
            remove_verified_snapshot(self.artifact_snapshot, Path(str(context["deployment_dir"])))
            self.artifact_snapshot = None
        return {"logical": logical, "physical_restore": False, "new_pid_stopped": stopped}

    @staticmethod
    def _p2_state_complete(context: Mapping[str, Any]) -> dict[str, Any]:
        return {"terminal": True}


class P2DeploymentDriver(DeploymentDriver):
    """P1 state/checkpoint engine with P2-only live approvals and ledger."""

    def __init__(self, plan: P2DeployPlan, *args: Any, **kwargs: Any):
        if not isinstance(plan, P2DeployPlan):
            raise DriverError("P2DeployPlan is required; P1 plan rejected")
        backend = kwargs.get("backend")
        if backend is None and len(args) >= 2:
            backend = args[1]
        if not plan.simulation and type(backend) is not P2RealBackend:
            raise DriverError("production P2 execution requires the exact P2RealBackend")
        super().__init__(plan, *args, **kwargs)
        self.authenticated_ledger = AuthenticatedApprovalLedger(self.root)
        self.checkpoint_journal = AuthenticatedApprovalLedger(
            self.root / ".checkpoint-journal-v2"
        )
        self._checkpoint_journal_key: bytes | None = None
        self._sensitive_markers: set[str] = set()

    def _register_sensitive_values(
        self,
        approval: Mapping[str, Any] | None,
        approval_key: bytes | None,
    ) -> None:
        if approval is not None:
            signature = approval.get("signature")
            payload = approval.get("payload")
            if isinstance(signature, str):
                self._sensitive_markers.add(signature)
            if isinstance(payload, Mapping):
                nonce = payload.get("nonce")
                if isinstance(nonce, str):
                    self._sensitive_markers.add(nonce)
        if approval_key:
            self._sensitive_markers.add(approval_key.hex())
            try:
                decoded = approval_key.decode("utf-8")
            except UnicodeDecodeError:
                decoded = ""
            if decoded:
                self._sensitive_markers.add(decoded)
        for name, value in os.environ.items():
            upper = name.upper()
            if value and any(
                marker in upper
                for marker in (
                    "TOKEN",
                    "SECRET",
                    "PASSWORD",
                    "API_KEY",
                    "HMAC",
                    "AUTH",
                )
            ):
                self._sensitive_markers.add(value)

    def _record(
        self,
        checkpoint: dict[str, Any],
        state: State,
        status: str,
        *,
        output: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        sanitized_output = redact_value(
            dict(output or {}), secrets=self._sensitive_markers
        )
        sanitized_error = redact_error_text(error) if error is not None else None
        super()._record(
            checkpoint,
            state,
            status,
            output=sanitized_output,
            error=sanitized_error,
        )

    @staticmethod
    def _checkpoint_envelope(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        checkpoint_hash = checkpoint.get("checkpoint_hash")
        checkpoint_hmac = checkpoint.get("checkpoint_hmac")
        if not isinstance(checkpoint_hash, str) or not isinstance(checkpoint_hmac, str):
            raise DriverError("checkpoint authentication evidence is missing")
        return {
            "algorithm": "P2-CHECKPOINT-JOURNAL-HMAC-SHA256",
            "payload": {
                "nonce": (
                    f"{checkpoint['deployment_id']}:{len(checkpoint.get('records', []))}:"
                    f"{checkpoint_hash}"
                ),
                "checkpoint_hash": checkpoint_hash,
                "status": checkpoint.get("status"),
            },
            "signature": checkpoint_hmac,
        }

    def _persist(self, checkpoint: dict[str, Any]) -> None:
        checkpoint.update(current_run_identity())
        if isinstance(checkpoint.get("error"), str):
            checkpoint["error"] = redact_error_text(str(checkpoint["error"]))
        super()._persist(checkpoint)
        if (
            checkpoint.get("mode") == DeployMode.EXECUTE.value
            and self._checkpoint_journal_key is not None
        ):
            try:
                self.checkpoint_journal.consume(
                    self._checkpoint_envelope(checkpoint),
                    str(checkpoint["deployment_id"]),
                    self._checkpoint_journal_key,
                )
            except LedgerError as exc:
                raise DriverError(f"checkpoint journal failure: {exc}") from exc

    def run(
        self,
        mode: DeployMode,
        deployment_id: str,
        *,
        approval: Mapping[str, Any] | None = None,
        approval_key: bytes | None = None,
    ) -> dict[str, Any]:
        self._register_sensitive_values(approval, approval_key)
        if mode == DeployMode.EXECUTE and approval_key:
            self._checkpoint_journal_key = hmac.new(
                approval_key,
                b"executive-board-p2-checkpoint-journal-v2",
                hashlib.sha256,
            ).digest()
        return super().run(
            mode,
            deployment_id,
            approval=approval,
            approval_key=approval_key,
        )

    def resume(
        self,
        deployment_id: str,
        *,
        approval: Mapping[str, Any] | None = None,
        approval_key: bytes | None = None,
    ) -> dict[str, Any]:
        self._register_sensitive_values(approval, approval_key)
        if not approval_key:
            raise DriverError("owner approval key is required for P2 resume")
        self._checkpoint_journal_key = hmac.new(
            approval_key,
            b"executive-board-p2-checkpoint-journal-v2",
            hashlib.sha256,
        ).digest()
        with self._lease(deployment_id):
            checkpoint = load_checkpoint(
                self._deployment_dir(deployment_id) / "checkpoint.json"
            )
            if checkpoint["plan_hash"] != self.plan.canonical_hash:
                raise DriverError("checkpoint plan hash mismatch")
            if checkpoint["status"] not in {"PAUSED", "IN_PROGRESS"}:
                raise DriverError(f"checkpoint is not resumable: {checkpoint['status']}")
            try:
                self.checkpoint_journal.verify_latest(
                    self._checkpoint_envelope(checkpoint),
                    deployment_id,
                    self._checkpoint_journal_key,
                )
            except LedgerError as exc:
                raise DriverError(f"checkpoint rollback detected: {exc}") from exc
            if checkpoint["mode"] == DeployMode.EXECUTE.value and approval is None:
                raise DriverError("owner approval is required to resume execute mode")
            return self._run_from_checkpoint(
                checkpoint,
                approval=approval,
                approval_key=approval_key,
            )

    def _verify_approval_for_state(
        self,
        state: State,
        checkpoint: dict[str, Any],
        approval: Mapping[str, Any] | None,
        approval_key: bytes | None,
    ) -> None:
        if DeployMode(checkpoint["mode"]) != DeployMode.EXECUTE or state not in {
            State.CANONICAL_MIGRATION,
            State.CONTROLLED_START,
        }:
            return
        if approval is None or not approval_key:
            raise DriverError("valid P2 owner approval is required")
        plan = self.plan
        if not isinstance(plan, P2DeployPlan):
            raise DriverError("P2DeployPlan is required; P1 plan rejected")
        if not plan.simulation and not isinstance(approval_key, TrustedHMACKey):
            raise DriverError("production P2 verification requires an owner trust-store key")
        verify_p2_approval(
            approval,
            plan,
            checkpoint["deployment_id"],
            approval_key,
            now=self.clock(),
        )
        checkpoint["approval_digest"] = hashlib.sha256(
            _canonical_json(dict(approval))
        ).hexdigest()

    def _run_rollback(
        self,
        checkpoint: dict[str, Any],
        *,
        approval: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = super()._run_rollback(checkpoint, approval=approval)
        if result.get("status") != "ROLLED_BACK":
            return result
        attempted = bool(
            State.CANONICAL_MIGRATION.value in result.get("completed_states", [])
            or getattr(self.backend, "canonical_effect_started", False)
        )
        logical = bool(result.get("rollback", {}).get("logical"))
        if not attempted or not logical:
            result["status"] = "BLOCKED"
            self._persist(result)
        return result
