from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import scripts.executive_board.installed_adapter as installed_adapter_module

from scripts.executive_board.canonical_adapter import (
    AdapterError,
    CanonicalAdapterSpec,
    create_maintenance_approval,
    database_fingerprint,
    load_trusted_hmac_key,
    physical_restore,
    validate_adapter_spec,
    writer_gate,
)
from scripts.executive_board.installed_adapter import (
    clean_runtime_env,
    launcher_command,
    migrate_installed,
    rollback_installed,
    verify_installed_database,
)
from scripts.executive_board.managed_runtime import (
    ManagedRuntimeController,
    RuntimeControllerError,
)
from scripts.executive_board.redaction import redact_value
from scripts.executive_board.release_provenance import (
    TrustedEd25519PublicKey,
    build_root_manifest,
    key_id_for_public_key,
    public_key_bytes_from_private,
    sign_root_manifest,
)
from scripts.executive_board.dependency_lock import (
    DependencyLockError,
    build_offline_install_commands,
    ensure_offline_venv,
    verify_dependency_bundle,
    verify_hashed_requirements,
)
from scripts.executive_board.deploy_driver import (
    DeployMode,
    DriverError,
    FakeBackend,
    State,
    create_approval,
)
from scripts.executive_board.deploy_driver_p2 import (
    P1_PLAN_HASH,
    P2DeploymentDriver,
    P2DeployPlan,
    P2RealBackend,
    verify_runtime_code_binding,
    create_p2_approval,
    verify_p2_approval,
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture()
def dependency_bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "demo_pkg-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"dependency wheel")
    lock = tmp_path / "requirements-p2.lock"
    lock.write_text(
        "demo-pkg==1.2.3 --hash=sha256:" + sha(wheel) + "\n", encoding="utf-8"
    )
    manifest = tmp_path / "wheelhouse-manifest.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "files": {wheel.name: sha(wheel)}}) + "\n",
        encoding="utf-8",
    )
    return lock, wheelhouse, manifest


def test_hashed_requirements_rejects_floating_and_unhashed(tmp_path: Path) -> None:
    floating = tmp_path / "floating.lock"
    floating.write_text("requests>=2\n", encoding="utf-8")
    with pytest.raises(DependencyLockError, match="exact-pinned|hash"):
        verify_hashed_requirements(floating)


def test_dependency_bundle_verifies_all_wheel_hashes(
    dependency_bundle: tuple[Path, Path, Path]
) -> None:
    lock, wheelhouse, manifest = dependency_bundle
    result = verify_dependency_bundle(lock, wheelhouse, manifest)
    assert result["requirements"] == 1
    assert result["wheels"] == 1
    assert result["offline"] is True


def test_dependency_bundle_rejects_wheel_tamper(
    dependency_bundle: tuple[Path, Path, Path]
) -> None:
    lock, wheelhouse, manifest = dependency_bundle
    next(wheelhouse.iterdir()).write_bytes(b"tampered")
    with pytest.raises(DependencyLockError, match="hash mismatch"):
        verify_dependency_bundle(lock, wheelhouse, manifest)


def test_dependency_bundle_ignores_inactive_platform_marker(
    dependency_bundle: tuple[Path, Path, Path]
) -> None:
    lock, wheelhouse, manifest = dependency_bundle
    lock.write_text(
        lock.read_text(encoding="utf-8")
        + "windows-only==1.0 ; sys_platform == 'win32' --hash=sha256:"
        + "b" * 64
        + "\n",
        encoding="utf-8",
    )
    result = verify_dependency_bundle(lock, wheelhouse, manifest)
    assert result["requirements"] == 1
    assert result["inactive_requirements"] == 1


def test_offline_install_commands_are_network_closed(
    dependency_bundle: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    lock, wheelhouse, _manifest = dependency_bundle
    overlay = tmp_path / "overlay.whl"
    overlay.write_bytes(b"overlay")
    commands = build_offline_install_commands(tmp_path / "venv", lock, wheelhouse, overlay)
    deps, project = commands
    assert "--no-index" in deps
    assert "--require-hashes" in deps
    assert "--find-links" in deps
    assert "--no-deps" in project
    assert "-e" not in deps + project


def test_production_offline_install_refuses_existing_mutable_venv(
    dependency_bundle: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    lock, wheelhouse, wheelhouse_manifest = dependency_bundle
    overlay = tmp_path / "overlay.whl"
    overlay.write_bytes(b"overlay")
    target = tmp_path / "existing-venv"
    (target / "bin").mkdir(parents=True)
    (target / "bin/python").write_text("tampered")
    (target / ".p2-offline-install.json").write_text("{}\n")
    with pytest.raises(DependencyLockError, match="must not be reused"):
        ensure_offline_venv(
            target,
            lock,
            wheelhouse,
            wheelhouse_manifest,
            overlay,
            simulation=False,
        )


@pytest.fixture()
def p2_files(tmp_path: Path, dependency_bundle: tuple[Path, Path, Path]) -> dict[str, Path]:
    lock, wheelhouse, wheelhouse_manifest = dependency_bundle
    release = tmp_path / "release"
    release.mkdir()
    files = {
        "wheel": release / "hermes.whl",
        "manifest": release / "manifest.json",
        "runbook": release / "runbook.md",
        "adapter": release / "canonical_adapter.py",
        "launcher": release / "launcher.sh",
        "lock": lock,
        "wheelhouse_manifest": wheelhouse_manifest,
        "wheelhouse": wheelhouse,
        "rollback": release / "rollback.sqlite",
    }
    for key, path in files.items():
        if key in {"wheelhouse", "lock", "wheelhouse_manifest"}:
            continue
        path.write_bytes((key + "\n").encode())
    return files


@pytest.fixture()
def p2_plan(tmp_path: Path, p2_files: dict[str, Path]) -> P2DeployPlan:
    f = p2_files
    driver = Path(__file__).parents[2] / "scripts/executive_board/deploy_driver_p2.py"
    return P2DeployPlan(
        release=f["wheel"].parent,
        wheel=f["wheel"],
        manifest=f["manifest"],
        runbook=f["runbook"],
        wheel_sha256=sha(f["wheel"]),
        manifest_sha256=sha(f["manifest"]),
        runbook_sha256=sha(f["runbook"]),
        canonical_db=tmp_path / "home/agents_os/state.sqlite",
        target_venv=tmp_path / "venv",
        host="127.0.0.1",
        port=19871,
        target_environment="p2-isolated-simulation",
        p2_driver=driver,
        p2_driver_sha256=sha(driver),
        dependency_lock=f["lock"],
        dependency_lock_sha256=sha(f["lock"]),
        wheelhouse=f["wheelhouse"],
        wheelhouse_manifest=f["wheelhouse_manifest"],
        wheelhouse_manifest_sha256=sha(f["wheelhouse_manifest"]),
        canonical_adapter=f["adapter"],
        canonical_adapter_sha256=sha(f["adapter"]),
        staged_launcher=f["launcher"],
        staged_launcher_sha256=sha(f["launcher"]),
        rollback_reference=f["rollback"],
        rollback_reference_sha256=sha(f["rollback"]),
        parent_p1_plan_hash=P1_PLAN_HASH,
        simulation=True,
    )


def test_p2_plan_binds_every_production_artifact(p2_plan: P2DeployPlan) -> None:
    data = p2_plan.to_dict()
    for key in (
        "dependency_lock_sha256",
        "wheelhouse_manifest_sha256",
        "canonical_adapter_sha256",
        "staged_launcher_sha256",
        "rollback_reference_sha256",
        "parent_p1_plan_hash",
    ):
        assert len(data[key]) == 64
    assert data["p2_plan_schema_version"] == 2
    assert len(p2_plan.canonical_hash) == 64


def test_runtime_code_binding_rejects_loaded_module_mismatch(
    tmp_path: Path, p2_plan: P2DeployPlan
) -> None:
    expected = tmp_path / "expected.py"
    tampered = tmp_path / "tampered.py"
    expected.write_text("SAFE = True\n")
    tampered.write_text("SAFE = False\n")
    manifest = {
        "source_artifacts": {
            name: {"sha256": sha(expected)}
            for name in (
                "deploy_driver_p2.py",
                "canonical_adapter.py",
                "installed_adapter.py",
                "managed_runtime.py",
            )
        }
    }
    p2_plan.manifest.write_text(json.dumps(manifest))
    bound = replace(
        p2_plan,
        manifest_sha256=sha(p2_plan.manifest),
        p2_driver=expected,
        p2_driver_sha256=sha(expected),
        canonical_adapter=expected,
        canonical_adapter_sha256=sha(expected),
    )
    with pytest.raises(DriverError, match="runtime code binding mismatch"):
        verify_runtime_code_binding(
            bound,
            module_files={
                "deploy_driver_p2.py": expected,
                "canonical_adapter.py": expected,
                "installed_adapter.py": tampered,
                "managed_runtime.py": expected,
            },
        )


def test_database_backup_is_fresh_and_restore_verified(
    tmp_path: Path, p2_plan: P2DeployPlan
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    backend = P2RealBackend(service_snapshot=lambda: {})
    deployment_dir = tmp_path / "deployment"
    context = {
        "plan": plan,
        "mode": DeployMode.EXECUTE.value,
        "deployment_dir": str(deployment_dir),
    }
    backup = backend._p2_state_database_backup(context)
    snapshot = Path(backup["snapshot"])
    assert snapshot.is_file()
    assert snapshot != plan.rollback_reference
    assert backup["source_logical_fingerprint"] == backup["snapshot_logical_fingerprint"]

    restored = backend._p2_state_backup_restore_verify(context)
    assert restored["integrity"] == "ok"
    assert restored["foreign_key_violations"] == 0
    assert restored["logical_parity"] is True

    dry_run = backend._p2_state_migration_dry_run(context)
    assert dry_run["source_snapshot"] == str(snapshot)


def test_p2_approval_rejects_p1_or_artifact_mismatch(p2_plan: P2DeployPlan) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(
        p2_plan, "p2-deploy", b"owner", now=now, ttl_seconds=300, nonce="single-use"
    )
    verified = verify_p2_approval(
        approval, p2_plan, "p2-deploy", b"owner", now=now
    )
    assert verified["p2_plan_hash"] == p2_plan.canonical_hash
    approval["payload"]["canonical_adapter_sha256"] = "0" * 64
    with pytest.raises(DriverError, match="signature"):
        verify_p2_approval(approval, p2_plan, "p2-deploy", b"owner", now=now)
    with pytest.raises(DriverError, match="P2 approval"):
        verify_p2_approval(
            {"algorithm": "HMAC-SHA256", "payload": {"plan_hash": P1_PLAN_HASH}, "signature": "x"},
            p2_plan,
            "p2-deploy",
            b"owner",
            now=now,
        )


def test_p2_approval_rejects_expiry(p2_plan: P2DeployPlan) -> None:
    issued = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(
        p2_plan, "p2-deploy", b"owner", now=issued, ttl_seconds=1, nonce="expiry"
    )
    with pytest.raises(DriverError, match="expired"):
        verify_p2_approval(
            approval,
            p2_plan,
            "p2-deploy",
            b"owner",
            now=issued + timedelta(seconds=2),
        )


def test_p2_approval_rejects_future_issue_oversized_ttl_and_empty_key(
    p2_plan: P2DeployPlan,
) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    future = create_p2_approval(
        p2_plan,
        "future",
        b"owner",
        now=now + timedelta(seconds=30),
        nonce="future",
    )
    with pytest.raises(DriverError, match="validity window"):
        verify_p2_approval(future, p2_plan, "future", b"owner", now=now)
    with pytest.raises(DriverError, match="TTL"):
        create_p2_approval(
            p2_plan, "oversized", b"owner", now=now, ttl_seconds=601
        )
    valid = create_p2_approval(p2_plan, "empty-key", b"owner", now=now)
    with pytest.raises(DriverError, match="key is empty"):
        verify_p2_approval(valid, p2_plan, "empty-key", b"", now=now)


def test_adapter_spec_rejects_real_port_in_simulation(p2_plan: P2DeployPlan) -> None:
    spec = CanonicalAdapterSpec.from_plan(p2_plan)
    bad = spec.__class__(**{**spec.__dict__, "port": 18791})
    with pytest.raises(AdapterError, match="18791"):
        validate_adapter_spec(bad)


def test_writer_gate_rejects_competing_writer(tmp_path: Path) -> None:
    db = tmp_path / "state.sqlite"
    sqlite3.connect(db).close()
    holder = sqlite3.connect(db)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(AdapterError, match="writer"):
            writer_gate(db, timeout_seconds=0.05)
    finally:
        holder.rollback()
        holder.close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_runtime_plan(tmp_path: Path, p2_plan: P2DeployPlan) -> P2DeployPlan:
    database = tmp_path / "home/agents_os/state.sqlite"
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE baseline (value TEXT NOT NULL)")
    connection.execute("INSERT INTO baseline VALUES ('preserve-me')")
    connection.commit()
    connection.close()
    shutil.copy2(database, p2_plan.rollback_reference)

    venv = tmp_path / "offline-venv"
    (venv / "bin").mkdir(parents=True)
    os.symlink(shutil.which("python3"), venv / "bin/python")
    launcher = p2_plan.staged_launcher
    launcher.write_text(
        """import argparse,json,sqlite3
from http.server import BaseHTTPRequestHandler,HTTPServer
p=argparse.ArgumentParser(); p.add_argument('--operation',required=True); p.add_argument('--db'); p.add_argument('--manifest'); p.add_argument('--wheel'); p.add_argument('--host'); p.add_argument('--port',type=int); p.add_argument('--baseline-meta-present'); p.add_argument('--baseline-version'); p.add_argument('--expected-fingerprint'); a=p.parse_args()
if a.operation == 'package-verify':
 print(json.dumps({'marker':'P2_PACKAGE_VERIFY_PASS','origins':{'fixture':'/tmp/site-packages/fixture.py'}}))
elif a.operation == 'migrate':
 c=sqlite3.connect(a.db); c.execute('CREATE TABLE executive_board_p2 (id INTEGER PRIMARY KEY, value TEXT)'); c.execute(\"INSERT INTO executive_board_p2(value) VALUES ('migrated')\"); c.commit(); c.close(); print('P2_MIGRATE=PASS')
elif a.operation == 'verify':
 c=sqlite3.connect(a.db); assert c.execute(\"SELECT value FROM executive_board_p2\").fetchone()[0]=='migrated'; c.close(); print('P2_VERIFY=PASS')
elif a.operation == 'rollback':
 c=sqlite3.connect(a.db); c.execute('DROP TABLE IF EXISTS executive_board_p2'); c.commit(); c.close(); print('P2_ROLLBACK=PASS')
elif a.operation == 'lifecycle-e2e':
 c=sqlite3.connect(a.db); assert c.execute("SELECT value FROM executive_board_p2").fetchone()[0]=='migrated'; c.close(); print('P2_BOARD_LIFECYCLE_E2E=PASS')
elif a.operation == 'serve':
 class H(BaseHTTPRequestHandler):
  def do_GET(self):
   body=json.dumps({'status':'ok'}).encode(); self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
  def log_message(self,*args): pass
 HTTPServer((a.host,a.port),H).serve_forever()
""",
        encoding="utf-8",
    )
    adapter = Path(__file__).parents[2] / "scripts/executive_board/canonical_adapter.py"
    source_root = Path(__file__).parents[2] / "scripts/executive_board"
    runtime_sources = {
        "deploy_driver_p2.py": source_root / "deploy_driver_p2.py",
        "canonical_adapter.py": adapter,
        "installed_adapter.py": source_root / "installed_adapter.py",
        "managed_runtime.py": source_root / "managed_runtime.py",
    }
    manifest = p2_plan.manifest
    manifest.write_text(
        json.dumps(
            {
                "wheel": {"sha256": p2_plan.wheel_sha256},
                "source_artifacts": {
                    name: {"sha256": sha(path)}
                    for name, path in runtime_sources.items()
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return p2_plan.__class__(
        **{
            **p2_plan.__dict__,
            "canonical_db": database,
            "target_venv": venv,
            "port": _free_port(),
            "manifest_sha256": sha(manifest),
            "canonical_adapter": adapter,
            "canonical_adapter_sha256": sha(adapter),
            "staged_launcher_sha256": sha(launcher),
            "rollback_reference_sha256": sha(p2_plan.rollback_reference),
        }
    )


def test_production_plan_rejects_fake_backend_before_checkpoint_creation(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    production_plan = replace(p2_plan, simulation=False)
    checkpoint_root = tmp_path / "state"
    with pytest.raises(DriverError, match="exact P2RealBackend"):
        P2DeploymentDriver(production_plan, checkpoint_root, FakeBackend())
    assert not checkpoint_root.exists()


def test_production_approval_verifier_rejects_caller_selected_raw_hmac_key(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    production_plan = replace(p2_plan, simulation=False)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(
        production_plan, "trust-root", b"x" * 32, now=now, nonce="trust-root"
    )
    driver = P2DeploymentDriver(
        production_plan,
        tmp_path / "state",
        P2RealBackend(service_snapshot=lambda: {}),
        clock=lambda: now,
    )
    checkpoint = {"mode": DeployMode.EXECUTE.value, "deployment_id": "trust-root"}
    with pytest.raises(DriverError, match="owner trust-store key"):
        driver._verify_approval_for_state(
            State.CANONICAL_MIGRATION, checkpoint, approval, b"x" * 32
        )


def test_trusted_hmac_key_loader_enforces_exact_length_and_private_mode(tmp_path: Path) -> None:
    key_file = tmp_path / "owner.key"
    key_file.write_bytes(b"k" * 32)
    key_file.chmod(0o600)
    assert bytes(load_trusted_hmac_key(key_file)) == b"k" * 32
    key_file.chmod(0o644)
    with pytest.raises(AdapterError, match="permissions"):
        load_trusted_hmac_key(key_file)
    key_file.chmod(0o600)
    key_file.write_bytes(b"short")
    with pytest.raises(AdapterError, match="exactly 32"):
        load_trusted_hmac_key(key_file)


def test_p2_driver_uses_p2_approval_at_both_live_boundaries(
    p2_plan: P2DeployPlan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(p2_plan, "approval-gates", b"owner", now=now, nonce="gate")
    calls: list[str] = []

    def tracked(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append(str(args[2]))
        return verify_p2_approval(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("scripts.executive_board.deploy_driver_p2.verify_p2_approval", tracked)
    driver = P2DeploymentDriver(
        p2_plan,
        tmp_path / "state",
        FakeBackend(failures={State.CANONICAL_MIGRATION: "stop"}),
        clock=lambda: now,
    )
    result = driver.run(DeployMode.EXECUTE, "approval-gates", approval=approval, approval_key=b"owner")
    assert result["failed_state"] == State.CANONICAL_MIGRATION.value
    assert calls == ["approval-gates"]


def test_p2_driver_reverifies_consumed_approval_before_controlled_start(
    p2_plan: P2DeployPlan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(
        p2_plan, "both-gates", b"owner", now=now, nonce="both-gates"
    )
    calls: list[str] = []
    original = verify_p2_approval

    def tracked(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append(str(args[2]))
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "scripts.executive_board.deploy_driver_p2.verify_p2_approval", tracked
    )
    result = P2DeploymentDriver(
        p2_plan, tmp_path / "state", FakeBackend(), clock=lambda: now
    ).run(
        DeployMode.EXECUTE,
        "both-gates",
        approval=approval,
        approval_key=b"owner",
    )
    assert result["status"] == "DEPLOYED"
    assert calls == ["both-gates", "both-gates"]


def test_p2_driver_rejects_p1_plan_and_approval(p2_plan: P2DeployPlan, tmp_path: Path) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    p1_approval = create_approval(p2_plan, "p1", b"owner", now=now, nonce="p1")
    result = P2DeploymentDriver(p2_plan, tmp_path / "state", FakeBackend(), clock=lambda: now).run(
        DeployMode.EXECUTE, "p1", approval=p1_approval, approval_key=b"owner"
    )
    assert result["status"] == "BLOCKED"
    assert result["error"].endswith("operation failed (details redacted)")


def test_adapter_executes_migrate_verify_listener_and_logical_rollback(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    spec = CanonicalAdapterSpec.from_plan(plan)
    baseline = migrate_installed(spec)
    assert verify_installed_database(spec)["marker"] == "PASS"
    controller = ManagedRuntimeController(
        host=spec.host,
        port=spec.port,
        command=launcher_command(spec, "serve", "--host", spec.host, "--port", str(spec.port)),
        expected_executable=spec.venv / "bin/python",
        env=clean_runtime_env(),
    )
    receipt = controller.start()
    try:
        assert controller.health(receipt)["status"] == "ok"
    finally:
        controller.shutdown(receipt)
    result = rollback_installed(spec, baseline)
    assert result["logical"] is True
    connection = sqlite3.connect(plan.canonical_db)
    try:
        assert connection.execute("SELECT value FROM baseline").fetchone()[0] == "preserve-me"
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE name='executive_board_p2'").fetchone() is None
    finally:
        connection.close()


def test_physical_restore_requires_separate_maintenance_approval(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    spec = CanonicalAdapterSpec.from_plan(plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    with pytest.raises(AdapterError, match="maintenance"):
        physical_restore(spec, {}, b"maintenance", now=now, maintenance_mode=False)
    approval = create_maintenance_approval(spec, b"maintenance", now=now, nonce="restore")
    result = physical_restore(spec, approval, b"maintenance", now=now, maintenance_mode=True)
    assert result["physical_restore"] is True
    connection = sqlite3.connect(spec.database)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM p2_physical_restore_nonces"
        ).fetchone()[0] == 1
    finally:
        connection.close()
    assert not (spec.database.parent / ".p2-physical-restore-ledger").exists()
    with pytest.raises(AdapterError, match="replay"):
        physical_restore(spec, approval, b"maintenance", now=now, maintenance_mode=True)


@pytest.mark.parametrize(
    "stage",
    [
        "after_source_snapshot",
        "after_candidate_validation",
        "after_exclusive_lock",
        "after_locked_baseline",
        "before_atomic_exchange",
        "after_atomic_exchange",
        "after_restored_validation",
    ],
)
def test_physical_restore_failure_injection_never_leaves_partial_state(
    p2_plan: P2DeployPlan, tmp_path: Path, stage: str
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    spec = CanonicalAdapterSpec.from_plan(plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_maintenance_approval(
        spec, b"maintenance", now=now, nonce=f"restore-{stage}"
    )
    before = database_fingerprint(spec.database)

    def fail(current: str) -> None:
        if current == stage:
            raise RuntimeError(f"injected at {stage}")

    with pytest.raises(RuntimeError, match="injected"):
        physical_restore(
            spec,
            approval,
            b"maintenance",
            now=now,
            maintenance_mode=True,
            fault_hook=fail,
        )
    assert database_fingerprint(spec.database) == before
    connection = sqlite3.connect(spec.database)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None
    finally:
        connection.close()
    assert not list(spec.database.parent.glob(".p2-physical-restore-*"))
    retry = physical_restore(
        spec,
        approval,
        b"maintenance",
        now=now,
        maintenance_mode=True,
    )
    assert retry["physical_restore"] is True
    with pytest.raises(AdapterError, match="replay"):
        physical_restore(
            spec,
            approval,
            b"maintenance",
            now=now,
            maintenance_mode=True,
        )


def test_physical_restore_rejects_ipv6_listener_on_target_port(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    plan = _make_runtime_plan(tmp_path, p2_plan)
    spec = CanonicalAdapterSpec.from_plan(plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_maintenance_approval(
        spec, b"maintenance", now=now, nonce="ipv6-listener"
    )
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        listener.bind(("::1", spec.port))
        listener.listen()
        with pytest.raises(AdapterError, match="no listener"):
            physical_restore(
                spec,
                approval,
                b"maintenance",
                now=now,
                maintenance_mode=True,
            )
    finally:
        listener.close()


def test_physical_restore_failure_after_restore_commit_keeps_nonce_and_write_consistent(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    spec = CanonicalAdapterSpec.from_plan(plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_maintenance_approval(
        spec, b"maintenance", now=now, nonce="post-commit-failure"
    )

    def fail(stage: str) -> None:
        if stage == "after_restore_commit":
            raise RuntimeError("injected after committed nonce")

    with pytest.raises(RuntimeError, match="committed nonce"):
        physical_restore(
            spec,
            approval,
            b"maintenance",
            now=now,
            maintenance_mode=True,
            fault_hook=fail,
        )
    connection = sqlite3.connect(spec.database)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM p2_physical_restore_nonces"
        ).fetchone()[0] == 1
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    with pytest.raises(AdapterError, match="replay|changed"):
        physical_restore(
            spec,
            approval,
            b"maintenance",
            now=now,
            maintenance_mode=True,
        )


def test_maintenance_approval_rejects_future_oversized_ttl_and_empty_key(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    spec = CanonicalAdapterSpec.from_plan(_make_runtime_plan(tmp_path, p2_plan))
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    with pytest.raises(AdapterError, match="key is empty"):
        create_maintenance_approval(spec, b"", now=now, nonce="empty-key")
    with pytest.raises(AdapterError, match="TTL"):
        create_maintenance_approval(
            spec, b"maintenance", now=now, ttl_seconds=601, nonce="oversized"
        )
    future = create_maintenance_approval(
        spec,
        b"maintenance",
        now=now + timedelta(seconds=30),
        nonce="future-maintenance",
    )
    with pytest.raises(AdapterError, match="expired or invalid"):
        physical_restore(
            spec, future, b"maintenance", now=now, maintenance_mode=True
        )


def test_controlled_start_rejects_occupied_port(p2_plan: P2DeployPlan, tmp_path: Path) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    blocker = socket.socket()
    blocker.bind((plan.host, plan.port))
    blocker.listen()
    try:
        spec = CanonicalAdapterSpec.from_plan(plan)
        controller = ManagedRuntimeController(
            host=spec.host,
            port=spec.port,
            command=launcher_command(spec, "serve", "--host", spec.host, "--port", str(spec.port)),
            expected_executable=spec.venv / "bin/python",
            env=clean_runtime_env(),
        )
        with pytest.raises(RuntimeControllerError, match="occupied"):
            controller.start()
    finally:
        blocker.close()


@pytest.mark.parametrize("mode", ["ipv4-loopback", "ipv4-wildcard", "ipv6-wildcard"])
def test_managed_runtime_rejects_any_additional_listener_owned_by_same_pid(
    tmp_path: Path, mode: str
) -> None:
    if mode == "ipv6-wildcard" and not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    target_port = _free_port()
    extra_port = _free_port()
    script = tmp_path / "extra-listener.py"
    script.write_text(
        """import socket,sys,time
target=int(sys.argv[1]); extra=int(sys.argv[2]); mode=sys.argv[3]
s1=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s1.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s1.bind(('127.0.0.1',target)); s1.listen()
if mode=='ipv6-wildcard':
 s2=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s2.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s2.bind(('::',extra))
else:
 s2=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s2.bind(('0.0.0.0' if mode=='ipv4-wildcard' else '127.0.0.1',extra))
s2.listen(); time.sleep(30)
""",
        encoding="utf-8",
    )
    controller = ManagedRuntimeController(
        host="127.0.0.1",
        port=target_port,
        command=[sys.executable, str(script), str(target_port), str(extra_port), mode],
        expected_executable=Path(sys.executable),
        startup_timeout=3,
    )
    with pytest.raises(RuntimeControllerError, match="unexpected|wildcard|additional"):
        controller.start()


def test_simulated_execute_reaches_commit_and_shuts_down_listener(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(plan, "simulated", b"owner", now=now, nonce="simulated")
    result = P2DeploymentDriver(plan, tmp_path / "state", P2RealBackend(service_snapshot=lambda: {}), clock=lambda: now).run(
        DeployMode.EXECUTE, "simulated", approval=approval, approval_key=b"owner"
    )
    assert result["status"] == "DEPLOYED"
    required = [
        State.PREFLIGHT.value,
        State.CANONICAL_MIGRATION.value,
        State.VERIFY_ONLY.value,
        State.CONTROLLED_START.value,
        State.HEALTH_CHECK.value,
        State.SECURITY_E2E.value,
        State.BOARD_LIFECYCLE_E2E.value,
        State.COMMIT_DEPLOY.value,
    ]
    positions = [result["completed_states"].index(state) for state in required]
    assert positions == sorted(positions)
    with socket.socket() as probe:
        assert probe.connect_ex((plan.host, plan.port)) != 0


@pytest.mark.parametrize(
    "state",
    [
        State.PREFLIGHT,
        State.ARTIFACT_VERIFY,
        State.SERVICE_AND_PORT_CHECK,
        State.DATABASE_BACKUP,
        State.BACKUP_RESTORE_VERIFY,
        State.STAGED_VENV_INSTALL,
        State.INSTALLED_PARITY_VERIFY,
        State.MIGRATION_DRY_RUN,
        State.ROLLBACK_DRY_RUN,
        State.CANONICAL_MIGRATION,
        State.VERIFY_ONLY,
        State.CONTROLLED_START,
        State.HEALTH_CHECK,
        State.SECURITY_E2E,
        State.BOARD_LIFECYCLE_E2E,
        State.COMMIT_DEPLOY,
    ],
)
def test_execute_failure_matrix_classifies_boundary(
    p2_plan: P2DeployPlan, tmp_path: Path, state: State
) -> None:
    plan = _make_runtime_plan(tmp_path / state.value.lower(), p2_plan)
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    deployment_id = "fail-" + state.value.lower()
    approval = create_p2_approval(plan, deployment_id, b"owner", now=now, nonce=deployment_id)
    backend = P2RealBackend(failures={state: "injected"}, service_snapshot=lambda: {})
    result = P2DeploymentDriver(plan, tmp_path / "states" / state.value, backend, clock=lambda: now).run(
        DeployMode.EXECUTE, deployment_id, approval=approval, approval_key=b"owner"
    )
    expected = (
        "ROLLED_BACK"
        if state in {
            State.CANONICAL_MIGRATION,
            State.VERIFY_ONLY,
            State.CONTROLLED_START,
            State.HEALTH_CHECK,
            State.SECURITY_E2E,
            State.BOARD_LIFECYCLE_E2E,
            State.COMMIT_DEPLOY,
        }
        else "BLOCKED"
    )
    assert result["status"] == expected
    assert result["failed_state"] == state.value
    assert result["rollback"]["physical_restore"] is False


def test_commit_rejects_service_snapshot_drift(p2_plan: P2DeployPlan, tmp_path: Path) -> None:
    plan = _make_runtime_plan(tmp_path, p2_plan)
    snapshots = iter(({1: "before"}, {1: "after"}, {1: "after"}))
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    approval = create_p2_approval(plan, "drift", b"owner", now=now, nonce="drift")
    result = P2DeploymentDriver(plan, tmp_path / "state", P2RealBackend(service_snapshot=lambda: next(snapshots)), clock=lambda: now).run(
        DeployMode.EXECUTE, "drift", approval=approval, approval_key=b"owner"
    )
    assert result["status"] == "BLOCKED"
    assert result["error"].endswith("operation failed (details redacted)")


def test_central_redaction_removes_markers_from_nested_values() -> None:
    markers = {"APPROVAL-MARKER", "HMAC-MARKER", "NONCE-MARKER"}
    value = {
        "nested": [
            "Authorization: Bearer APPROVAL-MARKER",
            "API_TOKEN=ENV-MARKER",
            "--secret CMD-MARKER",
            "/home/goran/private/trust-store.key",
            {"nonce": "NONCE-MARKER", "key": "HMAC-MARKER"},
        ]
    }
    serialized = json.dumps(redact_value(value, secrets=markers))
    for marker in (*markers, "ENV-MARKER", "CMD-MARKER", "/home/goran"):
        assert marker not in serialized


def test_failure_checkpoint_status_and_exception_details_are_secret_free(
    p2_plan: P2DeployPlan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 7, 21, 20, 0, tzinfo=timezone.utc)
    deployment_id = "redaction"
    key = b"KEY-MARKER"
    approval = create_p2_approval(
        p2_plan,
        deployment_id,
        key,
        now=now,
        nonce="NONCE-MARKER",
    )
    monkeypatch.setenv("DONIBOT_API_TOKEN", "ENV-MARKER")
    secret_error = (
        "CHILD-STDERR-MARKER Authorization: Bearer APPROVAL-MARKER "
        "NONCE-MARKER KEY-MARKER ENV-MARKER /home/goran/private/key "
        "python --token CMD-MARKER"
    )
    root = tmp_path / "state"
    result = P2DeploymentDriver(
        p2_plan,
        root,
        FakeBackend(failures={State.PREFLIGHT: secret_error}),
        clock=lambda: now,
    ).run(
        DeployMode.EXECUTE,
        deployment_id,
        approval=approval,
        approval_key=key,
    )
    serialized = json.dumps(result)
    for marker in (
        "CHILD-STDERR-MARKER",
        "APPROVAL-MARKER",
        "NONCE-MARKER",
        "KEY-MARKER",
        "ENV-MARKER",
        "CMD-MARKER",
        "/home/goran/private",
    ):
        assert marker not in serialized
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    content = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                assert marker not in content


def test_installed_adapter_never_serializes_child_stderr_or_command_secrets(
    p2_plan: P2DeployPlan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker_stderr = "CHILD-STDERR-MARKER"
    marker_command = "COMMAND-TOKEN-MARKER"

    def fail(*_args: object, **_kwargs: object) -> object:
        raise subprocess.CalledProcessError(
            1,
            ["python", "--token", marker_command],
            stderr=marker_stderr,
        )

    monkeypatch.setattr(installed_adapter_module.subprocess, "run", fail)
    fake_python = tmp_path / "venv" / "bin" / "python"
    fake_python.parent.mkdir(parents=True)
    fake_python.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_python.chmod(0o700)
    spec = replace(CanonicalAdapterSpec.from_plan(p2_plan), venv=fake_python.parents[1])
    with pytest.raises(AdapterError) as captured:
        installed_adapter_module.verify_installed_package(spec)
    message = str(captured.value)
    assert marker_stderr not in message
    assert marker_command not in message
    assert "child details redacted" in message


def _signed_simulation_plan(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> tuple[P2DeployPlan, TrustedEd25519PublicKey]:
    canonical_source = Path(validate_adapter_spec.__code__.co_filename)
    installed_source = Path(installed_adapter_module.__file__)
    managed_source = Path(ManagedRuntimeController.__init__.__code__.co_filename)
    release_manifest = {
        "wheel": {"sha256": p2_plan.wheel_sha256},
        "source_artifacts": {
            "deploy_driver_p2.py": {"sha256": p2_plan.p2_driver_sha256},
            "canonical_adapter.py": {"sha256": sha(canonical_source)},
            "installed_adapter.py": {"sha256": sha(installed_source)},
            "managed_runtime.py": {"sha256": sha(managed_source)},
        },
    }
    p2_plan.manifest.write_text(
        json.dumps(release_manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    p2_plan = replace(
        p2_plan,
        manifest_sha256=sha(p2_plan.manifest),
        canonical_adapter=canonical_source,
        canonical_adapter_sha256=sha(canonical_source),
    )
    release_plan = tmp_path / "release-plan.json"
    release_plan.write_text('{"mode":"simulation"}\n', encoding="utf-8")
    artifact_hashes = {
        "wheel.whl": p2_plan.wheel_sha256,
        "manifest.json": p2_plan.manifest_sha256,
        "release-plan.json": hashlib.sha256(release_plan.read_bytes()).hexdigest(),
        "runbook.md": p2_plan.runbook_sha256,
        "p2-driver.py": p2_plan.p2_driver_sha256,
        "dependency.lock": p2_plan.dependency_lock_sha256,
        "canonical-adapter.py": p2_plan.canonical_adapter_sha256,
        "installed-launcher.py": p2_plan.staged_launcher_sha256,
        "rollback.sqlite": p2_plan.rollback_reference_sha256,
        "wheelhouse-manifest.json": p2_plan.wheelhouse_manifest_sha256,
    }
    wheelhouse_index = json.loads(p2_plan.wheelhouse_manifest.read_text(encoding="utf-8"))
    artifact_hashes.update(
        {f"wheelhouse/{name}": digest for name, digest in wheelhouse_index["files"].items()}
    )
    private = bytes(range(32))
    public = public_key_bytes_from_private(private)
    root = build_root_manifest(artifact_hashes, public, trust_domain="simulation")
    root_bytes, signature_bytes = sign_root_manifest(root, private)
    root_path = tmp_path / "root-manifest.json"
    signature_path = tmp_path / "root-manifest.sig.json"
    root_path.write_bytes(root_bytes)
    signature_path.write_bytes(signature_bytes)
    plan = replace(
        p2_plan,
        root_manifest=root_path,
        root_manifest_signature=signature_path,
        release_plan=release_plan,
        release_plan_sha256=artifact_hashes["release-plan.json"],
    )
    trust_key = TrustedEd25519PublicKey(
        public, key_id_for_public_key(public), "simulation"
    )
    return plan, trust_key


def test_artifact_gate_requires_and_verifies_signed_exact_snapshot(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan, trust_key = _signed_simulation_plan(p2_plan, tmp_path)
    deployment_dir = tmp_path / "deployment"
    deployment_dir.mkdir(mode=0o700)
    backend = P2RealBackend(provenance_trust_key=trust_key)
    result = backend._p2_state_artifact_verify(
        {"plan": plan, "deployment_dir": str(deployment_dir)}
    )
    assert result["provenance"]["algorithm"] == "Ed25519"
    assert result["provenance"]["key_id"] == trust_key.key_id
    assert result["provenance"]["trust_domain"] == "simulation"
    assert backend.artifact_snapshot is not None
    assert plan.release_plan is not None
    assert backend.artifact_snapshot.files["release-plan.json"].read_bytes() == plan.release_plan.read_bytes()


def test_production_artifact_gate_forbids_unsigned_fallback(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    signed, _ = _signed_simulation_plan(p2_plan, tmp_path)
    production = replace(
        signed,
        simulation=False,
        root_manifest=None,
        root_manifest_signature=None,
        release_plan=None,
        release_plan_sha256=None,
    )
    deployment_dir = tmp_path / "deployment"
    deployment_dir.mkdir(mode=0o700)
    with pytest.raises(DriverError, match="signed release provenance"):
        P2RealBackend()._p2_state_artifact_verify(
            {"plan": production, "deployment_dir": str(deployment_dir)}
        )


def test_signed_snapshot_rejects_post_signature_artifact_replacement(
    p2_plan: P2DeployPlan, tmp_path: Path
) -> None:
    plan, trust_key = _signed_simulation_plan(p2_plan, tmp_path)
    assert plan.release_plan is not None
    plan.release_plan.write_text('{"mode":"replaced"}\n', encoding="utf-8")
    deployment_dir = tmp_path / "deployment"
    deployment_dir.mkdir(mode=0o700)
    with pytest.raises(DriverError):
        P2RealBackend(provenance_trust_key=trust_key)._p2_state_artifact_verify(
            {"plan": plan, "deployment_dir": str(deployment_dir)}
        )
