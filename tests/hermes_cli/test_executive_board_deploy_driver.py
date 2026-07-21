from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import scripts.executive_board.deploy_driver as deploy_driver

from scripts.executive_board.deploy_driver import (
    DriverError,
    DeploymentDriver,
    DeployMode,
    DeployPlan,
    FakeBackend,
    RealBackend,
    State,
    StateError,
    create_approval,
    load_checkpoint,
    validate_import_origins,
    validate_listener,
    validate_service_snapshot,
    verify_approval,
)


EXPECTED_STATES = [
    "PREFLIGHT",
    "ARTIFACT_VERIFY",
    "SERVICE_AND_PORT_CHECK",
    "DATABASE_BACKUP",
    "BACKUP_RESTORE_VERIFY",
    "STAGED_VENV_INSTALL",
    "INSTALLED_PARITY_VERIFY",
    "MIGRATION_DRY_RUN",
    "ROLLBACK_DRY_RUN",
    "CANONICAL_MIGRATION",
    "VERIFY_ONLY",
    "CONTROLLED_START",
    "HEALTH_CHECK",
    "SECURITY_E2E",
    "BOARD_LIFECYCLE_E2E",
    "COMMIT_DEPLOY",
    "ROLLBACK",
    "COMPLETE",
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def release(tmp_path: Path) -> Path:
    root = tmp_path / "release"
    root.mkdir()
    (root / "wheel.whl").write_bytes(b"wheel")
    (root / "manifest.json").write_text('{"wheel":{"sha256":"%s"}}\n' % digest(b"wheel"))
    (root / "runbook.md").write_text("verified runbook\n")
    return root


@pytest.fixture()
def plan(release: Path, tmp_path: Path) -> DeployPlan:
    return DeployPlan(
        release=release,
        wheel=release / "wheel.whl",
        manifest=release / "manifest.json",
        runbook=release / "runbook.md",
        wheel_sha256=digest(b"wheel"),
        manifest_sha256=digest((release / "manifest.json").read_bytes()),
        runbook_sha256=digest(b"verified runbook\n"),
        canonical_db=tmp_path / "canonical.sqlite",
        target_venv=tmp_path / "versioned-venv",
        host="127.0.0.1",
        port=18791,
        target_environment="isolated-test",
    )


@pytest.fixture()
def driver(plan: DeployPlan, tmp_path: Path) -> DeploymentDriver:
    return DeploymentDriver(plan, tmp_path / "checkpoints", FakeBackend())


def test_state_machine_declares_exact_required_states() -> None:
    assert [state.value for state in State] == EXPECTED_STATES


def test_plan_hash_is_canonical_and_stable(plan: DeployPlan) -> None:
    first = plan.canonical_hash
    second = DeployPlan.from_dict(plan.to_dict()).canonical_hash
    assert first == second
    assert len(first) == 64


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("wheel", b"tampered", "wheel hash mismatch"),
        ("manifest", b"tampered", "manifest hash mismatch"),
        ("runbook", b"tampered", "runbook hash mismatch"),
    ],
)
def test_artifact_hash_mismatch_is_fail_closed(
    plan: DeployPlan, tmp_path: Path, field: str, replacement: bytes, message: str
) -> None:
    getattr(plan, field).write_bytes(replacement)
    backend = FakeBackend(use_real_artifact_verify=True)
    deployment = DeploymentDriver(plan, tmp_path / "state", backend)
    result = deployment.run(DeployMode.VERIFY_ONLY, "hash-mismatch")
    assert result["status"] == "BLOCKED"
    assert message in result["error"].lower()
    assert result["completed_states"][-2:] == ["ROLLBACK", "COMPLETE"]


def test_port_occupied_by_unknown_process_routes_to_rollback(plan: DeployPlan, tmp_path: Path) -> None:
    backend = FakeBackend(failures={State.SERVICE_AND_PORT_CHECK: "unknown process owns 18791"})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "port-busy")
    assert result["status"] == "BLOCKED"
    assert "unknown process" in result["error"]


def test_active_database_writer_routes_to_rollback(plan: DeployPlan, tmp_path: Path) -> None:
    backend = FakeBackend(failures={State.DATABASE_BACKUP: "active DB writer"})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "writer")
    assert result["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "state",
    [
        State.DATABASE_BACKUP,
        State.BACKUP_RESTORE_VERIFY,
        State.MIGRATION_DRY_RUN,
        State.ROLLBACK_DRY_RUN,
        State.INSTALLED_PARITY_VERIFY,
    ],
)
def test_failure_injection_never_continues_to_next_state(
    plan: DeployPlan, tmp_path: Path, state: State
) -> None:
    backend = FakeBackend(failures={state: f"injected {state.value}"})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, state.value.lower())
    assert result["status"] == "BLOCKED"
    assert result["failed_state"] == state.value
    assert result["completed_states"][-2:] == ["ROLLBACK", "COMPLETE"]
    assert state.value not in result["completed_states"]


def test_rollback_failure_is_blocked_not_success(plan: DeployPlan, tmp_path: Path) -> None:
    backend = FakeBackend(
        failures={State.CANONICAL_MIGRATION: "partial migration", State.ROLLBACK: "rollback failure"}
    )
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "rollback-fails")
    assert result["status"] == "BLOCKED"
    assert result["failed_state"] == State.ROLLBACK.value


def test_complete_failure_after_rollback_is_persisted_as_blocked(
    plan: DeployPlan, tmp_path: Path
) -> None:
    backend = FakeBackend(
        failures={State.ARTIFACT_VERIFY: "artifact failure", State.COMPLETE: "complete failure"}
    )
    deployment = DeploymentDriver(plan, tmp_path / "state", backend)
    result = deployment.run(DeployMode.DRY_RUN, "complete-failure")
    assert result["status"] == "BLOCKED"
    assert result["failed_state"] == State.COMPLETE.value
    loaded = deployment.status("complete-failure")
    assert loaded["status"] == "BLOCKED"
    assert State.COMPLETE.value not in result["completed_states"]


def test_import_origin_mismatch_is_rejected(tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    good = venv / "lib/python3.12/site-packages/hermes_cli/a.py"
    bad = tmp_path / "dirty/hermes_cli/b.py"
    with pytest.raises(DriverError, match="import-origin mismatch"):
        validate_import_origins([good, bad], venv, forbidden_roots=[Path("/mnt/d/HermesAgent/app")])


def test_source_shadowing_is_rejected(tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    shadow = Path("/mnt/d/HermesAgent/app/hermes_cli/agents_os.py")
    with pytest.raises(DriverError, match="source shadowing"):
        validate_import_origins([shadow], venv, forbidden_roots=[Path("/mnt/d/HermesAgent/app")])


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.20"])
def test_listener_outside_loopback_is_rejected(host: str) -> None:
    with pytest.raises(DriverError, match="loopback"):
        validate_listener(host, 18791, expected_pid=123, observed_pid=123)


def test_listener_wrong_process_is_rejected() -> None:
    with pytest.raises(DriverError, match="pid"):
        validate_listener("127.0.0.1", 18791, expected_pid=123, observed_pid=456)


def test_approval_binds_plan_target_and_artifacts(plan: DeployPlan) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    approval = create_approval(plan, "deploy-1", b"owner-secret", now=now, ttl_seconds=300, nonce="n-1")
    verified = verify_approval(approval, plan, "deploy-1", b"owner-secret", now=now)
    assert verified["plan_hash"] == plan.canonical_hash
    assert verified["wheel_sha256"] == plan.wheel_sha256
    assert verified["manifest_sha256"] == plan.manifest_sha256
    assert verified["target_environment"] == plan.target_environment


def test_expired_approval_is_rejected(plan: DeployPlan) -> None:
    issued = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    approval = create_approval(plan, "deploy-1", b"owner-secret", now=issued, ttl_seconds=1, nonce="n-1")
    with pytest.raises(DriverError, match="expired"):
        verify_approval(approval, plan, "deploy-1", b"owner-secret", now=issued + timedelta(seconds=2))


def test_approval_payload_tamper_is_rejected(plan: DeployPlan) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    approval = create_approval(plan, "deploy-1", b"owner-secret", now=now, ttl_seconds=300, nonce="n-1")
    approval["payload"]["wheel_sha256"] = "0" * 64
    with pytest.raises(DriverError, match="signature"):
        verify_approval(approval, plan, "deploy-1", b"owner-secret", now=now)


def test_approval_replay_is_rejected_across_deployments(plan: DeployPlan, tmp_path: Path) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    approval = create_approval(plan, "deploy-1", b"owner-secret", now=now, ttl_seconds=300, nonce="n-1")
    first = DeploymentDriver(plan, tmp_path / "state", FakeBackend(), clock=lambda: now)
    first.run(DeployMode.EXECUTE, "deploy-1", approval=approval, approval_key=b"owner-secret")
    replay = create_approval(
        plan, "deploy-2", b"owner-secret", now=now, ttl_seconds=300, nonce="n-1"
    )
    second = DeploymentDriver(plan, tmp_path / "state", FakeBackend(), clock=lambda: now)
    result = second.run(
        DeployMode.EXECUTE, "deploy-2", approval=replay, approval_key=b"owner-secret"
    )
    assert result["status"] == "BLOCKED"
    assert "signature" in result["error"] or "replay" in result["error"]


def test_execute_without_approval_is_rejected(driver: DeploymentDriver) -> None:
    with pytest.raises(DriverError, match="approval"):
        driver.run(DeployMode.EXECUTE, "no-approval")


def test_real_backend_execute_is_hard_blocked_in_p1(
    plan: DeployPlan, tmp_path: Path
) -> None:
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    approval = create_approval(
        plan, "p1-block", b"owner-secret", now=now, ttl_seconds=300, nonce="p1-block"
    )
    before_exists = plan.canonical_db.exists()
    result = DeploymentDriver(
        plan, tmp_path / "real-state", RealBackend(timeout=1), clock=lambda: now
    ).run(
        DeployMode.EXECUTE,
        "p1-block",
        approval=approval,
        approval_key=b"owner-secret",
    )
    assert result["status"] == "BLOCKED"
    assert result["failed_state"] == State.PREFLIGHT.value
    assert "CANONICAL_EXECUTION_DISABLED_IN_P1" in result["error"]
    assert plan.canonical_db.exists() is before_exists


def test_execute_rejects_dirty_python_environment(
    plan: DeployPlan, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/tmp/shadow")
    result = DeploymentDriver(plan, tmp_path / "state", FakeBackend()).run(DeployMode.DRY_RUN, "dirty-env")
    assert result["status"] == "BLOCKED"
    assert "PYTHONPATH" in result["error"]


def test_resume_from_verified_checkpoint_continues_exact_next_state(
    plan: DeployPlan, tmp_path: Path
) -> None:
    backend = FakeBackend(stop_after=State.MIGRATION_DRY_RUN)
    deployment = DeploymentDriver(plan, tmp_path / "state", backend)
    partial = deployment.run(DeployMode.DRY_RUN, "resume-ok")
    assert partial["status"] == "PAUSED"
    assert partial["next_state"] == State.ROLLBACK_DRY_RUN.value
    resumed = DeploymentDriver(plan, tmp_path / "state", FakeBackend()).resume("resume-ok")
    assert resumed["status"] == "DRY_RUN_COMPLETE"
    assert resumed["completed_states"][-1] == State.COMPLETE.value


def test_resume_rejects_tampered_checkpoint(plan: DeployPlan, tmp_path: Path) -> None:
    root = tmp_path / "state"
    DeploymentDriver(plan, root, FakeBackend(stop_after=State.ARTIFACT_VERIFY)).run(
        DeployMode.DRY_RUN, "tampered"
    )
    checkpoint_path = root / "tampered" / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["next_state"] = State.CONTROLLED_START.value
    checkpoint_path.write_text(json.dumps(checkpoint))
    with pytest.raises(DriverError, match="checkpoint.*tamper|hash|HMAC authentication"):
        DeploymentDriver(plan, root, FakeBackend()).resume("tampered")


def test_rehashed_mode_tamper_is_rejected(plan: DeployPlan, tmp_path: Path) -> None:
    root = tmp_path / "state"
    deployment = DeploymentDriver(
        plan, root, FakeBackend(stop_after=State.ARTIFACT_VERIFY)
    )
    deployment.run(DeployMode.DRY_RUN, "mode-tamper")
    checkpoint_path = root / "mode-tamper" / "checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["mode"] = DeployMode.EXECUTE.value
    checkpoint.pop("checkpoint_hash")
    canonical = json.dumps(
        checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    checkpoint["checkpoint_hash"] = hashlib.sha256(canonical).hexdigest()
    checkpoint_path.write_text(json.dumps(checkpoint))
    with pytest.raises(DriverError, match="authentication|HMAC"):
        deployment.status("mode-tamper")


def test_explicit_rollback_from_paused_checkpoint_remains_loadable(
    plan: DeployPlan, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    deployment = DeploymentDriver(
        plan, root, FakeBackend(stop_after=State.MIGRATION_DRY_RUN)
    )
    paused = deployment.run(DeployMode.DRY_RUN, "paused-rollback")
    assert paused["status"] == "PAUSED"
    rolled_back = DeploymentDriver(plan, root, FakeBackend()).rollback(
        "paused-rollback"
    )
    assert rolled_back["status"] == "BLOCKED"
    loaded = DeploymentDriver(plan, root, FakeBackend()).status("paused-rollback")
    assert loaded["status"] == "BLOCKED"


def test_verify_only_checkpoint_remains_loadable(
    plan: DeployPlan, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    deployment = DeploymentDriver(plan, root, FakeBackend())
    result = deployment.run(DeployMode.VERIFY_ONLY, "verify-status")
    assert result["status"] == "VERIFY_ONLY_COMPLETE"
    loaded = deployment.status("verify-status")
    assert loaded["status"] == "VERIFY_ONLY_COMPLETE"


def test_resume_from_non_resumable_checkpoint_is_rejected(plan: DeployPlan, tmp_path: Path) -> None:
    root = tmp_path / "state"
    DeploymentDriver(plan, root, FakeBackend()).run(DeployMode.DRY_RUN, "complete")
    with pytest.raises(DriverError, match="not resumable"):
        DeploymentDriver(plan, root, FakeBackend()).resume("complete")


def test_state_skip_is_rejected(driver: DeploymentDriver) -> None:
    checkpoint = driver.initialize(DeployMode.DRY_RUN, "skip")
    with pytest.raises(StateError, match="illegal transition"):
        driver.transition(checkpoint, State.CONTROLLED_START)


def test_double_execution_attempt_is_rejected(driver: DeploymentDriver) -> None:
    driver.run(DeployMode.DRY_RUN, "same-id")
    with pytest.raises(DriverError, match="already exists"):
        driver.run(DeployMode.DRY_RUN, "same-id")


def test_concurrent_deployment_lease_is_fail_closed(
    plan: DeployPlan, tmp_path: Path
) -> None:
    first = DeploymentDriver(plan, tmp_path / "state", FakeBackend())
    second = DeploymentDriver(plan, tmp_path / "state", FakeBackend())
    with first._lease("same-id"):
        with pytest.raises(DriverError, match="lease already held"):
            with second._lease("same-id"):
                pass


def test_stuck_state_timeout_routes_to_rollback(plan: DeployPlan, tmp_path: Path) -> None:
    backend = FakeBackend(timeouts={State.STAGED_VENV_INSTALL})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "timeout")
    assert result["status"] == "BLOCKED"
    assert result["failed_state"] == State.STAGED_VENV_INSTALL.value
    assert "timeout" in result["error"].lower()


def test_e2e_failure_after_start_rolls_back_partial_deploy(plan: DeployPlan, tmp_path: Path) -> None:
    backend = FakeBackend(failures={State.SECURITY_E2E: "injected E2E failure"})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "e2e-fail")
    assert result["status"] == "ROLLED_BACK"
    assert State.CONTROLLED_START.value in result["completed_states"]
    assert result["rollback"]["logical"] is True
    assert result["rollback"]["physical_restore"] is False


def test_partial_canonical_migration_failure_uses_logical_rollback(
    plan: DeployPlan, tmp_path: Path
) -> None:
    backend = FakeBackend(failures={State.CANONICAL_MIGRATION: "partial migration"})
    result = DeploymentDriver(plan, tmp_path / "state", backend).run(DeployMode.DRY_RUN, "partial")
    assert result["status"] == "ROLLED_BACK"
    assert result["rollback"] == {"logical": True, "physical_restore": False}


def test_rollback_removes_meta_table_created_only_by_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rollback.sqlite"
    import sqlite3

    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT)")
    connection.commit()
    connection.close()

    deploy_driver._restore_absent_meta_table(
        database, {"meta_table_existed": False}
    )

    connection = sqlite3.connect(database)
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
    ).fetchone()
    connection.close()
    assert exists is None


def test_rollback_keeps_nonempty_meta_table_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "rollback-nonempty.sqlite"
    import sqlite3

    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO agents_os_meta VALUES ('unrelated', 'keep')")
    connection.commit()
    connection.close()

    with pytest.raises(DriverError, match="non-Board rows remain"):
        deploy_driver._restore_absent_meta_table(
            database, {"meta_table_existed": False}
        )


def test_existing_gateway_and_dashboard_snapshot_must_remain_unchanged() -> None:
    before = {18789: {"pid": 101, "cmdline_hash": "a"}, 18790: {"pid": 202, "cmdline_hash": "b"}}
    validate_service_snapshot(before, dict(before))
    changed = {18789: {"pid": 999, "cmdline_hash": "x"}, 18790: before[18790]}
    with pytest.raises(DriverError, match="service fingerprint"):
        validate_service_snapshot(before, changed)


def test_checkpoint_is_external_atomic_and_hash_chained(driver: DeploymentDriver, tmp_path: Path) -> None:
    result = driver.run(DeployMode.DRY_RUN, "checkpointed")
    checkpoint_path = tmp_path / "checkpoints/checkpointed/checkpoint.json"
    assert checkpoint_path.exists()
    checkpoint = load_checkpoint(checkpoint_path)
    assert checkpoint["plan_hash"] == driver.plan.canonical_hash
    assert all(record["record_hash"] for record in checkpoint["records"])
    assert checkpoint["records"][1]["previous_record_hash"] == checkpoint["records"][0]["record_hash"]
    assert result["status"] == "DRY_RUN_COMPLETE"


def test_rehashed_checkpoint_state_skip_is_rejected(
    plan: DeployPlan, tmp_path: Path
) -> None:
    deployment = DeploymentDriver(plan, tmp_path / "state", FakeBackend())
    checkpoint = deployment.initialize(DeployMode.DRY_RUN, "forged-skip")
    deployment._record(checkpoint, State.PREFLIGHT, "PASS", output={"verified": True})
    checkpoint["completed_states"].append(State.PREFLIGHT.value)
    checkpoint["current_state"] = State.PREFLIGHT.value
    checkpoint["next_state"] = State.CONTROLLED_START.value
    deployment._record(
        checkpoint, State.CONTROLLED_START, "PASS", output={"simulated": True}
    )
    checkpoint["completed_states"].append(State.CONTROLLED_START.value)
    checkpoint["current_state"] = State.CONTROLLED_START.value
    checkpoint["next_state"] = State.HEALTH_CHECK.value
    deployment._persist(checkpoint)
    with pytest.raises(DriverError, match="state-sequence mismatch"):
        load_checkpoint(tmp_path / "state/forged-skip/checkpoint.json")
