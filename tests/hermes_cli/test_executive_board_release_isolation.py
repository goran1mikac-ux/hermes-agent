from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.executive_board import run_p2_installed_simulation as simulation_runner
from scripts.executive_board.installed_adapter import clean_runtime_env
from scripts.executive_board.release_isolation import (
    ReleaseIsolationError,
    ReleaseRunGuard,
    ReleaseRunSpec,
    assert_safe_database_target,
)


def _spec(tmp_path: Path, *, run_id: str = "codex-20260722T190000Z-a1b2c3d4") -> ReleaseRunSpec:
    worktree = tmp_path / "worktrees" / "codex-incident-worktree"
    venv = tmp_path / "venvs" / run_id
    temp_root = tmp_path / "runs" / run_id
    for path in (worktree, venv, temp_root):
        path.mkdir(parents=True, exist_ok=True)
    canonical = tmp_path / "canonical" / "state.sqlite"
    canonical.parent.mkdir(exist_ok=True)
    canonical.write_bytes(b"canonical")
    return ReleaseRunSpec(
        run_id=run_id,
        technical_owner="codex",
        worktree=worktree,
        venv=venv,
        temp_root=temp_root,
        database=temp_root / "test.sqlite",
        canonical_database=canonical,
        canonical_inode=canonical.stat().st_ino,
        mode="simulation",
        lock_file=tmp_path / "release.lock",
        ownership_file=temp_root / "run-ownership.json",
    )


def test_release_guard_requires_codex_unique_run_scoped_paths(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    with ReleaseRunGuard(spec) as ownership:
        assert ownership["run_id"] == spec.run_id
        assert ownership["technical_owner"] == "codex"
        assert os.environ["P2_RUN_ID"] == spec.run_id
        assert spec.ownership_file.stat().st_mode & 0o777 == 0o600
    assert "P2_RUN_ID" not in os.environ


@pytest.mark.parametrize("field", ["venv", "temp_root"])
def test_release_guard_rejects_non_run_scoped_paths(tmp_path: Path, field: str) -> None:
    spec = _spec(tmp_path)
    values = dict(spec.__dict__)
    values[field] = tmp_path / field
    Path(values[field]).mkdir(exist_ok=True)
    with pytest.raises(ReleaseIsolationError, match="run-scoped"):
        ReleaseRunGuard(ReleaseRunSpec(**values)).__enter__()


def test_release_guard_rejects_non_codex_owner(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    values = dict(spec.__dict__)
    values["technical_owner"] = "donibot"
    with pytest.raises(ReleaseIsolationError, match="technical owner"):
        ReleaseRunGuard(ReleaseRunSpec(**values)).__enter__()


def test_release_guard_blocks_parallel_release_run(tmp_path: Path) -> None:
    first = _spec(tmp_path, run_id="codex-20260722T190000Z-a1b2c3d4")
    second = _spec(tmp_path, run_id="codex-20260722T190001Z-b2c3d4e5")
    second_values = dict(second.__dict__)
    second_values["lock_file"] = first.lock_file
    with ReleaseRunGuard(first):
        with pytest.raises(ReleaseIsolationError, match="parallel release"):
            ReleaseRunGuard(ReleaseRunSpec(**second_values)).__enter__()


def test_canonical_path_and_inode_are_denied_in_test_and_simulation(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    with pytest.raises(ReleaseIsolationError, match="canonical database"):
        assert_safe_database_target(
            spec.canonical_database,
            mode="simulation",
            canonical_database=spec.canonical_database,
            canonical_inode=spec.canonical_inode,
        )
    alias = tmp_path / "alias.sqlite"
    os.link(spec.canonical_database, alias)
    with pytest.raises(ReleaseIsolationError, match="canonical inode"):
        assert_safe_database_target(
            alias,
            mode="test",
            canonical_database=spec.canonical_database,
            canonical_inode=spec.canonical_inode,
        )


def test_missing_canonical_identity_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "test.sqlite"
    with pytest.raises(ReleaseIsolationError, match="canonical identity"):
        assert_safe_database_target(
            target,
            mode="simulation",
            canonical_database=None,
            canonical_inode=None,
        )

def test_release_guard_rejects_doni_worktree(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    values = dict(spec.__dict__)
    values["worktree"] = tmp_path / "worktrees" / "donibot-shared-worktree"
    Path(values["worktree"]).mkdir(parents=True)
    with pytest.raises(ReleaseIsolationError, match="Codex-specific"):
        ReleaseRunGuard(ReleaseRunSpec(**values)).__enter__()


def test_clean_runtime_env_propagates_run_ownership_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/safe/bin")
    monkeypatch.setenv("P2_RUN_ID", "codex-20260722T190000Z-a1b2c3d4")
    monkeypatch.setenv("P2_TECHNICAL_OWNER", "codex")
    monkeypatch.setenv("P2_RUN_OWNERSHIP_TOKEN", "secret-run-token")
    monkeypatch.setenv("P2_RUN_OWNERSHIP_TOKEN_SHA256", "a" * 64)
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-propagate")
    environment = clean_runtime_env()
    assert environment == {
        "PATH": "/safe/bin",
        "PYTHONNOUSERSITE": "1",
        "P2_RUN_ID": "codex-20260722T190000Z-a1b2c3d4",
        "P2_TECHNICAL_OWNER": "codex",
        "P2_RUN_OWNERSHIP_TOKEN": "secret-run-token",
        "P2_RUN_OWNERSHIP_TOKEN_SHA256": "a" * 64,
    }

def test_simulation_entrypoint_requires_release_run_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = tmp_path / "release"
    run_id = "codex-20260722T190000Z-a1b2c3d4"
    run_root = tmp_path / "runs" / run_id
    worktree = tmp_path / "worktrees" / "codex-incident-worktree"
    venv = tmp_path / "venvs" / run_id
    canonical = tmp_path / "canonical" / "state.sqlite"
    for path in (release, run_root, worktree, venv, canonical.parent):
        path.mkdir(parents=True, exist_ok=True)
    canonical.write_bytes(b"canonical")
    entered: list[ReleaseRunSpec] = []

    class GuardProbe:
        def __init__(self, spec: ReleaseRunSpec):
            entered.append(spec)

        def __enter__(self) -> dict[str, str]:
            return {"run_id": run_id}

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(simulation_runner, "ReleaseRunGuard", GuardProbe, raising=False)
    monkeypatch.setattr(simulation_runner, "_execute", lambda _args: 0, raising=False)
    result = simulation_runner.main(
        [
            "--release",
            str(release),
            "--run-id",
            run_id,
            "--run-root",
            str(run_root),
            "--worktree",
            str(worktree),
            "--venv",
            str(venv),
            "--canonical-db",
            str(canonical),
            "--canonical-inode",
            str(canonical.stat().st_ino),
            "--release-lock",
            str(tmp_path / "release.lock"),
        ]
    )
    assert result == 0
    assert len(entered) == 1
    assert entered[0].technical_owner == "codex"
    assert entered[0].database == run_root / "home/agents_os/state.sqlite"
    assert entered[0].ownership_file == run_root / "run-ownership.json"