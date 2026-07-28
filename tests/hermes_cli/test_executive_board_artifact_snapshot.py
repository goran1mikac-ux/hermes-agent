from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts.executive_board.artifact_snapshot import (
    ArtifactSnapshotError,
    SnapshotInputs,
    create_verified_snapshot,
    remove_verified_snapshot,
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_inputs(tmp_path: Path) -> SnapshotInputs:
    source = tmp_path / "caller-release"
    source.mkdir()
    files: dict[str, Path] = {}
    for name in (
        "wheel.whl",
        "manifest.json",
        "runbook.md",
        "launcher.py",
        "adapter.py",
        "driver.py",
        "lock.txt",
        "rollback.sqlite",
    ):
        filename = "hermes_agent-0.19.0-py3-none-any.whl" if name == "wheel.whl" else name
        path = source / filename
        path.write_bytes((name + "\n").encode())
        files[name] = path
    wheelhouse = source / "wheelhouse"
    wheelhouse.mkdir()
    dependency = wheelhouse / "dependency-1.0-py3-none-any.whl"
    dependency.write_bytes(b"dependency-wheel")
    wheelhouse_manifest = source / "wheelhouse-manifest.json"
    wheelhouse_manifest.write_text(
        json.dumps({"schema_version": 1, "files": {dependency.name: sha(dependency)}}) + "\n",
        encoding="utf-8",
    )
    return SnapshotInputs(
        files=files,
        expected_hashes={name: sha(path) for name, path in files.items()},
        wheelhouse=wheelhouse,
        wheelhouse_manifest=wheelhouse_manifest,
        wheelhouse_manifest_sha256=sha(wheelhouse_manifest),
    )


def test_snapshot_uses_verified_copies_after_caller_sources_are_replaced(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path)
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    snapshot = create_verified_snapshot(inputs, deployment)
    expected = snapshot.files["wheel.whl"].read_bytes()

    inputs.files["wheel.whl"].write_bytes(b"attacker replacement")
    inputs.files["launcher.py"].write_bytes(b"raise SystemExit('attacker')")
    inputs.files["lock.txt"].write_bytes(b"evil==9")
    next(inputs.wheelhouse.iterdir()).write_bytes(b"mutated dependency")

    assert snapshot.files["wheel.whl"].read_bytes() == expected
    assert snapshot.files["wheel.whl"] != inputs.files["wheel.whl"]
    assert snapshot.files["wheel.whl"].name == inputs.files["wheel.whl"].name
    assert snapshot.files["launcher.py"].read_bytes() == b"launcher.py\n"
    assert snapshot.files["lock.txt"].read_bytes() == b"lock.txt\n"
    assert next(snapshot.wheelhouse.iterdir()).read_bytes() == b"dependency-wheel"


def test_snapshot_rejects_symlink_source(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path)
    target = inputs.files["launcher.py"]
    target.unlink()
    target.symlink_to(inputs.files["adapter.py"])
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    with pytest.raises(ArtifactSnapshotError, match="symlink|regular"):
        create_verified_snapshot(inputs, deployment)


def test_snapshot_rejects_hardlinked_source(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path)
    hardlink = inputs.files["wheel.whl"].with_name("wheel-hardlink.whl")
    os.link(inputs.files["wheel.whl"], hardlink)
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    with pytest.raises(ArtifactSnapshotError, match="hardlink"):
        create_verified_snapshot(inputs, deployment)


def test_snapshot_rejects_manifest_path_traversal(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path)
    inputs.wheelhouse_manifest.write_text(
        json.dumps({"schema_version": 1, "files": {"../escape.whl": "0" * 64}}),
        encoding="utf-8",
    )
    inputs = SnapshotInputs(
        files=inputs.files,
        expected_hashes=inputs.expected_hashes,
        wheelhouse=inputs.wheelhouse,
        wheelhouse_manifest=inputs.wheelhouse_manifest,
        wheelhouse_manifest_sha256=sha(inputs.wheelhouse_manifest),
    )
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    with pytest.raises(ArtifactSnapshotError, match="filename"):
        create_verified_snapshot(inputs, deployment)


def test_snapshot_rejects_inode_change_during_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inputs = fixture_inputs(tmp_path)
    original_open = os.open
    swapped = False

    def racing_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal swapped
        if not swapped and Path(path) == inputs.files["launcher.py"] and dir_fd is None:
            swapped = True
            replacement = inputs.files["launcher.py"].with_suffix(".replacement")
            replacement.write_bytes(b"replacement")
            replacement.replace(inputs.files["launcher.py"])
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    with pytest.raises(ArtifactSnapshotError, match="changed during open|hash mismatch"):
        create_verified_snapshot(inputs, deployment)


def test_snapshot_cleanup_removes_private_tree_on_success(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path)
    deployment = tmp_path / "deployment"
    deployment.mkdir(mode=0o700)
    snapshot = create_verified_snapshot(inputs, deployment)
    assert snapshot.root.exists()
    assert snapshot.root.stat().st_mode & 0o077 == 0
    remove_verified_snapshot(snapshot, deployment)
    assert not snapshot.root.exists()
