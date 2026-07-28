#!/usr/bin/env python3
"""Fail-closed hash-pinned offline dependency bundle verifier for RC2 P2."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement


class DependencyLockError(RuntimeError):
    pass


_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(path: Path) -> list[str]:
    if path.is_symlink() or not path.is_file():
        raise DependencyLockError(f"dependency lock is not a regular file: {path}")
    logical: list[str] = []
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1].strip() + " "
            continue
        current += stripped
        logical.append(current.strip())
        current = ""
    if current:
        raise DependencyLockError("unterminated dependency-lock continuation")
    return logical


def verify_hashed_requirements(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in _logical_lines(path):
        lowered = line.lower()
        if lowered.startswith(("-e ", "--editable", "git+", "http://", "https://")):
            raise DependencyLockError("editable or URL dependency is forbidden")
        hashes = sorted(set(_HASH_RE.findall(line)))
        requirement_text = line.split("--hash=sha256:", 1)[0].strip()
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement as exc:
            raise DependencyLockError(
                f"dependency must be exact-pinned and hash-pinned: {line!r}"
            ) from exc
        specifiers = list(requirement.specifier)
        exact = (
            len(specifiers) == 1
            and specifiers[0].operator == "=="
            and "*" not in specifiers[0].version
            and requirement.url is None
        )
        if not exact or not hashes:
            raise DependencyLockError(
                f"dependency must be exact-pinned and hash-pinned: {line!r}"
            )
        entries.append(
            {
                "name": _normalized(requirement.name),
                "version": specifiers[0].version,
                "hashes": hashes,
                "active": requirement.marker is None or requirement.marker.evaluate(),
                "line": line,
            }
        )
    if not entries:
        raise DependencyLockError("dependency lock is empty")
    return entries


def verify_dependency_bundle(
    lock_path: Path, wheelhouse: Path, manifest_path: Path
) -> dict[str, Any]:
    requirements = verify_hashed_requirements(lock_path)
    if wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise DependencyLockError("wheelhouse is not a regular directory")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise DependencyLockError("wheelhouse manifest is not a regular file")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DependencyLockError("invalid wheelhouse manifest") from exc
    files = manifest.get("files")
    if manifest.get("schema_version") != 1 or not isinstance(files, dict) or not files:
        raise DependencyLockError("invalid wheelhouse manifest shape")
    actual_names = sorted(path.name for path in wheelhouse.iterdir() if path.is_file())
    if actual_names != sorted(files):
        raise DependencyLockError("wheelhouse file set mismatch")
    wheel_by_dist: dict[str, list[tuple[str, str]]] = {}
    for name, expected in files.items():
        path = wheelhouse / name
        if path.is_symlink() or path.suffix != ".whl":
            raise DependencyLockError(f"non-wheel or symlink in wheelhouse: {name}")
        actual = _sha256(path)
        if not isinstance(expected, str) or actual != expected:
            raise DependencyLockError(f"wheel hash mismatch: {name}")
        distribution = _normalized(name.split("-", 1)[0])
        wheel_by_dist.setdefault(distribution, []).append((name, actual))
    missing: list[str] = []
    hash_mismatch: list[str] = []
    active_requirements = [item for item in requirements if item["active"]]
    for requirement in active_requirements:
        candidates = wheel_by_dist.get(requirement["name"], [])
        if not candidates:
            missing.append(requirement["name"])
        elif not any(digest in requirement["hashes"] for _name, digest in candidates):
            hash_mismatch.append(requirement["name"])
    if missing:
        raise DependencyLockError(f"dependency wheel missing: {missing}")
    if hash_mismatch:
        raise DependencyLockError(f"lock hash does not bind wheel: {hash_mismatch}")
    return {
        "offline": True,
        "requirements": len(active_requirements),
        "inactive_requirements": len(requirements) - len(active_requirements),
        "wheels": len(files),
        "lock_sha256": _sha256(lock_path),
        "manifest_sha256": _sha256(manifest_path),
    }


def build_offline_install_commands(
    venv: Path, lock_path: Path, wheelhouse: Path, overlay_wheel: Path
) -> tuple[list[str], list[str]]:
    pip = str(venv / "bin/pip")
    dependencies = [
        pip,
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--require-hashes",
        "--only-binary=:all:",
        "--find-links",
        str(wheelhouse.resolve()),
        "-r",
        str(lock_path.resolve()),
    ]
    project = [
        pip,
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--no-deps",
        str(overlay_wheel.resolve()),
    ]
    return dependencies, project


def ensure_offline_venv(
    target_venv: Path,
    lock_path: Path,
    wheelhouse: Path,
    wheelhouse_manifest: Path,
    overlay_wheel: Path,
    *,
    simulation: bool = False,
    base_python: Path = Path("/usr/bin/python3"),
) -> dict[str, Any]:
    """Create or verify a network-closed, hash-pinned target virtualenv."""
    bundle = verify_dependency_bundle(lock_path, wheelhouse, wheelhouse_manifest)
    expected = {
        "schema_version": 1,
        "lock_sha256": bundle["lock_sha256"],
        "wheelhouse_manifest_sha256": bundle["manifest_sha256"],
        "overlay_wheel_sha256": _sha256(overlay_wheel),
        "network_resolution": False,
        "editable_install": False,
    }
    marker = target_venv / ".p2-offline-install.json"
    python = target_venv / "bin/python"
    if target_venv.exists():
        if simulation and python.exists():
            return {**bundle, "venv": str(target_venv), "existing_simulation": True}
        raise DependencyLockError(
            "existing production target venv must not be reused"
        )
    if not base_python.is_file():
        raise DependencyLockError(f"base interpreter missing: {base_python}")
    target_venv.parent.mkdir(parents=True, exist_ok=True)
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONNOUSERSITE": "1"}
    created = False
    try:
        subprocess.run(
            [str(base_python), "-I", "-m", "venv", "--copies", str(target_venv)],
            cwd="/tmp",
            env=env,
            check=True,
            timeout=120,
        )
        created = True
        dependencies, project = build_offline_install_commands(
            target_venv, lock_path, wheelhouse, overlay_wheel
        )
        subprocess.run(dependencies, cwd="/tmp", env=env, check=True, timeout=300)
        subprocess.run(project, cwd="/tmp", env=env, check=True, timeout=180)
        subprocess.run(
            [str(target_venv / "bin/pip"), "check"],
            cwd="/tmp",
            env=env,
            check=True,
            timeout=60,
        )
        marker.write_text(json.dumps(expected, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, subprocess.SubprocessError) as exc:
        if created:
            shutil.rmtree(target_venv, ignore_errors=True)
        raise DependencyLockError(f"offline virtualenv installation failed: {exc}") from exc
    return {**bundle, "venv": str(target_venv), "created": True}
