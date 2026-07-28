#!/usr/bin/env python3
"""Private exact-byte staging for RC2 P2 release inputs.

Caller-controlled release paths are opened once with ``O_NOFOLLOW``, copied into
a deployment-private tree, re-hashed there, and never used again by execution or
installation code.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class ArtifactSnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class SnapshotInputs:
    files: Mapping[str, Path]
    expected_hashes: Mapping[str, str]
    wheelhouse: Path
    wheelhouse_manifest: Path
    wheelhouse_manifest_sha256: str


@dataclass(frozen=True)
class VerifiedArtifactSnapshot:
    root: Path
    files: Mapping[str, Path]
    wheelhouse: Path
    wheelhouse_manifest: Path
    hashes: Mapping[str, str]


def _digest_fd(descriptor: int) -> tuple[str, bytes]:
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
        chunks.append(chunk)
    return hasher.hexdigest(), b"".join(chunks)


def _safe_name(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or Path(value).name != value
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in value)
    ):
        raise ArtifactSnapshotError(f"unsafe artifact filename: {value!r}")
    return value


def _open_verified(path: Path, expected: str, label: str, *, dir_fd: int | None = None) -> tuple[bytes, str]:
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ArtifactSnapshotError(f"invalid expected hash for {label}")
    try:
        before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise ArtifactSnapshotError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ArtifactSnapshotError(f"{label} is not a regular file or is a symlink")
    if before.st_nlink != 1:
        raise ArtifactSnapshotError(f"{label} has an unexpected hardlink count")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise ArtifactSnapshotError(f"cannot safely open {label}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ArtifactSnapshotError(f"{label} changed during open")
        actual, payload = _digest_fd(descriptor)
    finally:
        os.close(descriptor)
    if actual != expected:
        raise ArtifactSnapshotError(f"{label} hash mismatch")
    return payload, actual


def _write_private(path: Path, payload: bytes, expected: str) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode):
            raise ArtifactSnapshotError(f"unsafe staged artifact: {path.name}")
    finally:
        os.close(descriptor)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ArtifactSnapshotError(f"staged artifact hash mismatch: {path.name}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_verified_snapshot(inputs: SnapshotInputs, deployment_dir: Path) -> VerifiedArtifactSnapshot:
    deployment = Path(deployment_dir)
    if deployment.is_symlink() or not deployment.is_dir() or deployment.stat().st_mode & 0o077:
        raise ArtifactSnapshotError("deployment directory must be private and non-symlinked")
    final = deployment / "verified-inputs"
    if final.exists() or final.is_symlink():
        raise ArtifactSnapshotError("verified artifact snapshot already exists")
    temporary = Path(tempfile.mkdtemp(prefix=".verified-inputs-", dir=deployment))
    os.chmod(temporary, 0o700)
    staged_files: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    try:
        if set(inputs.files) != set(inputs.expected_hashes):
            raise ArtifactSnapshotError("artifact snapshot input/hash set mismatch")
        for label in sorted(inputs.files):
            _safe_name(label)
            source = Path(inputs.files[label])
            payload, actual = _open_verified(source, inputs.expected_hashes[label], label)
            destination_name = source.name if label == "wheel.whl" else label
            _safe_name(destination_name)
            if label == "wheel.whl" and not destination_name.endswith(".whl"):
                raise ArtifactSnapshotError("wheel source must have a .whl filename")
            destination = temporary / destination_name
            _write_private(destination, payload, actual)
            staged_files[label] = destination
            hashes[label] = actual

        manifest_payload, manifest_hash = _open_verified(
            Path(inputs.wheelhouse_manifest),
            inputs.wheelhouse_manifest_sha256,
            "wheelhouse manifest",
        )
        try:
            manifest = json.loads(manifest_payload.decode("utf-8"))
            declared = manifest["files"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ArtifactSnapshotError("invalid wheelhouse manifest") from exc
        if manifest.get("schema_version") != 1 or not isinstance(declared, dict) or not declared:
            raise ArtifactSnapshotError("invalid wheelhouse manifest shape")
        for name, digest in declared.items():
            if not isinstance(name, str) or not isinstance(digest, str):
                raise ArtifactSnapshotError("invalid wheelhouse manifest entry")
            _safe_name(name)

        wheelhouse_source = Path(inputs.wheelhouse)
        if wheelhouse_source.is_symlink() or not wheelhouse_source.is_dir():
            raise ArtifactSnapshotError("wheelhouse is not a safe directory")
        source_fd = os.open(
            wheelhouse_source,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        wheelhouse_destination = temporary / "wheelhouse"
        wheelhouse_destination.mkdir(mode=0o700)
        try:
            actual_names = sorted(os.listdir(source_fd))
            if actual_names != sorted(declared):
                raise ArtifactSnapshotError("wheelhouse file set mismatch")
            for name in sorted(declared):
                payload, actual = _open_verified(
                    Path(name), declared[name], f"wheelhouse/{name}", dir_fd=source_fd
                )
                _write_private(wheelhouse_destination / name, payload, actual)
                hashes[f"wheelhouse/{name}"] = actual
        finally:
            os.close(source_fd)
        manifest_destination = temporary / "wheelhouse-manifest.json"
        _write_private(manifest_destination, manifest_payload, manifest_hash)
        hashes["wheelhouse-manifest.json"] = manifest_hash
        _fsync_directory(wheelhouse_destination)
        os.chmod(wheelhouse_destination, 0o500)
        _fsync_directory(temporary)
        os.replace(temporary, final)
        _fsync_directory(deployment)
        os.chmod(final, 0o500)
        rebound_files = {name: final / path.name for name, path in staged_files.items()}
        return VerifiedArtifactSnapshot(
            root=final,
            files=rebound_files,
            wheelhouse=final / "wheelhouse",
            wheelhouse_manifest=final / "wheelhouse-manifest.json",
            hashes=hashes,
        )
    except BaseException:
        if temporary.exists():
            os.chmod(temporary, 0o700)
            for directory in [path for path in temporary.rglob("*") if path.is_dir()]:
                os.chmod(directory, 0o700)
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def remove_verified_snapshot(snapshot: VerifiedArtifactSnapshot, deployment_dir: Path) -> None:
    deployment = Path(deployment_dir).resolve()
    root = snapshot.root
    if root.is_symlink() or root.parent.resolve() != deployment or root.name != "verified-inputs":
        raise ArtifactSnapshotError("refusing to remove snapshot outside deployment directory")
    if not root.exists():
        return
    os.chmod(root, 0o700)
    for directory in [path for path in root.rglob("*") if path.is_dir()]:
        os.chmod(directory, 0o700)
    shutil.rmtree(root)
    _fsync_directory(deployment)
