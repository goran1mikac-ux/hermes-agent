#!/usr/bin/env python3
"""Ed25519-signed provenance root for Executive Board P2 releases."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class ProvenanceError(RuntimeError):
    pass


REQUIRED_RELEASE_ARTIFACTS = frozenset(
    {
        "wheel.whl",
        "manifest.json",
        "release-plan.json",
        "runbook.md",
        "p2-driver.py",
        "dependency.lock",
        "canonical-adapter.py",
        "installed-launcher.py",
        "rollback.sqlite",
        "wheelhouse-manifest.json",
    }
)


@dataclass(frozen=True)
class TrustedEd25519PublicKey:
    key_bytes: bytes
    key_id: str
    trust_domain: str


@dataclass(frozen=True)
class VerifiedProvenance:
    manifest: Mapping[str, Any]
    manifest_sha256: str
    signature_sha256: str
    artifact_hashes: Mapping[str, str]
    key_id: str
    trust_domain: str


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def key_id_for_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ProvenanceError("Ed25519 public key must contain exactly 32 bytes")
    return "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()[:32]


def _read_safe_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    candidate = Path(path)
    try:
        before = os.stat(candidate, follow_symlinks=False)
    except OSError as exc:
        raise ProvenanceError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ProvenanceError(f"unsafe {label} file")
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProvenanceError(f"{label} changed during open")
        payload = os.read(descriptor, max_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > max_bytes:
        raise ProvenanceError(f"{label} exceeds size limit")
    return payload


def load_trusted_public_key(path: Path, *, expected_domain: str) -> TrustedEd25519PublicKey:
    candidate = Path(path)
    payload = _read_safe_file(candidate, "provenance trust root", max_bytes=4096)
    mode = os.stat(candidate, follow_symlinks=False)
    if mode.st_uid != os.geteuid() or mode.st_gid != os.getegid() or mode.st_mode & 0o077:
        raise ProvenanceError("provenance trust-root ownership or permissions are unsafe")
    try:
        document = json.loads(payload.decode("utf-8"))
        key_bytes = base64.b64decode(document["public_key_base64"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ProvenanceError("invalid provenance trust root") from exc
    if document.get("algorithm") != "Ed25519" or document.get("trust_domain") != expected_domain:
        raise ProvenanceError("provenance trust-root algorithm or domain mismatch")
    key_id = key_id_for_public_key(key_bytes)
    if document.get("key_id") != key_id:
        raise ProvenanceError("provenance trust-root key ID mismatch")
    return TrustedEd25519PublicKey(key_bytes, key_id, expected_domain)


def build_root_manifest(
    artifact_hashes: Mapping[str, str],
    public_key: bytes,
    *,
    trust_domain: str,
) -> dict[str, Any]:
    if trust_domain not in {"production", "simulation"}:
        raise ProvenanceError("invalid provenance trust domain")
    normalized: dict[str, str] = {}
    for name, digest in sorted(artifact_hashes.items()):
        if not name or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ProvenanceError("unsafe provenance artifact path")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ProvenanceError(f"invalid provenance hash: {name}")
        normalized[name] = digest
    missing = REQUIRED_RELEASE_ARTIFACTS - normalized.keys()
    if missing:
        raise ProvenanceError(f"provenance manifest missing required artifacts: {sorted(missing)}")
    return {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": key_id_for_public_key(public_key),
        "trust_domain": trust_domain,
        "artifacts": normalized,
    }


def sign_root_manifest(manifest: Mapping[str, Any], private_key: bytes) -> tuple[bytes, bytes]:
    if len(private_key) != 32:
        raise ProvenanceError("Ed25519 private key must contain exactly 32 bytes")
    manifest_bytes = canonical_json(manifest)
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(manifest_bytes)
    envelope = canonical_json(
        {
            "algorithm": "Ed25519",
            "key_id": manifest.get("key_id"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
    )
    return manifest_bytes, envelope


def verify_release_provenance(
    manifest_path: Path,
    signature_path: Path | None,
    trust_key: TrustedEd25519PublicKey | None,
    *,
    expected_domain: str,
) -> VerifiedProvenance:
    if signature_path is None or trust_key is None:
        raise ProvenanceError("signed provenance is mandatory; unsigned fallback is forbidden")
    if trust_key.trust_domain != expected_domain:
        raise ProvenanceError("production and simulation provenance roots may not be reused")
    manifest_bytes = _read_safe_file(Path(manifest_path), "root manifest", max_bytes=1024 * 1024)
    signature_bytes = _read_safe_file(Path(signature_path), "root signature", max_bytes=4096)
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        envelope = json.loads(signature_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError("invalid provenance serialization") from exc
    if not isinstance(manifest, dict) or canonical_json(manifest) != manifest_bytes:
        raise ProvenanceError("root manifest must use canonical JSON encoding")
    if not isinstance(envelope, dict) or canonical_json(envelope) != signature_bytes:
        raise ProvenanceError("root signature must use canonical JSON encoding")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("algorithm") != "Ed25519"
        or envelope.get("algorithm") != "Ed25519"
        or manifest.get("trust_domain") != expected_domain
        or manifest.get("key_id") != trust_key.key_id
        or envelope.get("key_id") != trust_key.key_id
    ):
        raise ProvenanceError("provenance metadata mismatch")
    try:
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
        Ed25519PublicKey.from_public_bytes(trust_key.key_bytes).verify(
            signature, manifest_bytes
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ProvenanceError("root manifest signature verification failed") from exc
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ProvenanceError("root manifest artifact index is invalid")
    normalized = build_root_manifest(
        artifacts, trust_key.key_bytes, trust_domain=expected_domain
    )["artifacts"]
    return VerifiedProvenance(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        signature_sha256=hashlib.sha256(signature_bytes).hexdigest(),
        artifact_hashes=normalized,
        key_id=trust_key.key_id,
        trust_domain=expected_domain,
    )


def verify_snapshot_provenance(
    provenance: VerifiedProvenance, snapshot_hashes: Mapping[str, str]
) -> None:
    if dict(provenance.artifact_hashes) != dict(snapshot_hashes):
        raise ProvenanceError("verified snapshot does not exactly match signed provenance")


def public_key_bytes_from_private(private_key: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
