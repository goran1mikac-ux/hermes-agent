#!/usr/bin/env python3
"""Authenticated append-only local approval ledger for P2.

The owner approval key is supplied by the trusted caller and is never persisted.
The separate anchor detects ordinary ledger rollback/truncation.  A same-UID
attacker able to roll back both ledger and anchor remains outside this local
model; an external append-only authority is required to close that risk.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class LedgerError(RuntimeError):
    pass


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_file(path: Path, *, required: bool = True) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise LedgerError(f"ledger file is missing: {path.name}")
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LedgerError(f"ledger file is a symlink or not regular: {path.name}")
    if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid():
        raise LedgerError(f"ledger owner/group mismatch: {path.name}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise LedgerError(f"ledger permissions must be 0600: {path.name}")


def _validate_directory(path: Path) -> None:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LedgerError("ledger trust directory is unsafe")
    if metadata.st_uid != os.geteuid() or metadata.st_gid != os.getegid():
        raise LedgerError("ledger trust directory owner/group mismatch")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise LedgerError("ledger trust directory permissions must be 0700")


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        payload = _canonical(value) + b"\n"
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise LedgerError("short atomic anchor write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class AuthenticatedApprovalLedger:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / "approval-ledger.v2.ndjson"
        self.trust_dir = self.root / ".approval-ledger-trust"
        self.anchor_path = self.trust_dir / "anchor.json"
        self.lock_path = self.trust_dir / "ledger.lock"

    def _prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.trust_dir.mkdir(mode=0o700, exist_ok=True)
        _validate_directory(self.trust_dir)
        if not self.lock_path.exists():
            descriptor = os.open(
                self.lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        _validate_file(self.lock_path)

    def _anchor(self, sequence: int, head_hash: str, key: bytes) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema_version": 2,
            "sequence": sequence,
            "head_hash": head_hash,
        }
        return {**body, "anchor_hmac": hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()}

    def _read(self, key: bytes) -> list[dict[str, Any]]:
        if len(key) != 32:
            raise LedgerError("ledger authentication key must contain 32 bytes")
        if not self.path.exists():
            if self.anchor_path.exists():
                raise LedgerError("ledger truncation detected: anchor exists without ledger")
            return []
        _validate_file(self.path)
        _validate_file(self.anchor_path)
        records: list[dict[str, Any]] = []
        previous = ""
        seen_nonces: set[str] = set()
        try:
            lines = self.path.read_bytes().splitlines()
        except OSError as exc:
            raise LedgerError("cannot read approval ledger") from exc
        if not lines:
            raise LedgerError("ledger truncation detected")
        for expected_sequence, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LedgerError("ledger record is not valid JSON") from exc
            if not isinstance(record, dict) or record.get("sequence") != expected_sequence:
                raise LedgerError("ledger sequence/reorder violation")
            nonce_digest = record.get("nonce_digest")
            if not isinstance(nonce_digest, str) or nonce_digest in seen_nonces:
                raise LedgerError("ledger duplicate nonce detected")
            seen_nonces.add(nonce_digest)
            stored_record_hash = record.pop("record_hash", None)
            stored_hmac = record.pop("record_hmac", None)
            if record.get("previous_record_hash") != previous:
                raise LedgerError("ledger hash-chain violation")
            expected_hmac = hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()
            if not isinstance(stored_hmac, str) or not hmac.compare_digest(stored_hmac, expected_hmac):
                raise LedgerError("ledger record authentication failed")
            authenticated = {**record, "record_hmac": stored_hmac}
            expected_hash = _digest(authenticated)
            if not isinstance(stored_record_hash, str) or not hmac.compare_digest(stored_record_hash, expected_hash):
                raise LedgerError("ledger record hash-chain authentication failed")
            record["record_hmac"] = stored_hmac
            record["record_hash"] = stored_record_hash
            previous = stored_record_hash
            records.append(record)
        try:
            anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerError("ledger anchor cannot be read") from exc
        stored_anchor_hmac = anchor.pop("anchor_hmac", None)
        expected_anchor_hmac = hmac.new(key, _canonical(anchor), hashlib.sha256).hexdigest()
        if not isinstance(stored_anchor_hmac, str) or not hmac.compare_digest(stored_anchor_hmac, expected_anchor_hmac):
            raise LedgerError("ledger anchor authentication failed")
        if anchor.get("sequence") != len(records) or anchor.get("head_hash") != previous:
            raise LedgerError("ledger truncation or anchor rollback detected")
        return records

    def consume(
        self,
        approval: Mapping[str, Any],
        deployment_id: str,
        key: bytes,
        *,
        allow_idempotent: bool = True,
    ) -> str:
        self._prepare()
        with self.lock_path.open("r+b") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            records = self._read(key)
            try:
                nonce = str(approval["payload"]["nonce"])
            except (KeyError, TypeError) as exc:
                raise LedgerError("approval nonce is missing") from exc
            if not nonce:
                raise LedgerError("approval nonce is missing")
            nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
            approval_digest = hashlib.sha256(_canonical(dict(approval))).hexdigest()
            for record in records:
                if record["nonce_digest"] == nonce_digest:
                    if record["deployment_id"] == deployment_id and record["approval_digest"] == approval_digest:
                        if allow_idempotent:
                            return approval_digest
                        raise LedgerError("approval replay detected")
                    raise LedgerError("approval replay detected")
            body: dict[str, Any] = {
                "schema_version": 2,
                "sequence": len(records) + 1,
                "previous_record_hash": records[-1]["record_hash"] if records else "",
                "nonce_digest": nonce_digest,
                "deployment_id": deployment_id,
                "approval_digest": approval_digest,
                "consumed_at": datetime.now(timezone.utc).isoformat(),
            }
            record_hmac = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            record: dict[str, Any] = {**body, "record_hmac": record_hmac}
            record["record_hash"] = _digest(record)
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                payload = _canonical(record) + b"\n"
                if os.write(descriptor, payload) != len(payload):
                    raise LedgerError("short approval ledger append")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _validate_file(self.path)
            _atomic_json(self.anchor_path, self._anchor(record["sequence"], record["record_hash"], key))
            _validate_file(self.anchor_path)
            return approval_digest

    def verify_consumed(self, approval: Mapping[str, Any], deployment_id: str, key: bytes) -> None:
        self._prepare()
        with self.lock_path.open("r+b") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_SH)
            records = self._read(key)
            try:
                nonce = str(approval["payload"]["nonce"])
            except (KeyError, TypeError) as exc:
                raise LedgerError("approval nonce is missing") from exc
            nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
            approval_digest = hashlib.sha256(_canonical(dict(approval))).hexdigest()
            if not any(
                record["nonce_digest"] == nonce_digest
                and record["deployment_id"] == deployment_id
                and record["approval_digest"] == approval_digest
                for record in records
            ):
                raise LedgerError("approval replay or ledger binding mismatch")

    def verify_latest(self, approval: Mapping[str, Any], deployment_id: str, key: bytes) -> None:
        """Require the supplied envelope to be the authenticated ledger head."""
        self._prepare()
        with self.lock_path.open("r+b") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_SH)
            records = self._read(key)
            if not records:
                raise LedgerError("authenticated ledger head is missing")
            try:
                nonce = str(approval["payload"]["nonce"])
            except (KeyError, TypeError) as exc:
                raise LedgerError("approval nonce is missing") from exc
            nonce_digest = hashlib.sha256(nonce.encode()).hexdigest()
            approval_digest = hashlib.sha256(_canonical(dict(approval))).hexdigest()
            latest = records[-1]
            if not (
                latest["nonce_digest"] == nonce_digest
                and latest["deployment_id"] == deployment_id
                and latest["approval_digest"] == approval_digest
            ):
                raise LedgerError("authenticated ledger rollback/head mismatch")
