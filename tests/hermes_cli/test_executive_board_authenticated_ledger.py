from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from scripts.executive_board.authenticated_ledger import AuthenticatedApprovalLedger, LedgerError


def approval(nonce: str, marker: str = "A") -> dict[str, object]:
    return {"payload": {"nonce": nonce}, "signature": marker, "algorithm": "test"}


def test_ledger_detects_replay_duplicate_reorder_truncation_and_record_tamper(tmp_path: Path) -> None:
    key = b"k" * 32
    ledger = AuthenticatedApprovalLedger(tmp_path)
    first = approval("nonce-1")
    second = approval("nonce-2")
    ledger.consume(first, "deploy-1", key)
    ledger.consume(second, "deploy-1", key)
    ledger.verify_consumed(second, "deploy-1", key)

    with pytest.raises(LedgerError, match="replay"):
        ledger.consume(approval("nonce-1", "different"), "deploy-2", key)

    original = ledger.path.read_bytes()
    lines = original.splitlines(keepends=True)
    ledger.path.write_bytes(b"".join(lines[:1]))
    with pytest.raises(LedgerError, match="truncation|anchor"):
        ledger.verify_consumed(second, "deploy-1", key)

    ledger.path.write_bytes(b"".join(lines[::-1]))
    with pytest.raises(LedgerError, match="sequence|chain|anchor"):
        ledger.verify_consumed(second, "deploy-1", key)

    ledger.path.write_bytes(original + lines[-1])
    with pytest.raises(LedgerError, match="sequence|duplicate|anchor"):
        ledger.verify_consumed(second, "deploy-1", key)

    tampered = json.loads(lines[-1])
    tampered["deployment_id"] = "attacker"
    ledger.path.write_bytes(lines[0] + (json.dumps(tampered) + "\n").encode())
    with pytest.raises(LedgerError, match="authentication|chain|anchor"):
        ledger.verify_consumed(second, "deploy-1", key)


def test_ledger_validates_permissions_owner_type_and_symlinks(tmp_path: Path) -> None:
    key = b"z" * 32
    ledger = AuthenticatedApprovalLedger(tmp_path)
    ledger.consume(approval("nonce"), "deploy", key)
    ledger.path.chmod(0o644)
    with pytest.raises(LedgerError, match="permissions"):
        ledger.verify_consumed(approval("nonce"), "deploy", key)

    ledger.path.chmod(0o600)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(ledger.path.read_bytes())
    replacement.chmod(0o600)
    ledger.path.unlink()
    ledger.path.symlink_to(replacement)
    with pytest.raises(LedgerError, match="symlink|regular"):
        ledger.verify_consumed(approval("nonce"), "deploy", key)


def test_ledger_stores_nonce_digest_not_nonce_and_separates_trust_boundary(tmp_path: Path) -> None:
    key = b"q" * 32
    secret_nonce = "PRIVATE-NONCE-MARKER"
    ledger = AuthenticatedApprovalLedger(tmp_path)
    ledger.consume(approval(secret_nonce), "deploy", key)
    assert secret_nonce.encode() not in ledger.path.read_bytes()
    assert ledger.trust_dir.stat().st_mode & 0o077 == 0
    assert ledger.path.stat().st_mode & 0o077 == 0
    assert ledger.anchor_path.stat().st_mode & 0o077 == 0
    assert hashlib.sha256(secret_nonce.encode()).hexdigest().encode() in ledger.path.read_bytes()
    assert not any(key in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())


def test_wrong_key_cannot_verify_or_advance_ledger(tmp_path: Path) -> None:
    ledger = AuthenticatedApprovalLedger(tmp_path)
    ledger.consume(approval("nonce"), "deploy", b"a" * 32)
    with pytest.raises(LedgerError, match="authentication|anchor"):
        ledger.verify_consumed(approval("nonce"), "deploy", b"b" * 32)


def test_latest_head_rejects_authenticated_checkpoint_rollback(tmp_path: Path) -> None:
    key = b"h" * 32
    ledger = AuthenticatedApprovalLedger(tmp_path)
    old = approval("checkpoint-hash-old")
    current = approval("checkpoint-hash-current")
    ledger.consume(old, "deploy", key)
    ledger.consume(current, "deploy", key)
    ledger.verify_latest(current, "deploy", key)
    with pytest.raises(LedgerError, match="rollback|head"):
        ledger.verify_latest(old, "deploy", key)
