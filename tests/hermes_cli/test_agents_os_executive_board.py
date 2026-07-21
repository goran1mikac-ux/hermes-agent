from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from hermes_cli.agents_os import connect, resolve_paths
from hermes_cli.agents_os_executive_board import (
    EXECUTIVE_BOARD_SCHEMA_VERSION,
    ExecutiveBoardMigrationError,
    BoardItem,
    BoardItemKind,
    ApprovalRecord,
    ExecutionContext,
    ExecutiveBoardExecutionGate,
    ExecutiveBoardStore,
    HMACLocalProofVerifier,
    PayloadValidationError,
    ApprovalRejected,
    canonicalize_action_payload,
    canonical_board_id,
    migrate,
    rollback,
    rollback_plan,
)


NOW = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)


def _payload(**changes):
    payload = {
        "schema_version": 1,
        "action_type": "deploy_contract_test",
        "target": "executive-board-fixture",
        "environment": "local-test",
        "normalized_parameters": {"dry_run": True, "retries": 2},
        "artifact_references": ["artifact:plan:sha256:abc"],
        "evidence_hash": "sha256:" + ("a" * 64),
        "risk_class": "R3",
        "requested_by": "goran",
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "rollback_reference": "rollback:fixture:v1",
    }
    payload.update(changes)
    return payload


def _approval(verifier, payload=None, **changes):
    bound_payload = payload or _payload()
    values = {
        "approval_id": "approval-1",
        "payload_hash": canonicalize_action_payload(bound_payload).sha256,
        "evidence_hash": bound_payload["evidence_hash"],
        "actor_id": "goran",
        "auth_method": "local_hmac",
        "decision": "approved",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "nonce_hash": verifier.hash_nonce("nonce-1"),
        "risk_class": "R3",
        "reviewer_id": "goran",
        "request_id": "request-1",
        "run_id": "run-1",
        "reason": "Approved local contract fixture",
    }
    values.update(changes)
    return verifier.sign(ApprovalRecord(**values))


def _context(**changes):
    values = {
        "request_id": "request-1",
        "run_id": "run-1",
        "environment": "local-test",
        "executor_id": "worker-1",
        "expected_executable_hash": "sha256:build-1",
        "actual_executable_hash": "sha256:build-1",
        "circuit_breaker_closed": True,
    }
    values.update(changes)
    return ExecutionContext(**values)


def test_canonical_identity_is_stable_and_kind_scoped():
    recommendation = canonical_board_id(BoardItemKind.RECOMMENDATION, "local-42")
    action = canonical_board_id(BoardItemKind.ACTION_REQUEST, "local-42")

    assert recommendation == "executive-board:recommendation:local-42"
    assert action == "executive-board:action_request:local-42"
    assert recommendation != action


@pytest.mark.parametrize("local_id", ["", " leading", "trailing ", "has:colon"])
def test_canonical_identity_rejects_ambiguous_local_ids(local_id):
    with pytest.raises(ValueError):
        canonical_board_id(BoardItemKind.RECOMMENDATION, local_id)


def test_store_round_trips_recommendation_and_action_request(tmp_path):
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        store = ExecutiveBoardStore(conn)
        recommendation = BoardItem.create(
            kind=BoardItemKind.RECOMMENDATION,
            local_id="rec-1",
            title="Prefer the reversible launch",
            body="Start with the local-only path.",
        )
        action = BoardItem.create(
            kind=BoardItemKind.ACTION_REQUEST,
            local_id="action-1",
            title="Approve the pilot",
            body="Decision requested by Friday.",
        )

        store.save(recommendation)
        store.save(action)

        assert store.get(recommendation.canonical_id) == recommendation
        assert store.get(action.canonical_id) == action
        assert store.get("executive-board:recommendation:missing") is None


def test_save_replaces_the_same_canonical_item_without_duplicates(tmp_path):
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        store = ExecutiveBoardStore(conn)
        original = BoardItem.create(
            kind=BoardItemKind.RECOMMENDATION,
            local_id="rec-1",
            title="First title",
            body="First body",
        )
        revised = BoardItem(
            canonical_id=original.canonical_id,
            kind=original.kind,
            title="Revised title",
            body="Revised body",
            created_at=original.created_at,
        )

        store.save(original)
        store.save(revised)

        assert store.get(original.canonical_id) == revised
        assert conn.execute("SELECT COUNT(*) FROM executive_board_items").fetchone()[0] == 1


def test_migration_is_idempotent_and_preserves_existing_data(tmp_path):
    db = tmp_path / "foundation.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO agents_os_meta VALUES ('schema_version', '1');
        CREATE TABLE preexisting_data (value TEXT NOT NULL);
        INSERT INTO preexisting_data VALUES ('keep me');
        """
    )

    migrate(conn)
    migrate(conn)

    assert conn.execute("SELECT value FROM preexisting_data").fetchone()[0] == "keep me"
    assert conn.execute(
        "SELECT value FROM agents_os_meta WHERE key='schema_version'"
    ).fetchone()[0] == "1"
    assert conn.execute(
        "SELECT value FROM agents_os_meta WHERE key='executive_board_schema_version'"
    ).fetchone()[0] == EXECUTIVE_BOARD_SCHEMA_VERSION
    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='executive_board_items'"
    ).fetchone()[0] == 1
    conn.close()


def test_migration_upgrades_real_v2_schema_and_preserves_rows(tmp_path):
    conn = sqlite3.connect(tmp_path / "v2.sqlite")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO agents_os_meta VALUES ('schema_version', '1');
        INSERT INTO agents_os_meta VALUES ('executive_board_schema_version', '2');
        CREATE TABLE executive_board_items (
            canonical_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind IN ('recommendation', 'action_request')),
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE executive_board_consumed_nonces (
            nonce_hash TEXT PRIMARY KEY,
            approval_id TEXT NOT NULL,
            consumed_at TEXT NOT NULL
        );
        INSERT INTO executive_board_items VALUES
            ('executive-board:recommendation:legacy', 'recommendation', 'Keep', 'Preserved', '2026-07-21T00:00:00+00:00');
        INSERT INTO executive_board_consumed_nonces VALUES
            ('sha256:legacy', 'approval-legacy', '2026-07-21T00:00:01+00:00');
        """
    )

    migrate(conn)
    migrate(conn)

    assert conn.execute(
        "SELECT value FROM agents_os_meta WHERE key='executive_board_schema_version'"
    ).fetchone()[0] == "3"
    assert conn.execute("SELECT title FROM executive_board_items").fetchone()[0] == "Keep"
    assert conn.execute("SELECT approval_id FROM executive_board_consumed_nonces").fetchone()[0] == "approval-legacy"
    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'executive_board_%'"
    ).fetchone()[0] == 6
    conn.close()


def test_migration_rejects_future_version_without_overwriting_metadata(tmp_path):
    conn = sqlite3.connect(tmp_path / "future.sqlite")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO agents_os_meta VALUES ('executive_board_schema_version', '4');
        """
    )

    with pytest.raises(ExecutiveBoardMigrationError, match="unsupported schema version"):
        migrate(conn)

    assert conn.execute(
        "SELECT value FROM agents_os_meta WHERE key='executive_board_schema_version'"
    ).fetchone()[0] == "4"
    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'executive_board_%'"
    ).fetchone()[0] == 0
    conn.close()


def test_migration_rejects_incomplete_v3_schema_instead_of_repairing_it(tmp_path):
    conn = sqlite3.connect(tmp_path / "incomplete-v3.sqlite")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE agents_os_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO agents_os_meta VALUES ('executive_board_schema_version', '3');
        CREATE TABLE executive_board_items (
            canonical_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    with pytest.raises(ExecutiveBoardMigrationError, match="table set mismatch"):
        migrate(conn)

    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'executive_board_%'"
    ).fetchone()[0] == 1
    conn.close()


def test_rollback_plan_is_read_only_and_rollback_removes_only_board_schema(tmp_path):
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        conn.execute("CREATE TABLE preexisting_data (value TEXT NOT NULL)")
        conn.execute("INSERT INTO preexisting_data VALUES ('keep me')")
        migrate(conn)
        before = conn.total_changes

        plan = rollback_plan(conn)

        assert conn.total_changes == before
        assert plan.tables == (
            "executive_board_lifecycle_events",
            "executive_board_challenges",
            "executive_board_proposals",
            "executive_board_meetings",
            "executive_board_items",
            "executive_board_consumed_nonces",
        )
        assert plan.meta_keys == ("executive_board_schema_version",)
        assert plan.present_tables == (
            "executive_board_lifecycle_events",
            "executive_board_challenges",
            "executive_board_proposals",
            "executive_board_meetings",
            "executive_board_items",
            "executive_board_consumed_nonces",
        )

        rollback(conn)

        assert conn.execute("SELECT value FROM preexisting_data").fetchone()[0] == "keep me"
        assert conn.execute(
            "SELECT value FROM agents_os_meta WHERE key='schema_version'"
        ).fetchone()[0] == "1"
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'executive_board_%'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM agents_os_meta WHERE key='executive_board_schema_version'"
        ).fetchone()[0] == 0

        rollback(conn)


def test_canonical_payload_is_stable_utf8_sorted_compact_and_hashed():
    left = _payload(normalized_parameters={"z": 2, "enabled": True, "name": "Žir"})
    right = dict(reversed(list(left.items())))

    canonical = canonicalize_action_payload(left)

    assert canonical.utf8 == canonicalize_action_payload(right).utf8
    assert canonical.utf8.decode() == canonical.json
    assert b'"enabled":true' in canonical.utf8
    assert b" " not in canonical.utf8
    assert len(canonical.sha256) == 64


@pytest.mark.parametrize(
    "evidence_hash",
    ["", "sha256:abc", "md5:" + ("a" * 32), "sha256:" + ("z" * 64)],
)
def test_canonical_payload_requires_a_sha256_evidence_hash(evidence_hash):
    with pytest.raises(PayloadValidationError, match="evidence_hash"):
        canonicalize_action_payload(_payload(evidence_hash=evidence_hash))


@pytest.mark.parametrize(
    "parameters",
    [
        {"ratio": 1.5},
        {"ratio": float("nan")},
        {"blob": b"secret"},
        {1: "not-a-string-key"},
        {"api_key": "plaintext-secret"},
        {"password": "plaintext-secret"},
        {"secret_reference": "vault:item", "token": "plaintext"},
    ],
)
def test_canonical_payload_rejects_unstable_or_secret_values(parameters):
    with pytest.raises(PayloadValidationError):
        canonicalize_action_payload(_payload(normalized_parameters=parameters))


def test_credential_action_allows_only_reference_and_fingerprint():
    canonicalize_action_payload(
        _payload(
            action_type="credential_rotate",
            normalized_parameters={
                "secret_reference": "vault:service/account",
                "fingerprint": "sha256:abc",
            },
        )
    )
    with pytest.raises(PayloadValidationError):
        canonicalize_action_payload(
            _payload(
                action_type="credential_rotate",
                normalized_parameters={"secret_reference": "vault:item", "scope": "extra"},
            )
        )


def test_fake_decided_by_or_model_claim_is_not_owner_proof(tmp_path):
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    unsigned = replace(_approval(verifier), proof="")
    forged_payload = _payload(decided_by="goran", approved_by="goran", approved_model_call=True)
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        gate = ExecutiveBoardExecutionGate(conn, verifier)
        with pytest.raises((PayloadValidationError, ApprovalRejected)):
            gate.authorize_and_consume(forged_payload, unsigned, _context(), now=NOW)


def test_approval_record_cannot_store_raw_auth_or_credential_material():
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    stored_fields = vars(_approval(verifier))
    forbidden = {"nonce", "token", "pin", "session_secret", "credential", "secret"}

    assert forbidden.isdisjoint(stored_fields)


@pytest.mark.parametrize(
    ("payload_change", "approval_change", "context_change"),
    [
        ({"target": "tampered"}, {}, {}),
        ({"artifact_references": ["artifact:other"]}, {}, {}),
        ({"evidence_hash": "sha256:" + ("b" * 64)}, {}, {}),
        ({}, {"evidence_hash": "sha256:" + ("b" * 64)}, {}),
        ({"risk_class": "R2"}, {}, {}),
        ({"rollback_reference": "rollback:other"}, {}, {}),
        ({}, {}, {"request_id": "request-other"}),
        ({}, {}, {"run_id": "run-other"}),
        ({}, {}, {"environment": "staging"}),
        ({}, {"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, {}),
        ({}, {}, {"actual_executable_hash": "sha256:other"}),
        ({}, {}, {"circuit_breaker_closed": False}),
    ],
)
def test_execution_gate_fails_closed_on_binding_mismatch(
    tmp_path, payload_change, approval_change, context_change
):
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    original = _payload()
    approval = _approval(verifier, original, **approval_change)
    candidate = {**original, **payload_change}
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        gate = ExecutiveBoardExecutionGate(conn, verifier)
        with pytest.raises(ApprovalRejected):
            gate.authorize_and_consume(
                candidate, approval, _context(**context_change), now=NOW
            )


def test_high_risk_reviewer_must_differ_from_executor(tmp_path):
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    approval = _approval(verifier)
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        with pytest.raises(ApprovalRejected):
            ExecutiveBoardExecutionGate(conn, verifier).authorize_and_consume(
                _payload(), approval, _context(executor_id="goran"), now=NOW
            )


@pytest.mark.parametrize(
    "approval_factory",
    [
        lambda verifier: replace(_approval(verifier), actor_id="not-goran"),
        lambda verifier: replace(_approval(verifier), reviewer_id="not-goran"),
        lambda verifier: replace(_approval(verifier), proof=""),
        lambda verifier: replace(_approval(verifier), proof="0" * 64),
    ],
)
def test_owner_identity_and_proof_fail_closed(tmp_path, approval_factory):
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        with pytest.raises(ApprovalRejected):
            ExecutiveBoardExecutionGate(conn, verifier).authorize_and_consume(
                _payload(), approval_factory(verifier), _context(), now=NOW
            )


def test_nonce_consumption_is_atomic_and_replay_is_rejected(tmp_path):
    verifier = HMACLocalProofVerifier(b"fixture-only-secret")
    approval = _approval(verifier)
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        gate = ExecutiveBoardExecutionGate(conn, verifier)
        gate.authorize_and_consume(_payload(), approval, _context(), now=NOW)
        with pytest.raises(ApprovalRejected, match="nonce"):
            gate.authorize_and_consume(_payload(), approval, _context(), now=NOW)
        assert conn.execute(
            "SELECT COUNT(*) FROM executive_board_consumed_nonces"
        ).fetchone()[0] == 1
