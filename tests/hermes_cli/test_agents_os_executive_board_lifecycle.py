from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from hermes_cli.agents_os import connect, resolve_paths
from hermes_cli.agents_os_executive_board import (
    ApprovalRecord,
    ApprovalRejected,
    BoardMeetingState,
    ExecutionContext,
    ExecutiveBoardExecutionGate,
    ExecutiveBoardLifecycle,
    HMACLocalProofVerifier,
    InvalidBoardTransition,
    canonicalize_action_payload,
    rollback,
)

NOW = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)


def _sha(char: str) -> str:
    return "sha256:" + (char * 64)


@pytest.fixture
def lifecycle(tmp_path):
    paths = resolve_paths(home=tmp_path / "isolated-profile")
    conn = connect(paths)
    verifier = HMACLocalProofVerifier(b"fixture-only-lifecycle-secret")
    board = ExecutiveBoardLifecycle(conn, verifier)
    try:
        yield board, conn, verifier, paths
    finally:
        conn.close()


def _submit_two_and_challenge(board: ExecutiveBoardLifecycle, meeting_id: str) -> None:
    board.submit_blind_proposal(
        meeting_id,
        proposal_id="proposal-a",
        proposer_id="agent-a",
        payload_hash=_sha("a"),
        evidence_hash=_sha("1"),
        created_at=NOW.isoformat(),
    )
    board.submit_blind_proposal(
        meeting_id,
        proposal_id="proposal-b",
        proposer_id="agent-b",
        payload_hash=_sha("b"),
        evidence_hash=_sha("2"),
        created_at=(NOW + timedelta(seconds=1)).isoformat(),
    )
    board.challenge(
        meeting_id,
        challenger_proposal_id="proposal-a",
        target_proposal_id="proposal-b",
        challenge_hash=_sha("c"),
        evidence_hash=_sha("3"),
        created_at=(NOW + timedelta(seconds=2)).isoformat(),
    )
    board.challenge(
        meeting_id,
        challenger_proposal_id="proposal-b",
        target_proposal_id="proposal-a",
        challenge_hash=_sha("d"),
        evidence_hash=_sha("4"),
        created_at=(NOW + timedelta(seconds=3)).isoformat(),
    )


def _build_to_recommendation(
    board: ExecutiveBoardLifecycle,
    meeting_id: str = "meeting-1",
    *,
    consensus: bool = True,
):
    board.create_meeting(meeting_id, "RC2 lifecycle decision", created_at=NOW.isoformat())
    _submit_two_and_challenge(board, meeting_id)
    board.record_deliberation(
        meeting_id,
        consensus=consensus,
        dissent=None if consensus else "Agent B retains a documented risk objection.",
        actor_id="board",
        created_at=(NOW + timedelta(seconds=4)).isoformat(),
    )
    board.record_recommendation(
        meeting_id,
        local_id=f"{meeting_id}-recommendation",
        title="Proceed with isolated RC deployment",
        body="Proceed only after every fail-closed checkpoint is green.",
        evidence_hash=_sha("e"),
        created_at=(NOW + timedelta(seconds=5)).isoformat(),
    )
    return board.get_meeting(meeting_id)


def _owner_material(board: ExecutiveBoardLifecycle, verifier, meeting_id: str):
    meeting = board.get_meeting(meeting_id)
    payload = {
        "schema_version": 1,
        "action_type": "executive_board.owner_decision",
        "target": meeting_id,
        "environment": "local-test",
        "normalized_parameters": {
            "decision": "approved",
            "recommendation_payload_hash": meeting.recommendation_payload_hash,
        },
        "artifact_references": [f"executive-board:{meeting_id}"],
        "evidence_hash": meeting.recommendation_evidence_hash,
        "risk_class": "R3",
        "requested_by": "goran",
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "rollback_reference": f"rollback:{meeting_id}",
    }
    canonical = canonicalize_action_payload(payload)
    approval = verifier.sign(
        ApprovalRecord(
            approval_id=f"approval-{meeting_id}",
            payload_hash=canonical.sha256,
            evidence_hash=payload["evidence_hash"],
            actor_id="goran",
            auth_method="local_hmac",
            decision="approved",
            approved_at=(NOW + timedelta(seconds=6)).isoformat(),
            expires_at=(NOW + timedelta(minutes=5)).isoformat(),
            nonce_hash=verifier.hash_nonce(f"nonce-{meeting_id}"),
            risk_class="R3",
            reviewer_id="goran",
            request_id=f"request-{meeting_id}",
            run_id=f"run-{meeting_id}",
            reason="Approved isolated lifecycle fixture",
        )
    )
    context = ExecutionContext(
        request_id=f"request-{meeting_id}",
        run_id=f"run-{meeting_id}",
        environment="local-test",
        executor_id="worker-1",
        expected_executable_hash="sha256:build-1",
        actual_executable_hash="sha256:build-1",
        circuit_breaker_closed=True,
    )
    return payload, approval, context


def test_full_consensus_lifecycle_closes_task_with_owner_bound_action(lifecycle):
    board, _, verifier, _ = lifecycle
    meeting = _build_to_recommendation(board)
    assert meeting.state is BoardMeetingState.RECOMMENDED
    assert len(board.list_blind_proposals("meeting-1")) == 2
    assert all(not hasattr(item, "proposer_id") for item in board.list_blind_proposals("meeting-1"))

    payload, approval, context = _owner_material(board, verifier, "meeting-1")
    board.owner_decide("meeting-1", payload, approval, context, now=NOW + timedelta(seconds=7))
    action = board.create_action_request(
        "meeting-1",
        local_id="meeting-1-action",
        title="Execute isolated RC deployment",
        body="Execution remains separately approval-gated.",
        created_at=(NOW + timedelta(seconds=8)).isoformat(),
    )
    board.close_task(
        "meeting-1",
        actor_id="worker-1",
        evidence_hash=_sha("f"),
        created_at=(NOW + timedelta(seconds=9)).isoformat(),
    )

    closed = board.get_meeting("meeting-1")
    assert closed.state is BoardMeetingState.CLOSED
    assert closed.consensus is True
    assert closed.dissent is None
    assert closed.owner_payload_hash == canonicalize_action_payload(payload).sha256
    assert closed.executor_id == "worker-1"
    assert closed.action_request_id == action.canonical_id
    assert closed.closure_evidence_hash == _sha("f")
    assert [event.event_type for event in board.list_events("meeting-1")] == [
        "meeting_created",
        "blind_proposal_submitted",
        "blind_proposal_submitted",
        "challenge_recorded",
        "challenge_recorded",
        "consensus_recorded",
        "recommendation_recorded",
        "owner_approved",
        "action_request_created",
        "task_closed",
    ]


def test_full_dissent_lifecycle_requires_and_preserves_dissent(lifecycle):
    board, _, _, _ = lifecycle
    meeting = _build_to_recommendation(board, meeting_id="meeting-dissent", consensus=False)
    assert meeting.state is BoardMeetingState.RECOMMENDED
    assert meeting.consensus is False
    assert meeting.dissent == "Agent B retains a documented risk objection."
    assert "dissent_recorded" in [
        event.event_type for event in board.list_events("meeting-dissent")
    ]


def test_blind_proposals_require_valid_unique_proposers_and_hashes(lifecycle):
    board, _, _, _ = lifecycle
    board.create_meeting("meeting-proposals", "Proposal gate", created_at=NOW.isoformat())
    board.submit_blind_proposal(
        "meeting-proposals",
        proposal_id="p1",
        proposer_id="agent-a",
        payload_hash=_sha("a"),
        evidence_hash=_sha("1"),
        created_at=NOW.isoformat(),
    )
    with pytest.raises(InvalidBoardTransition):
        board.submit_blind_proposal(
            "meeting-proposals",
            proposal_id="p2",
            proposer_id="agent-a",
            payload_hash=_sha("b"),
            evidence_hash=_sha("2"),
            created_at=NOW.isoformat(),
        )
    with pytest.raises(ValueError, match="payload_hash"):
        board.submit_blind_proposal(
            "meeting-proposals",
            proposal_id="p2",
            proposer_id="agent-b",
            payload_hash="bad",
            evidence_hash=_sha("2"),
            created_at=NOW.isoformat(),
        )
    assert len(board.list_blind_proposals("meeting-proposals")) == 1


def test_challenge_requires_two_proposals_and_rejects_self_direction(lifecycle):
    board, _, _, _ = lifecycle
    board.create_meeting("meeting-challenge", "Challenge gate", created_at=NOW.isoformat())
    board.submit_blind_proposal(
        "meeting-challenge",
        proposal_id="p1",
        proposer_id="agent-a",
        payload_hash=_sha("a"),
        evidence_hash=_sha("1"),
        created_at=NOW.isoformat(),
    )
    with pytest.raises(InvalidBoardTransition):
        board.challenge(
            "meeting-challenge",
            challenger_proposal_id="p1",
            target_proposal_id="p1",
            challenge_hash=_sha("c"),
            evidence_hash=_sha("3"),
            created_at=NOW.isoformat(),
        )
    assert board.get_meeting("meeting-challenge").state is BoardMeetingState.COLLECTING_PROPOSALS


def test_deliberation_requires_bidirectional_challenges(lifecycle):
    board, _, _, _ = lifecycle
    board.create_meeting("meeting-one-way", "One way", created_at=NOW.isoformat())
    board.submit_blind_proposal("meeting-one-way", proposal_id="p1", proposer_id="a", payload_hash=_sha("a"), evidence_hash=_sha("1"), created_at=NOW.isoformat())
    board.submit_blind_proposal("meeting-one-way", proposal_id="p2", proposer_id="b", payload_hash=_sha("b"), evidence_hash=_sha("2"), created_at=NOW.isoformat())
    board.challenge("meeting-one-way", challenger_proposal_id="p1", target_proposal_id="p2", challenge_hash=_sha("c"), evidence_hash=_sha("3"), created_at=NOW.isoformat())
    with pytest.raises(InvalidBoardTransition, match="bidirectional"):
        board.record_deliberation("meeting-one-way", consensus=True, dissent=None, actor_id="board", created_at=NOW.isoformat())
    assert board.get_meeting("meeting-one-way").state is BoardMeetingState.CHALLENGING


def test_non_consensus_deliberation_requires_nonempty_dissent(lifecycle):
    board, _, _, _ = lifecycle
    board.create_meeting("meeting-no-dissent", "No dissent", created_at=NOW.isoformat())
    _submit_two_and_challenge(board, "meeting-no-dissent")
    with pytest.raises(InvalidBoardTransition, match="dissent"):
        board.record_deliberation("meeting-no-dissent", consensus=False, dissent=" ", actor_id="board", created_at=NOW.isoformat())
    assert board.get_meeting("meeting-no-dissent").state is BoardMeetingState.CHALLENGED


def test_recommendation_rejected_before_deliberation(lifecycle):
    board, _, _, _ = lifecycle
    board.create_meeting("meeting-early-rec", "Early recommendation", created_at=NOW.isoformat())
    with pytest.raises(InvalidBoardTransition):
        board.record_recommendation("meeting-early-rec", local_id="rec", title="No", body="Too early", evidence_hash=_sha("e"), created_at=NOW.isoformat())
    assert board.get_meeting("meeting-early-rec").state is BoardMeetingState.COLLECTING_PROPOSALS


def test_action_request_and_closure_are_rejected_before_owner_approval(lifecycle):
    board, _, _, _ = lifecycle
    _build_to_recommendation(board, meeting_id="meeting-early-action")
    with pytest.raises(InvalidBoardTransition):
        board.create_action_request("meeting-early-action", local_id="action", title="No", body="Not approved", created_at=NOW.isoformat())
    with pytest.raises(InvalidBoardTransition):
        board.close_task("meeting-early-action", actor_id="worker", evidence_hash=_sha("f"), created_at=NOW.isoformat())
    assert board.get_meeting("meeting-early-action").state is BoardMeetingState.RECOMMENDED


@pytest.mark.parametrize("failure", ["tamper", "evidence", "expiry", "self_approval"])
def test_owner_decision_rejects_tamper_evidence_expiry_and_self_approval(lifecycle, failure):
    board, _, verifier, _ = lifecycle
    _build_to_recommendation(board, meeting_id=f"meeting-{failure}")
    payload, approval, context = _owner_material(board, verifier, f"meeting-{failure}")
    now = NOW + timedelta(seconds=7)
    if failure == "tamper":
        payload = {**payload, "normalized_parameters": {**payload["normalized_parameters"], "decision": "rejected"}}
    elif failure == "evidence":
        approval = verifier.sign(replace(approval, evidence_hash=_sha("9"), proof=""))
    elif failure == "expiry":
        now = NOW + timedelta(minutes=6)
    else:
        context = replace(context, executor_id="goran")
    with pytest.raises(ApprovalRejected):
        board.owner_decide(f"meeting-{failure}", payload, approval, context, now=now)
    assert board.get_meeting(f"meeting-{failure}").state is BoardMeetingState.RECOMMENDED


def test_consumed_owner_approval_nonce_replay_is_rejected(lifecycle):
    board, conn, verifier, _ = lifecycle
    _build_to_recommendation(board, meeting_id="meeting-replay")
    payload, approval, context = _owner_material(board, verifier, "meeting-replay")
    board.owner_decide("meeting-replay", payload, approval, context, now=NOW + timedelta(seconds=7))
    with pytest.raises(ApprovalRejected, match="nonce already consumed"):
        ExecutiveBoardExecutionGate(conn, verifier).authorize_and_consume(
            payload, approval, context, now=NOW + timedelta(seconds=8)
        )


def test_owner_approval_nonce_and_state_transition_are_atomic(lifecycle):
    board, conn, verifier, _ = lifecycle
    _build_to_recommendation(board, meeting_id="meeting-atomic")
    payload, approval, context = _owner_material(board, verifier, "meeting-atomic")
    conn.execute(
        """
        CREATE TRIGGER reject_owner_event
        BEFORE INSERT ON executive_board_lifecycle_events
        WHEN NEW.event_type='owner_approved'
        BEGIN SELECT RAISE(ABORT, 'fixture-owner-event-failure'); END
        """
    )

    with pytest.raises(ApprovalRejected, match="atomic approval transition failed"):
        board.owner_decide(
            "meeting-atomic", payload, approval, context, now=NOW + timedelta(seconds=7)
        )
    assert board.get_meeting("meeting-atomic").state is BoardMeetingState.RECOMMENDED
    assert conn.execute(
        "SELECT COUNT(*) FROM executive_board_consumed_nonces"
    ).fetchone()[0] == 0

    conn.execute("DROP TRIGGER reject_owner_event")
    board.owner_decide(
        "meeting-atomic", payload, approval, context, now=NOW + timedelta(seconds=8)
    )
    assert board.get_meeting("meeting-atomic").state is BoardMeetingState.OWNER_APPROVED


def test_closure_requires_valid_evidence_hash_and_is_single_transition(lifecycle):
    board, _, verifier, _ = lifecycle
    _build_to_recommendation(board, meeting_id="meeting-close")
    payload, approval, context = _owner_material(board, verifier, "meeting-close")
    board.owner_decide("meeting-close", payload, approval, context, now=NOW + timedelta(seconds=7))
    board.create_action_request("meeting-close", local_id="close-action", title="Do", body="Approved", created_at=NOW.isoformat())
    with pytest.raises(InvalidBoardTransition, match="approved executor"):
        board.close_task("meeting-close", actor_id="goran", evidence_hash=_sha("f"), created_at=NOW.isoformat())
    with pytest.raises(ValueError, match="evidence_hash"):
        board.close_task("meeting-close", actor_id="worker-1", evidence_hash="bad", created_at=NOW.isoformat())
    board.close_task("meeting-close", actor_id="worker-1", evidence_hash=_sha("f"), created_at=NOW.isoformat())
    with pytest.raises(InvalidBoardTransition):
        board.close_task("meeting-close", actor_id="worker-1", evidence_hash=_sha("f"), created_at=NOW.isoformat())


def test_rollback_removes_all_lifecycle_schema_and_preserves_foundation(lifecycle):
    board, conn, _, paths = lifecycle
    board.create_meeting("meeting-rollback", "Rollback", created_at=NOW.isoformat())
    rollback(conn)
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "tasks" in tables
    assert not {name for name in tables if name.startswith("executive_board_")}
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert paths.db.exists()
