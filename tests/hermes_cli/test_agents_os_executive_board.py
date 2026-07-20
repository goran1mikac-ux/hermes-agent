from __future__ import annotations

import sqlite3

import pytest

from hermes_cli.agents_os import connect, resolve_paths
from hermes_cli.agents_os_executive_board import (
    EXECUTIVE_BOARD_SCHEMA_VERSION,
    BoardItem,
    BoardItemKind,
    ExecutiveBoardStore,
    canonical_board_id,
    migrate,
    rollback,
    rollback_plan,
)


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


def test_rollback_plan_is_read_only_and_rollback_removes_only_board_schema(tmp_path):
    with connect(resolve_paths(home=tmp_path / "profile")) as conn:
        conn.execute("CREATE TABLE preexisting_data (value TEXT NOT NULL)")
        conn.execute("INSERT INTO preexisting_data VALUES ('keep me')")
        migrate(conn)
        before = conn.total_changes

        plan = rollback_plan(conn)

        assert conn.total_changes == before
        assert plan.tables == ("executive_board_items",)
        assert plan.meta_keys == ("executive_board_schema_version",)
        assert plan.present_tables == ("executive_board_items",)

        rollback(conn)

        assert conn.execute("SELECT value FROM preexisting_data").fetchone()[0] == "keep me"
        assert conn.execute(
            "SELECT value FROM agents_os_meta WHERE key='schema_version'"
        ).fetchone()[0] == "1"
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='executive_board_items'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM agents_os_meta WHERE key='executive_board_schema_version'"
        ).fetchone()[0] == 0

        rollback(conn)
