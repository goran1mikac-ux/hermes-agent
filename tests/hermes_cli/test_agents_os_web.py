from __future__ import annotations

import io
import json

import pytest

from hermes_cli.agents_os import connect, resolve_paths
from hermes_cli.agents_os_executive_board import BoardItem, BoardItemKind, ExecutiveBoardStore
from hermes_cli.agents_os_web import create_app


FIXED_TIME = "2026-07-20T10:00:00+00:00"


def call(app, path, *, method="GET", body=b"", content_type=None, content_length=None):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)) if content_length is None else content_length,
    }
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    response_body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], response_body


def json_call(app, path, **kwargs):
    status, headers, body = call(app, path, **kwargs)
    return status, headers, json.loads(body)


@pytest.fixture
def board_app(tmp_path):
    paths = resolve_paths(home=tmp_path / "isolated-profile")
    with connect(paths) as conn:
        store = ExecutiveBoardStore(conn)
        store.save(
            BoardItem.create(
                kind=BoardItemKind.RECOMMENDATION,
                local_id="rec-1",
                title="Prefer local rollout",
                body="Keep the first slice reversible.",
                created_at="2026-07-19T09:00:00+00:00",
            )
        )
    return create_app(paths, clock=lambda: FIXED_TIME), paths


def test_health_and_metadata_are_minimal_and_deterministic(board_app):
    app, _ = board_app

    health_status, health_headers, health = json_call(app, "/health")
    meta_status, _, metadata = json_call(app, "/api/metadata")

    assert health_status == "200 OK"
    assert health_headers["Content-Type"] == "application/json; charset=utf-8"
    assert health == {"status": "ok"}
    assert meta_status == "200 OK"
    assert metadata == {"name": "Executive Board", "api_version": "1", "local_only": True}


def test_board_list_and_detail_use_the_explicit_test_database(board_app):
    app, _ = board_app

    list_status, _, listing = json_call(app, "/api/board")
    detail_status, _, detail = json_call(
        app, "/api/board/executive-board%3Arecommendation%3Arec-1"
    )

    expected = {
        "id": "executive-board:recommendation:rec-1",
        "kind": "recommendation",
        "title": "Prefer local rollout",
        "body": "Keep the first slice reversible.",
        "created_at": "2026-07-19T09:00:00+00:00",
    }
    assert list_status == "200 OK"
    assert listing == {"items": [expected]}
    assert detail_status == "200 OK"
    assert detail == expected


def test_missing_detail_is_a_generic_json_404(board_app):
    status, _, payload = json_call(board_app[0], "/api/board/missing")

    assert status == "404 Not Found"
    assert payload == {"error": "not_found"}


def test_post_action_request_only_persists_a_pending_board_item(board_app):
    app, paths = board_app
    request = json.dumps(
        {"local_id": "approve-1", "title": "Approve pilot", "body": "Review locally."}
    ).encode()

    status, headers, payload = json_call(
        app,
        "/api/action-requests",
        method="POST",
        body=request,
        content_type="application/json",
    )

    assert status == "201 Created"
    assert headers["Location"] == "/api/board/executive-board%3Aaction_request%3Aapprove-1"
    assert payload == {
        "id": "executive-board:action_request:approve-1",
        "kind": "action_request",
        "status": "pending",
        "title": "Approve pilot",
        "body": "Review locally.",
        "created_at": FIXED_TIME,
    }
    with connect(paths) as conn:
        saved = ExecutiveBoardStore(conn).get(payload["id"])
    assert saved is not None
    assert saved.kind is BoardItemKind.ACTION_REQUEST
    assert saved.title == "Approve pilot"


@pytest.mark.parametrize(
    ("body", "content_type", "content_length", "expected_status"),
    [
        (b"{}", None, None, "415 Unsupported Media Type"),
        (b"{}", "text/plain", None, "415 Unsupported Media Type"),
        (b"{", "application/json", None, "400 Bad Request"),
        (b"[]", "application/json", None, "400 Bad Request"),
        (b'{"local_id":"x","title":"t","body":"b","extra":true}', "application/json", None, "400 Bad Request"),
        (b'{"local_id":"x","title":"","body":"b"}', "application/json", None, "400 Bad Request"),
        (b"{}", "application/json", "not-a-number", "400 Bad Request"),
        (b"{}", "application/json", str(65_537), "413 Request Entity Too Large"),
    ],
)
def test_post_validation_fails_closed_without_echoing_input(
    board_app, body, content_type, content_length, expected_status
):
    status, _, payload = json_call(
        board_app[0],
        "/api/action-requests",
        method="POST",
        body=body,
        content_type=content_type,
        content_length=content_length,
    )

    assert status == expected_status
    assert payload == {"error": {
        "415 Unsupported Media Type": "unsupported_media_type",
        "400 Bad Request": "invalid_request",
        "413 Request Entity Too Large": "payload_too_large",
    }[expected_status]}
    assert "local_id" not in payload


def test_methods_are_restricted_with_allow_header(board_app):
    status, headers, payload = json_call(board_app[0], "/api/board", method="POST")

    assert status == "405 Method Not Allowed"
    assert headers["Allow"] == "GET"
    assert payload == {"error": "method_not_allowed"}


def test_minimal_html_board_escapes_item_content(board_app):
    app, paths = board_app
    with connect(paths) as conn:
        ExecutiveBoardStore(conn).save(
            BoardItem.create(
                kind=BoardItemKind.RECOMMENDATION,
                local_id="unsafe",
                title="<script>alert(1)</script>",
                body="Use <b>care</b>.",
                created_at=FIXED_TIME,
            )
        )

    status, headers, body = call(app, "/")
    html = body.decode()

    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "<h1>Executive Board</h1>" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Use &lt;b&gt;care&lt;/b&gt;." in html
    assert "<script>alert(1)</script>" not in html
