"""Small local-only WSGI surface for the Agents OS Executive Board."""

from __future__ import annotations

import html
import json
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from http import HTTPStatus
from urllib.parse import quote, unquote

from hermes_cli.agents_os import AgentsOSPaths, connect
from hermes_cli.agents_os_executive_board import (
    BoardItem,
    BoardItemKind,
    ExecutiveBoardStore,
)

MAX_REQUEST_BYTES = 65_536
_ACTION_FIELDS = frozenset({"local_id", "title", "body"})

StartResponse = Callable[[str, list[tuple[str, str]]], object]
WSGIApp = Callable[[dict, StartResponse], Iterable[bytes]]


def _item_payload(item: BoardItem) -> dict[str, str]:
    payload = {
        "id": item.canonical_id,
        "kind": item.kind.value,
        "title": item.title,
        "body": item.body,
        "created_at": item.created_at,
    }
    if item.kind is BoardItemKind.ACTION_REQUEST:
        payload["status"] = "pending"
    return payload


def _response(
    start_response: StartResponse,
    status: HTTPStatus,
    body: bytes,
    content_type: str,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> list[bytes]:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ]
    headers.extend(extra_headers)
    start_response(f"{status.value} {status.phrase}", headers)
    return [body]


def _json_response(
    start_response: StartResponse,
    status: HTTPStatus,
    payload: object,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> list[bytes]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _response(
        start_response,
        status,
        body,
        "application/json; charset=utf-8",
        extra_headers,
    )


def _error(start_response: StartResponse, status: HTTPStatus, code: str, **kwargs):
    return _json_response(start_response, status, {"error": code}, **kwargs)


def _list_items(paths: AgentsOSPaths) -> list[BoardItem]:
    with connect(paths) as conn:
        ExecutiveBoardStore(conn)
        rows = conn.execute(
            "SELECT canonical_id FROM executive_board_items "
            "ORDER BY created_at ASC, canonical_id ASC"
        ).fetchall()
        store = ExecutiveBoardStore(conn)
        return [item for row in rows if (item := store.get(row["canonical_id"])) is not None]


def _read_action_request(environ: dict) -> tuple[str, str, str] | None:
    content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise TypeError("unsupported media type")

    raw_length = environ.get("CONTENT_LENGTH", "")
    try:
        content_length = int(raw_length)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid content length") from exc
    if content_length < 0:
        raise ValueError("invalid content length")
    if content_length > MAX_REQUEST_BYTES:
        raise OverflowError("request too large")

    body = environ["wsgi.input"].read(content_length + 1)
    if len(body) != content_length or len(body) > MAX_REQUEST_BYTES:
        raise ValueError("invalid request body")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid json") from exc
    if not isinstance(payload, dict) or frozenset(payload) != _ACTION_FIELDS:
        raise ValueError("invalid request fields")

    local_id, title, body_text = (payload["local_id"], payload["title"], payload["body"])
    if not all(isinstance(value, str) for value in (local_id, title, body_text)):
        raise ValueError("request fields must be strings")
    if not local_id or len(local_id) > 128:
        raise ValueError("invalid local id")
    if not title.strip() or len(title) > 200:
        raise ValueError("invalid title")
    if not body_text.strip() or len(body_text) > 10_000:
        raise ValueError("invalid body")
    return local_id, title, body_text


def create_app(
    paths: AgentsOSPaths,
    *,
    clock: Callable[[], str] | None = None,
) -> WSGIApp:
    """Construct a directly callable WSGI app backed only by ``paths``."""
    if not isinstance(paths, AgentsOSPaths):
        raise TypeError("paths must be an AgentsOSPaths instance")
    now = clock or (lambda: datetime.now(timezone.utc).isoformat())

    def app(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")

        allowed = "POST" if path == "/api/action-requests" else "GET"
        if method != allowed:
            return _error(
                start_response,
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
                extra_headers=(("Allow", allowed),),
            )

        try:
            if path == "/health":
                return _json_response(start_response, HTTPStatus.OK, {"status": "ok"})
            if path == "/api/metadata":
                return _json_response(
                    start_response,
                    HTTPStatus.OK,
                    {"name": "Executive Board", "api_version": "1", "local_only": True},
                )
            if path == "/api/board":
                items = [_item_payload(item) for item in _list_items(paths)]
                return _json_response(start_response, HTTPStatus.OK, {"items": items})
            if path.startswith("/api/board/"):
                canonical_id = unquote(path.removeprefix("/api/board/"))
                with connect(paths) as conn:
                    item = ExecutiveBoardStore(conn).get(canonical_id)
                if item is None:
                    return _error(start_response, HTTPStatus.NOT_FOUND, "not_found")
                return _json_response(start_response, HTTPStatus.OK, _item_payload(item))
            if path == "/api/action-requests":
                try:
                    action = _read_action_request(environ)
                except TypeError:
                    return _error(
                        start_response,
                        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                        "unsupported_media_type",
                    )
                except OverflowError:
                    return _error(
                        start_response, HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large"
                    )
                except (KeyError, ValueError):
                    return _error(start_response, HTTPStatus.BAD_REQUEST, "invalid_request")
                assert action is not None
                local_id, title, body_text = action
                try:
                    item = BoardItem.create(
                        kind=BoardItemKind.ACTION_REQUEST,
                        local_id=local_id,
                        title=title,
                        body=body_text,
                        created_at=now(),
                    )
                except (TypeError, ValueError):
                    return _error(start_response, HTTPStatus.BAD_REQUEST, "invalid_request")
                with connect(paths) as conn:
                    store = ExecutiveBoardStore(conn)
                    if store.get(item.canonical_id) is not None:
                        return _error(start_response, HTTPStatus.CONFLICT, "conflict")
                    store.save(item)
                location = "/api/board/" + quote(item.canonical_id, safe="")
                return _json_response(
                    start_response,
                    HTTPStatus.CREATED,
                    _item_payload(item),
                    (("Location", location),),
                )
            if path == "/":
                cards = []
                for item in _list_items(paths):
                    cards.append(
                        "<article>"
                        f"<h2>{html.escape(item.title)}</h2>"
                        f"<p>{html.escape(item.body)}</p>"
                        f"<small>{html.escape(item.kind.value)} · "
                        f"{html.escape(item.created_at)}</small>"
                        "</article>"
                    )
                document = (
                    "<!doctype html><html><head><meta charset=\"utf-8\">"
                    "<title>Executive Board</title></head><body>"
                    "<main><h1>Executive Board</h1>"
                    + "".join(cards)
                    + "</main></body></html>"
                ).encode("utf-8")
                return _response(
                    start_response, HTTPStatus.OK, document, "text/html; charset=utf-8"
                )
            return _error(start_response, HTTPStatus.NOT_FOUND, "not_found")
        except Exception:
            return _error(start_response, HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

    return app


__all__ = ["MAX_REQUEST_BYTES", "create_app"]
