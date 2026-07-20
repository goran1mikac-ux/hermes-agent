"""Local Executive Board domain records on the Agents OS SQLite foundation."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

EXECUTIVE_BOARD_SCHEMA_VERSION = "2"
_SCHEMA_META_KEY = "executive_board_schema_version"
_TABLE = "executive_board_items"
_NONCE_TABLE = "executive_board_consumed_nonces"
_LOCAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "action_type",
        "target",
        "environment",
        "normalized_parameters",
        "artifact_references",
        "risk_class",
        "requested_by",
        "created_at",
        "expires_at",
        "rollback_reference",
    }
)
_SECRET_KEYS = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key|pin|session[_-]?secret)",
    re.IGNORECASE,
)


class PayloadValidationError(ValueError):
    pass


class ApprovalRejected(PermissionError):
    pass


@dataclass(frozen=True)
class CanonicalPayload:
    json: str
    utf8: bytes
    sha256: str


def _validate_json_value(value: Any, *, path: str = "payload") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise PayloadValidationError(f"floats are not allowed at {path}")
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise PayloadValidationError(f"bytes are not allowed at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PayloadValidationError(f"dictionary keys must be strings at {path}")
            if _SECRET_KEYS.search(key) and key not in {"secret_reference"}:
                raise PayloadValidationError(f"credential value is not allowed at {path}.{key}")
            _validate_json_value(item, path=f"{path}.{key}")
        return
    raise PayloadValidationError(f"unsupported value type at {path}: {type(value).__name__}")


def _parse_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise PayloadValidationError(f"{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PayloadValidationError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise PayloadValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonicalize_action_payload(payload: Mapping[str, Any]) -> CanonicalPayload:
    """Validate and deterministically encode an approval-bound action payload."""
    if not isinstance(payload, Mapping):
        raise PayloadValidationError("payload must be a mapping")
    keys = set(payload)
    if keys != _PAYLOAD_FIELDS:
        missing = sorted(_PAYLOAD_FIELDS - keys)
        extra = sorted(keys - _PAYLOAD_FIELDS, key=str)
        raise PayloadValidationError(f"payload fields mismatch; missing={missing}, extra={extra}")
    material = dict(payload)
    _validate_json_value(material)
    if isinstance(material["schema_version"], bool) or not isinstance(
        material["schema_version"], int
    ):
        raise PayloadValidationError("schema_version must be an integer")
    if not isinstance(material["normalized_parameters"], dict):
        raise PayloadValidationError("normalized_parameters must be an object")
    if not isinstance(material["artifact_references"], list) or not all(
        isinstance(item, str) for item in material["artifact_references"]
    ):
        raise PayloadValidationError("artifact_references must be a list of strings")
    for field in (
        "action_type", "target", "environment", "risk_class", "requested_by",
        "rollback_reference",
    ):
        if not isinstance(material[field], str) or not material[field]:
            raise PayloadValidationError(f"{field} must be a non-empty string")
    _parse_timestamp(material["created_at"], "created_at")
    _parse_timestamp(material["expires_at"], "expires_at")
    if "credential" in material["action_type"].lower():
        parameters = material["normalized_parameters"]
        if set(parameters) != {"secret_reference", "fingerprint"} or not all(
            isinstance(parameters[key], str) and parameters[key]
            for key in ("secret_reference", "fingerprint")
        ):
            raise PayloadValidationError(
                "credential actions require only secret_reference and fingerprint"
            )
    encoded = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return CanonicalPayload(
        json=encoded.decode("utf-8"),
        utf8=encoded,
        sha256=hashlib.sha256(encoded).hexdigest(),
    )


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    payload_hash: str
    actor_id: str
    auth_method: str
    decision: str
    approved_at: str
    expires_at: str
    nonce_hash: str
    risk_class: str
    reviewer_id: str
    request_id: str
    run_id: str
    reason: str
    proof: str = ""

    def proof_bytes(self) -> bytes:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "proof"
        }
        return json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")


class HMACLocalProofVerifier:
    """Injectable local-only proof adapter; the key is never persisted."""

    auth_method = "local_hmac"

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("a non-empty in-memory secret is required")
        self._secret = secret

    def hash_nonce(self, nonce: str) -> str:
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        return hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    def sign(self, record: ApprovalRecord) -> ApprovalRecord:
        from dataclasses import replace

        proof = hmac.new(self._secret, record.proof_bytes(), hashlib.sha256).hexdigest()
        return replace(record, proof=proof)

    def verify(self, record: ApprovalRecord) -> bool:
        if record.auth_method != self.auth_method or not record.proof:
            return False
        expected = hmac.new(self._secret, record.proof_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(record.proof, expected)


@dataclass(frozen=True)
class ExecutionContext:
    request_id: str
    run_id: str
    environment: str
    executor_id: str
    expected_executable_hash: str
    actual_executable_hash: str
    circuit_breaker_closed: bool


class ExecutiveBoardExecutionGate:
    def __init__(self, conn: sqlite3.Connection, proof_verifier: Any) -> None:
        self.conn = conn
        self.proof_verifier = proof_verifier
        migrate(conn)

    def authorize_and_consume(
        self,
        payload: Mapping[str, Any],
        approval: ApprovalRecord,
        context: ExecutionContext,
        *,
        now: datetime | None = None,
    ) -> None:
        canonical = canonicalize_action_payload(payload)
        checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        reject = lambda reason: ApprovalRejected(reason)
        if not isinstance(approval, ApprovalRecord) or not self.proof_verifier.verify(approval):
            raise reject("invalid local owner proof")
        if approval.decision != "approved":
            raise reject("approval decision is not approved")
        if approval.actor_id != "goran" or approval.reviewer_id != "goran":
            raise reject("Goran is the only final owner authority")
        if canonical.sha256 != approval.payload_hash:
            raise reject("current payload hash does not match approval")
        if payload["risk_class"] != approval.risk_class:
            raise reject("risk class does not match approval")
        if payload["environment"] != context.environment:
            raise reject("environment binding mismatch")
        if approval.request_id != context.request_id or approval.run_id != context.run_id:
            raise reject("request/run binding mismatch")
        if checked_at >= _parse_timestamp(payload["expires_at"], "expires_at"):
            raise reject("payload expired")
        if checked_at >= _parse_timestamp(approval.expires_at, "expires_at"):
            raise reject("approval expired")
        if payload["risk_class"].upper() == "R3" and approval.reviewer_id == context.executor_id:
            raise reject("high-risk reviewer must differ from executor")
        if (
            not context.expected_executable_hash
            or context.expected_executable_hash != context.actual_executable_hash
        ):
            raise reject("executable manifest/build hash mismatch")
        if context.circuit_breaker_closed is not True:
            raise reject("circuit breaker is open")
        try:
            with self.conn:
                self.conn.execute(
                    f"INSERT INTO {_NONCE_TABLE}(nonce_hash, approval_id, consumed_at) "
                    "VALUES (?, ?, ?)",
                    (approval.nonce_hash, approval.approval_id, checked_at.isoformat()),
                )
        except sqlite3.IntegrityError as exc:
            raise reject("nonce already consumed") from exc


class BoardItemKind(str, Enum):
    RECOMMENDATION = "recommendation"
    ACTION_REQUEST = "action_request"


def canonical_board_id(kind: BoardItemKind, local_id: str) -> str:
    """Build the stable, kind-scoped identity for a local Board record."""
    try:
        normalized_kind = BoardItemKind(kind)
    except ValueError as exc:
        raise ValueError(f"unsupported Board item kind: {kind!r}") from exc
    if not isinstance(local_id, str) or not _LOCAL_ID.fullmatch(local_id):
        raise ValueError("local_id must contain only letters, digits, '.', '_' or '-'")
    return f"executive-board:{normalized_kind.value}:{local_id}"


@dataclass(frozen=True)
class BoardItem:
    canonical_id: str
    kind: BoardItemKind
    title: str
    body: str
    created_at: str

    def __post_init__(self) -> None:
        kind = BoardItemKind(self.kind)
        object.__setattr__(self, "kind", kind)
        prefix = f"executive-board:{kind.value}:"
        if not self.canonical_id.startswith(prefix):
            raise ValueError("canonical_id does not match the Board item kind")
        canonical_board_id(kind, self.canonical_id.removeprefix(prefix))
        if not self.title.strip():
            raise ValueError("title must not be empty")
        if not self.body.strip():
            raise ValueError("body must not be empty")
        if not self.created_at:
            raise ValueError("created_at must not be empty")

    @classmethod
    def create(
        cls,
        *,
        kind: BoardItemKind,
        local_id: str,
        title: str,
        body: str,
        created_at: str | None = None,
    ) -> BoardItem:
        normalized_kind = BoardItemKind(kind)
        timestamp = created_at or datetime.now(timezone.utc).isoformat()
        return cls(
            canonical_id=canonical_board_id(normalized_kind, local_id),
            kind=normalized_kind,
            title=title,
            body=body,
            created_at=timestamp,
        )


@dataclass(frozen=True)
class ExecutiveBoardRollbackPlan:
    """Read-only description of schema owned by this feature slice."""

    tables: tuple[str, ...]
    meta_keys: tuple[str, ...]
    present_tables: tuple[str, ...]
    present_meta_keys: tuple[str, ...]


def migrate(conn: sqlite3.Connection) -> None:
    """Add the Executive Board schema without changing foundation data."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS executive_board_items (
                canonical_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK (kind IN ('recommendation', 'action_request')),
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO agents_os_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_SCHEMA_META_KEY, EXECUTIVE_BOARD_SCHEMA_VERSION),
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_NONCE_TABLE} (
                nonce_hash TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )


class ExecutiveBoardStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        migrate(conn)

    def save(self, item: BoardItem) -> None:
        """Insert or replace the payload belonging to one canonical identity."""
        if not isinstance(item, BoardItem):
            raise TypeError("item must be a BoardItem")
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO executive_board_items
                    (canonical_id, kind, title, body, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(canonical_id) DO UPDATE SET
                    kind=excluded.kind,
                    title=excluded.title,
                    body=excluded.body,
                    created_at=excluded.created_at
                """,
                (item.canonical_id, item.kind.value, item.title, item.body, item.created_at),
            )

    def get(self, canonical_id: str) -> BoardItem | None:
        row = self.conn.execute(
            "SELECT canonical_id, kind, title, body, created_at "
            "FROM executive_board_items WHERE canonical_id = ?",
            (canonical_id,),
        ).fetchone()
        if row is None:
            return None
        return BoardItem(
            canonical_id=row["canonical_id"],
            kind=BoardItemKind(row["kind"]),
            title=row["title"],
            body=row["body"],
            created_at=row["created_at"],
        )


def rollback_plan(conn: sqlite3.Connection) -> ExecutiveBoardRollbackPlan:
    """Inspect what rollback would remove; this function performs no writes."""
    meta_table_present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
    ).fetchone()
    meta_present = None
    if meta_table_present:
        meta_present = conn.execute(
            "SELECT 1 FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,)
        ).fetchone()
    return ExecutiveBoardRollbackPlan(
        tables=(_TABLE, _NONCE_TABLE),
        meta_keys=(_SCHEMA_META_KEY,),
        present_tables=tuple(
            table
            for table in (_TABLE, _NONCE_TABLE)
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
        ),
        present_meta_keys=(_SCHEMA_META_KEY,) if meta_present else (),
    )


def rollback(conn: sqlite3.Connection) -> None:
    """Idempotently remove only schema and metadata owned by this slice."""
    with conn:
        conn.execute(f"DROP TABLE IF EXISTS {_TABLE}")
        conn.execute(f"DROP TABLE IF EXISTS {_NONCE_TABLE}")
        meta_table_present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone()
        if meta_table_present:
            conn.execute("DELETE FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,))
