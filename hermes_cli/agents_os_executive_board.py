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
from typing import Any, Callable, Mapping

EXECUTIVE_BOARD_SCHEMA_VERSION = "3"
_SCHEMA_META_KEY = "executive_board_schema_version"
_TABLE = "executive_board_items"
_NONCE_TABLE = "executive_board_consumed_nonces"
_MEETING_TABLE = "executive_board_meetings"
_PROPOSAL_TABLE = "executive_board_proposals"
_CHALLENGE_TABLE = "executive_board_challenges"
_EVENT_TABLE = "executive_board_lifecycle_events"
_OWNED_TABLES = (
    _EVENT_TABLE,
    _CHALLENGE_TABLE,
    _PROPOSAL_TABLE,
    _MEETING_TABLE,
    _TABLE,
    _NONCE_TABLE,
)
_LOCAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "action_type",
        "target",
        "environment",
        "normalized_parameters",
        "artifact_references",
        "evidence_hash",
        "risk_class",
        "requested_by",
        "created_at",
        "expires_at",
        "rollback_reference",
    }
)
_SHA256_EVIDENCE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SECRET_KEYS = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|credential|private[_-]?key|pin|session[_-]?secret)",
    re.IGNORECASE,
)


class PayloadValidationError(ValueError):
    pass


class ApprovalRejected(PermissionError):
    pass


class InvalidBoardTransition(RuntimeError):
    """Raised before any write when a lifecycle transition is not allowed."""


class ExecutiveBoardMigrationError(RuntimeError):
    """Raised without mutation when Board schema provenance is inconsistent."""


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
    if not isinstance(material["evidence_hash"], str) or not _SHA256_EVIDENCE.fullmatch(
        material["evidence_hash"]
    ):
        raise PayloadValidationError("evidence_hash must be a lowercase sha256 digest")
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
    evidence_hash: str
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
        authorized_write: Callable[[], None] | None = None,
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
        if payload["evidence_hash"] != approval.evidence_hash:
            raise reject("current evidence hash does not match approval")
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
                if authorized_write is not None:
                    authorized_write()
        except sqlite3.IntegrityError as exc:
            consumed = self.conn.execute(
                f"SELECT 1 FROM {_NONCE_TABLE} WHERE nonce_hash=?",
                (approval.nonce_hash,),
            ).fetchone()
            reason = "nonce already consumed" if consumed else "atomic approval transition failed"
            raise reject(reason) from exc


class BoardItemKind(str, Enum):
    RECOMMENDATION = "recommendation"
    ACTION_REQUEST = "action_request"


class BoardMeetingState(str, Enum):
    COLLECTING_PROPOSALS = "collecting_proposals"
    CHALLENGING = "challenging"
    CHALLENGED = "challenged"
    DELIBERATED = "deliberated"
    RECOMMENDED = "recommended"
    OWNER_APPROVED = "owner_approved"
    ACTION_REQUESTED = "action_requested"
    CLOSED = "closed"


@dataclass(frozen=True)
class BoardMeeting:
    meeting_id: str
    title: str
    state: BoardMeetingState
    created_at: str
    consensus: bool | None = None
    dissent: str | None = None
    recommendation_id: str | None = None
    recommendation_payload_hash: str | None = None
    recommendation_evidence_hash: str | None = None
    owner_payload_hash: str | None = None
    owner_approval_id: str | None = None
    executor_id: str | None = None
    action_request_id: str | None = None
    closure_evidence_hash: str | None = None
    closed_at: str | None = None


@dataclass(frozen=True)
class BlindProposal:
    proposal_id: str
    payload_hash: str
    evidence_hash: str
    created_at: str


@dataclass(frozen=True)
class BoardLifecycleEvent:
    event_type: str
    actor_id: str
    payload_hash: str | None
    evidence_hash: str | None
    created_at: str


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


_V2_SCHEMA_COLUMNS = {
    _TABLE: ("canonical_id", "kind", "title", "body", "created_at"),
    _NONCE_TABLE: ("nonce_hash", "approval_id", "consumed_at"),
}
_V3_SCHEMA_COLUMNS = {
    **_V2_SCHEMA_COLUMNS,
    _MEETING_TABLE: (
        "meeting_id", "title", "state", "created_at", "consensus", "dissent",
        "recommendation_id", "recommendation_payload_hash",
        "recommendation_evidence_hash", "owner_payload_hash", "owner_approval_id",
        "executor_id", "action_request_id", "closure_evidence_hash", "closed_at",
    ),
    _PROPOSAL_TABLE: (
        "meeting_id", "proposal_id", "proposer_id", "payload_hash",
        "evidence_hash", "created_at",
    ),
    _CHALLENGE_TABLE: (
        "meeting_id", "challenger_proposal_id", "target_proposal_id",
        "challenge_hash", "evidence_hash", "created_at",
    ),
    _EVENT_TABLE: (
        "event_id", "meeting_id", "event_type", "actor_id", "payload_hash",
        "evidence_hash", "created_at",
    ),
}


def _board_table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name LIKE 'executive_board_%'"
        ).fetchall()
    }


def _validate_schema_shape(
    conn: sqlite3.Connection, expected: Mapping[str, tuple[str, ...]]
) -> None:
    actual_tables = _board_table_names(conn)
    expected_tables = set(expected)
    if actual_tables != expected_tables:
        raise ExecutiveBoardMigrationError(
            "Executive Board table set mismatch: "
            f"expected {sorted(expected_tables)!r}, got {sorted(actual_tables)!r}"
        )
    for table, expected_columns in expected.items():
        actual_columns = tuple(
            row[0]
            for row in conn.execute(
                "SELECT name FROM pragma_table_info(?) ORDER BY cid", (table,)
            ).fetchall()
        )
        if actual_columns != expected_columns:
            raise ExecutiveBoardMigrationError(
                f"Executive Board column mismatch for {table}: "
                f"expected {expected_columns!r}, got {actual_columns!r}"
            )


def migrate(conn: sqlite3.Connection) -> None:
    """Install v3 or upgrade a validated v2 schema without touching foundation data."""
    version_row = conn.execute(
        "SELECT value FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,)
    ).fetchone()
    current_version = None if version_row is None else str(version_row[0])
    if current_version == EXECUTIVE_BOARD_SCHEMA_VERSION:
        _validate_schema_shape(conn, _V3_SCHEMA_COLUMNS)
        return
    if current_version not in (None, "2"):
        raise ExecutiveBoardMigrationError(
            f"unsupported schema version: {current_version!r}"
        )
    if current_version == "2":
        _validate_schema_shape(conn, _V2_SCHEMA_COLUMNS)
    elif _board_table_names(conn):
        raise ExecutiveBoardMigrationError(
            "Executive Board tables exist without schema metadata"
        )
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
            f"""
            CREATE TABLE IF NOT EXISTS {_NONCE_TABLE} (
                nonce_hash TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_MEETING_TABLE} (
                meeting_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN (
                    'collecting_proposals', 'challenging', 'challenged',
                    'deliberated', 'recommended', 'owner_approved',
                    'action_requested', 'closed'
                )),
                created_at TEXT NOT NULL,
                consensus INTEGER CHECK (consensus IN (0, 1)),
                dissent TEXT,
                recommendation_id TEXT,
                recommendation_payload_hash TEXT,
                recommendation_evidence_hash TEXT,
                owner_payload_hash TEXT,
                owner_approval_id TEXT,
                executor_id TEXT,
                action_request_id TEXT,
                closure_evidence_hash TEXT,
                closed_at TEXT
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_PROPOSAL_TABLE} (
                meeting_id TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                proposer_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (meeting_id, proposal_id),
                UNIQUE (meeting_id, proposer_id),
                FOREIGN KEY (meeting_id) REFERENCES {_MEETING_TABLE}(meeting_id)
                    ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_CHALLENGE_TABLE} (
                meeting_id TEXT NOT NULL,
                challenger_proposal_id TEXT NOT NULL,
                target_proposal_id TEXT NOT NULL,
                challenge_hash TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (meeting_id, challenger_proposal_id, target_proposal_id),
                FOREIGN KEY (meeting_id, challenger_proposal_id)
                    REFERENCES {_PROPOSAL_TABLE}(meeting_id, proposal_id),
                FOREIGN KEY (meeting_id, target_proposal_id)
                    REFERENCES {_PROPOSAL_TABLE}(meeting_id, proposal_id),
                CHECK (challenger_proposal_id <> target_proposal_id)
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_EVENT_TABLE} (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                meeting_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload_hash TEXT,
                evidence_hash TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (meeting_id) REFERENCES {_MEETING_TABLE}(meeting_id)
                    ON DELETE CASCADE
            )
            """
        )
        _validate_schema_shape(conn, _V3_SCHEMA_COLUMNS)
        conn.execute(
            "INSERT INTO agents_os_meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_SCHEMA_META_KEY, EXECUTIVE_BOARD_SCHEMA_VERSION),
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


def _require_local_id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _LOCAL_ID.fullmatch(value):
        raise ValueError(f"{field} must contain only letters, digits, '.', '_' or '-'")
    return value


def _require_sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_EVIDENCE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


class ExecutiveBoardLifecycle:
    """Persistent, fail-closed lifecycle for one local Executive Board meeting."""

    def __init__(self, conn: sqlite3.Connection, proof_verifier: Any) -> None:
        self.conn = conn
        self.proof_verifier = proof_verifier
        migrate(conn)

    def _meeting(self, meeting_id: str) -> BoardMeeting:
        _require_local_id(meeting_id, "meeting_id")
        row = self.conn.execute(
            f"SELECT * FROM {_MEETING_TABLE} WHERE meeting_id=?", (meeting_id,)
        ).fetchone()
        if row is None:
            raise InvalidBoardTransition("meeting does not exist")
        return BoardMeeting(
            meeting_id=row["meeting_id"],
            title=row["title"],
            state=BoardMeetingState(row["state"]),
            created_at=row["created_at"],
            consensus=None if row["consensus"] is None else bool(row["consensus"]),
            dissent=row["dissent"],
            recommendation_id=row["recommendation_id"],
            recommendation_payload_hash=row["recommendation_payload_hash"],
            recommendation_evidence_hash=row["recommendation_evidence_hash"],
            owner_payload_hash=row["owner_payload_hash"],
            owner_approval_id=row["owner_approval_id"],
            executor_id=row["executor_id"],
            action_request_id=row["action_request_id"],
            closure_evidence_hash=row["closure_evidence_hash"],
            closed_at=row["closed_at"],
        )

    def _require_state(self, meeting_id: str, *allowed: BoardMeetingState) -> BoardMeeting:
        meeting = self._meeting(meeting_id)
        if meeting.state not in allowed:
            expected = ", ".join(item.value for item in allowed)
            raise InvalidBoardTransition(
                f"meeting state {meeting.state.value!r} does not allow transition; expected {expected}"
            )
        return meeting

    def _event(
        self,
        meeting_id: str,
        event_type: str,
        *,
        actor_id: str,
        created_at: str,
        payload_hash: str | None = None,
        evidence_hash: str | None = None,
    ) -> None:
        self.conn.execute(
            f"INSERT INTO {_EVENT_TABLE} "
            "(meeting_id,event_type,actor_id,payload_hash,evidence_hash,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (meeting_id, event_type, actor_id, payload_hash, evidence_hash, created_at),
        )

    def create_meeting(self, meeting_id: str, title: str, *, created_at: str) -> BoardMeeting:
        _require_local_id(meeting_id, "meeting_id")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("title must not be empty")
        _parse_timestamp(created_at, "created_at")
        try:
            with self.conn:
                self.conn.execute(
                    f"INSERT INTO {_MEETING_TABLE}(meeting_id,title,state,created_at) "
                    "VALUES (?,?,?,?)",
                    (meeting_id, title.strip(), BoardMeetingState.COLLECTING_PROPOSALS.value, created_at),
                )
                self._event(meeting_id, "meeting_created", actor_id="board", created_at=created_at)
        except sqlite3.IntegrityError as exc:
            raise InvalidBoardTransition("meeting already exists") from exc
        return self._meeting(meeting_id)

    def submit_blind_proposal(
        self,
        meeting_id: str,
        *,
        proposal_id: str,
        proposer_id: str,
        payload_hash: str,
        evidence_hash: str,
        created_at: str,
    ) -> BlindProposal:
        self._require_state(meeting_id, BoardMeetingState.COLLECTING_PROPOSALS)
        _require_local_id(proposal_id, "proposal_id")
        _require_local_id(proposer_id, "proposer_id")
        _require_sha256(payload_hash, "payload_hash")
        _require_sha256(evidence_hash, "evidence_hash")
        _parse_timestamp(created_at, "created_at")
        try:
            with self.conn:
                self.conn.execute(
                    f"INSERT INTO {_PROPOSAL_TABLE} "
                    "(meeting_id,proposal_id,proposer_id,payload_hash,evidence_hash,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (meeting_id, proposal_id, proposer_id, payload_hash, evidence_hash, created_at),
                )
                self._event(
                    meeting_id,
                    "blind_proposal_submitted",
                    actor_id="blind",
                    created_at=created_at,
                    payload_hash=payload_hash,
                    evidence_hash=evidence_hash,
                )
        except sqlite3.IntegrityError as exc:
            raise InvalidBoardTransition("proposal id or proposer already used") from exc
        return BlindProposal(proposal_id, payload_hash, evidence_hash, created_at)

    def list_blind_proposals(self, meeting_id: str) -> tuple[BlindProposal, ...]:
        self._meeting(meeting_id)
        rows = self.conn.execute(
            f"SELECT proposal_id,payload_hash,evidence_hash,created_at "
            f"FROM {_PROPOSAL_TABLE} WHERE meeting_id=? ORDER BY proposal_id",
            (meeting_id,),
        ).fetchall()
        return tuple(BlindProposal(*tuple(row)) for row in rows)

    def challenge(
        self,
        meeting_id: str,
        *,
        challenger_proposal_id: str,
        target_proposal_id: str,
        challenge_hash: str,
        evidence_hash: str,
        created_at: str,
    ) -> None:
        self._require_state(
            meeting_id,
            BoardMeetingState.COLLECTING_PROPOSALS,
            BoardMeetingState.CHALLENGING,
        )
        _require_local_id(challenger_proposal_id, "challenger_proposal_id")
        _require_local_id(target_proposal_id, "target_proposal_id")
        if challenger_proposal_id == target_proposal_id:
            raise InvalidBoardTransition("a proposal cannot challenge itself")
        _require_sha256(challenge_hash, "challenge_hash")
        _require_sha256(evidence_hash, "evidence_hash")
        _parse_timestamp(created_at, "created_at")
        proposal_ids = {
            row[0]
            for row in self.conn.execute(
                f"SELECT proposal_id FROM {_PROPOSAL_TABLE} WHERE meeting_id=?",
                (meeting_id,),
            ).fetchall()
        }
        if len(proposal_ids) < 2:
            raise InvalidBoardTransition("at least two blind proposals are required")
        if {challenger_proposal_id, target_proposal_id} - proposal_ids:
            raise InvalidBoardTransition("challenge references an unknown proposal")
        try:
            with self.conn:
                self.conn.execute(
                    f"INSERT INTO {_CHALLENGE_TABLE} "
                    "(meeting_id,challenger_proposal_id,target_proposal_id,challenge_hash,evidence_hash,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (meeting_id, challenger_proposal_id, target_proposal_id, challenge_hash, evidence_hash, created_at),
                )
                self._event(
                    meeting_id,
                    "challenge_recorded",
                    actor_id=challenger_proposal_id,
                    created_at=created_at,
                    payload_hash=challenge_hash,
                    evidence_hash=evidence_hash,
                )
                count = self.conn.execute(
                    f"SELECT COUNT(*) FROM {_CHALLENGE_TABLE} WHERE meeting_id=?",
                    (meeting_id,),
                ).fetchone()[0]
                expected = len(proposal_ids) * (len(proposal_ids) - 1)
                state = BoardMeetingState.CHALLENGED if count == expected else BoardMeetingState.CHALLENGING
                self.conn.execute(
                    f"UPDATE {_MEETING_TABLE} SET state=? WHERE meeting_id=?",
                    (state.value, meeting_id),
                )
        except sqlite3.IntegrityError as exc:
            raise InvalidBoardTransition("challenge direction already recorded") from exc

    def record_deliberation(
        self,
        meeting_id: str,
        *,
        consensus: bool,
        dissent: str | None,
        actor_id: str,
        created_at: str,
    ) -> None:
        meeting = self._meeting(meeting_id)
        if meeting.state is not BoardMeetingState.CHALLENGED:
            raise InvalidBoardTransition("complete bidirectional challenges are required")
        if not isinstance(consensus, bool):
            raise ValueError("consensus must be a boolean")
        if not consensus and (not isinstance(dissent, str) or not dissent.strip()):
            raise InvalidBoardTransition("non-consensus requires documented dissent")
        if consensus and dissent not in (None, ""):
            raise InvalidBoardTransition("consensus cannot carry dissent")
        if not isinstance(actor_id, str) or not actor_id:
            raise ValueError("actor_id must not be empty")
        _parse_timestamp(created_at, "created_at")
        normalized_dissent = None if consensus else str(dissent).strip()
        event_type = "consensus_recorded" if consensus else "dissent_recorded"
        with self.conn:
            self.conn.execute(
                f"UPDATE {_MEETING_TABLE} SET state=?,consensus=?,dissent=? WHERE meeting_id=?",
                (BoardMeetingState.DELIBERATED.value, int(consensus), normalized_dissent, meeting_id),
            )
            self._event(meeting_id, event_type, actor_id=actor_id, created_at=created_at)

    def record_recommendation(
        self,
        meeting_id: str,
        *,
        local_id: str,
        title: str,
        body: str,
        evidence_hash: str,
        created_at: str,
    ) -> BoardItem:
        meeting = self._require_state(meeting_id, BoardMeetingState.DELIBERATED)
        _require_sha256(evidence_hash, "evidence_hash")
        item = BoardItem.create(
            kind=BoardItemKind.RECOMMENDATION,
            local_id=local_id,
            title=title,
            body=body,
            created_at=created_at,
        )
        material = json.dumps(
            {
                "meeting_id": meeting_id,
                "title": item.title,
                "body": item.body,
                "consensus": meeting.consensus,
                "dissent": meeting.dissent,
                "evidence_hash": evidence_hash,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_hash = "sha256:" + hashlib.sha256(material).hexdigest()
        with self.conn:
            self.conn.execute(
                f"INSERT INTO {_TABLE}(canonical_id,kind,title,body,created_at) VALUES(?,?,?,?,?)",
                (item.canonical_id, item.kind.value, item.title, item.body, item.created_at),
            )
            self.conn.execute(
                f"UPDATE {_MEETING_TABLE} SET state=?,recommendation_id=?,"
                "recommendation_payload_hash=?,recommendation_evidence_hash=? WHERE meeting_id=?",
                (
                    BoardMeetingState.RECOMMENDED.value,
                    item.canonical_id,
                    payload_hash,
                    evidence_hash,
                    meeting_id,
                ),
            )
            self._event(
                meeting_id,
                "recommendation_recorded",
                actor_id="board",
                created_at=created_at,
                payload_hash=payload_hash,
                evidence_hash=evidence_hash,
            )
        return item

    def owner_decide(
        self,
        meeting_id: str,
        payload: Mapping[str, Any],
        approval: ApprovalRecord,
        context: ExecutionContext,
        *,
        now: datetime | None = None,
    ) -> None:
        meeting = self._require_state(meeting_id, BoardMeetingState.RECOMMENDED)
        try:
            parameters = payload["normalized_parameters"]
            valid_binding = (
                payload["action_type"] == "executive_board.owner_decision"
                and payload["target"] == meeting_id
                and parameters == {
                    "decision": "approved",
                    "recommendation_payload_hash": meeting.recommendation_payload_hash,
                }
                and payload["evidence_hash"] == meeting.recommendation_evidence_hash
            )
        except (KeyError, TypeError):
            valid_binding = False
        if not valid_binding:
            raise ApprovalRejected("owner decision is not bound to the current recommendation")
        canonical = canonicalize_action_payload(payload)
        checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

        def apply_owner_decision() -> None:
            self.conn.execute(
                f"UPDATE {_MEETING_TABLE} SET state=?,owner_payload_hash=?,owner_approval_id=?,executor_id=? "
                "WHERE meeting_id=?",
                (
                    BoardMeetingState.OWNER_APPROVED.value,
                    canonical.sha256,
                    approval.approval_id,
                    context.executor_id,
                    meeting_id,
                ),
            )
            self._event(
                meeting_id,
                "owner_approved",
                actor_id="goran",
                created_at=checked_at.isoformat(),
                payload_hash=canonical.sha256,
                evidence_hash=payload["evidence_hash"],
            )

        ExecutiveBoardExecutionGate(self.conn, self.proof_verifier).authorize_and_consume(
            payload,
            approval,
            context,
            now=now,
            authorized_write=apply_owner_decision,
        )

    def create_action_request(
        self,
        meeting_id: str,
        *,
        local_id: str,
        title: str,
        body: str,
        created_at: str,
    ) -> BoardItem:
        meeting = self._require_state(meeting_id, BoardMeetingState.OWNER_APPROVED)
        if not meeting.owner_payload_hash or not meeting.owner_approval_id:
            raise InvalidBoardTransition("owner approval evidence is missing")
        item = BoardItem.create(
            kind=BoardItemKind.ACTION_REQUEST,
            local_id=local_id,
            title=title,
            body=body,
            created_at=created_at,
        )
        with self.conn:
            self.conn.execute(
                f"INSERT INTO {_TABLE}(canonical_id,kind,title,body,created_at) VALUES(?,?,?,?,?)",
                (item.canonical_id, item.kind.value, item.title, item.body, item.created_at),
            )
            self.conn.execute(
                f"UPDATE {_MEETING_TABLE} SET state=?,action_request_id=? WHERE meeting_id=?",
                (BoardMeetingState.ACTION_REQUESTED.value, item.canonical_id, meeting_id),
            )
            self._event(
                meeting_id,
                "action_request_created",
                actor_id="goran",
                created_at=created_at,
                payload_hash=meeting.owner_payload_hash,
                evidence_hash=meeting.recommendation_evidence_hash,
            )
        return item

    def close_task(
        self,
        meeting_id: str,
        *,
        actor_id: str,
        evidence_hash: str,
        created_at: str,
    ) -> None:
        meeting = self._require_state(meeting_id, BoardMeetingState.ACTION_REQUESTED)
        if not isinstance(actor_id, str) or not actor_id:
            raise ValueError("actor_id must not be empty")
        if actor_id != meeting.executor_id:
            raise InvalidBoardTransition("task closure requires the approved executor")
        _require_sha256(evidence_hash, "evidence_hash")
        _parse_timestamp(created_at, "created_at")
        with self.conn:
            self.conn.execute(
                f"UPDATE {_MEETING_TABLE} SET state=?,closure_evidence_hash=?,closed_at=? WHERE meeting_id=?",
                (BoardMeetingState.CLOSED.value, evidence_hash, created_at, meeting_id),
            )
            self._event(
                meeting_id,
                "task_closed",
                actor_id=actor_id,
                created_at=created_at,
                evidence_hash=evidence_hash,
            )

    def get_meeting(self, meeting_id: str) -> BoardMeeting:
        return self._meeting(meeting_id)

    def list_events(self, meeting_id: str) -> tuple[BoardLifecycleEvent, ...]:
        self._meeting(meeting_id)
        rows = self.conn.execute(
            f"SELECT event_type,actor_id,payload_hash,evidence_hash,created_at "
            f"FROM {_EVENT_TABLE} WHERE meeting_id=? ORDER BY event_id",
            (meeting_id,),
        ).fetchall()
        return tuple(BoardLifecycleEvent(*tuple(row)) for row in rows)


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
        tables=_OWNED_TABLES,
        meta_keys=(_SCHEMA_META_KEY,),
        present_tables=tuple(
            table
            for table in _OWNED_TABLES
            if conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
        ),
        present_meta_keys=(_SCHEMA_META_KEY,) if meta_present else (),
    )


def rollback(conn: sqlite3.Connection) -> None:
    """Idempotently remove only schema and metadata owned by this slice."""
    with conn:
        for table in _OWNED_TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        meta_table_present = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agents_os_meta'"
        ).fetchone()
        if meta_table_present:
            conn.execute("DELETE FROM agents_os_meta WHERE key=?", (_SCHEMA_META_KEY,))
