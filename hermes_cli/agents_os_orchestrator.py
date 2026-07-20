"""Background local execution with an atomic terminal projection."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from hermes_cli.agents_os import AgentsOSPaths, connect, log_event, utc_now
from hermes_cli.agents_os_commands import (
    complete_command,
    ensure_schema as ensure_command_schema,
    get_command,
    mark_running,
)
from hermes_cli.agents_os_execution import RuntimeAdapterRegistry, execute_invocation
from hermes_cli.agents_os_memory import (
    create_memory_candidate,
    create_memory_object,
    ensure_memory_schema,
)


TERMINAL_STATUSES = {"succeeded", "failed", "timed_out"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS runtime_executions (
    run_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL,
    runtime TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('queued','running','succeeded','failed','timed_out')),
    cwd TEXT NOT NULL,
    evidence_argv TEXT NOT NULL DEFAULT '[]',
    exit_code INTEGER,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);
"""


def ensure_execution_schema(conn: sqlite3.Connection) -> None:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_executions'"
    ).fetchone()
    if not exists:
        conn.executescript(SCHEMA)


def execution_projection(conn: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
    ensure_execution_schema(conn)
    row = conn.execute("SELECT * FROM runtime_executions WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["evidence_argv"] = json.loads(item["evidence_argv"])
    return item


class ExecutionCoordinator:
    def __init__(
        self,
        paths: AgentsOSPaths,
        *,
        allowed_cwds: list[Path] | tuple[Path, ...],
        registry: RuntimeAdapterRegistry,
        before_terminal_projection: Callable[[], None] | None = None,
    ) -> None:
        self.paths = paths
        self.allowed_cwds = tuple(path.resolve() for path in allowed_cwds)
        self.registry = registry
        self.before_terminal_projection = before_terminal_projection

    def queue(
        self,
        *,
        command_id: str,
        runtime: str,
        cwd: Path,
        approved_model_call: bool,
        timeout_seconds: float = 300,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Local process consent only. This is deliberately not owner authentication.
        if not approved_model_call:
            raise PermissionError("local process execution requires explicit consent")
        resolved_cwd = cwd.resolve(strict=True)
        if resolved_cwd not in self.allowed_cwds:
            raise ValueError("cwd is not allowlisted")
        adapter = self.registry.get(runtime)
        probe = adapter.probe()
        if not probe.available:
            raise RuntimeError(probe.reason or "runtime unavailable")
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        with connect(self.paths) as conn:
            ensure_command_schema(conn)
            ensure_memory_schema(conn)
            ensure_execution_schema(conn)
            command = get_command(conn, command_id)
            if command["state"] != "queued":
                raise ValueError("command must be queued")
            metadata = command["metadata"] or {}
            now = utc_now()
            conn.execute(
                "INSERT INTO runs(id,task_id,workflow,status,input,created_at) VALUES(?,?,?,?,?,?)",
                (run_id, metadata.get("task_id"), metadata.get("workflow", "local"), "queued", command["transcript"], now),
            )
            conn.execute(
                "INSERT INTO runtime_executions(run_id,command_id,runtime,status,cwd,created_at) VALUES(?,?,?,?,?,?)",
                (run_id, command_id, runtime, "queued", str(resolved_cwd), now),
            )
            log_event(conn, "execution_queued", task_id=metadata.get("task_id"), run_id=run_id)
        thread = threading.Thread(
            target=self._run,
            kwargs=dict(run_id=run_id, command_id=command_id, runtime=runtime, cwd=resolved_cwd,
                        timeout_seconds=timeout_seconds, options=dict(options or {})),
            daemon=True,
            name=f"agents-os-{run_id}",
        )
        thread.start()
        return {"run_id": run_id, "status": "queued"}

    def _run(
        self,
        *,
        run_id: str,
        command_id: str,
        runtime: str,
        cwd: Path,
        timeout_seconds: float,
        options: dict[str, Any],
    ) -> None:
        command: dict[str, Any] | None = None
        try:
            with connect(self.paths) as conn:
                command = get_command(conn, command_id)
                command = mark_running(conn, command_id, expected_version=command["version"], run_id=run_id)
                now = utc_now()
                conn.execute("UPDATE runs SET status='running' WHERE id=?", (run_id,))
                conn.execute("UPDATE runtime_executions SET status='running',started_at=? WHERE run_id=?", (now, run_id))
                task_id = (command["metadata"] or {}).get("task_id")
                if task_id:
                    conn.execute("UPDATE tasks SET status='in_progress',updated_at=? WHERE id=?", (now, task_id))
            invocation = self.registry.get(runtime).build_invocation(
                prompt=command["transcript"], cwd=cwd, **options
            )
            result = execute_invocation(invocation, timeout_seconds=timeout_seconds)
            status = "timed_out" if result.timed_out else "succeeded" if result.succeeded else "failed"
            text = result.stdout.decode("utf-8", errors="replace")
            error = result.stderr.decode("utf-8", errors="replace")
            self._finish(
                run_id=run_id, command_id=command_id, runtime=runtime, status=status,
                result_text=text, error_text=error, exit_code=result.returncode,
                evidence_argv=invocation.evidence_argv,
            )
        except Exception as exc:
            self._finish(
                run_id=run_id, command_id=command_id, runtime=runtime, status="failed",
                result_text="", error_text=f"{type(exc).__name__}: {exc}", exit_code=None,
                evidence_argv=(),
            )

    def _finish(
        self,
        *,
        run_id: str,
        command_id: str,
        runtime: str,
        status: str,
        result_text: str,
        error_text: str,
        exit_code: int | None,
        evidence_argv: tuple[str, ...],
    ) -> None:
        with connect(self.paths) as conn:
            ensure_command_schema(conn)
            ensure_memory_schema(conn)
            ensure_execution_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            command = get_command(conn, command_id)
            metadata = command["metadata"] or {}
            task_id = metadata.get("task_id")
            profile_id = str(metadata.get("profile_id") or "local")
            succeeded = status == "succeeded"
            if command["state"] == "queued":
                command = mark_running(conn, command_id, expected_version=command["version"], run_id=run_id)
            if command["state"] == "running":
                complete_command(
                    conn, command_id, expected_version=command["version"], succeeded=succeeded,
                    result={"text": result_text, "run_id": run_id} if succeeded else None,
                    error=None if succeeded else {"message": error_text, "status": status},
                )
            now = utc_now()
            conn.execute(
                "UPDATE runs SET status=?,completed_at=? WHERE id=?",
                ("succeeded" if succeeded else "failed", now, run_id),
            )
            if succeeded:
                create_memory_object(
                    conn, title=f"Result {run_id}", body_text=result_text, profile_id=profile_id,
                    task_id=task_id or command_id, run_id=run_id, producer_runtime=runtime,
                )
            else:
                create_memory_candidate(
                    conn, result_text=error_text or result_text or status, profile_id=profile_id,
                    task_id=task_id, run_id=run_id, producer_runtime=runtime,
                )
            if task_id:
                conn.execute(
                    "UPDATE tasks SET status=?,updated_at=? WHERE id=?",
                    ("review" if succeeded else "blocked", now, task_id),
                )
            log_event(
                conn, "execution_completed", task_id=task_id, run_id=run_id,
                payload={"status": status, "exit_code": exit_code},
            )
            if self.before_terminal_projection is not None:
                self.before_terminal_projection()
            # Load-bearing ordering: this must remain the final write before commit.
            conn.execute(
                """UPDATE runtime_executions
                   SET status=?,evidence_argv=?,exit_code=?,error=?,completed_at=? WHERE run_id=?""",
                (status, json.dumps(evidence_argv), exit_code, error_text or None, now, run_id),
            )
            conn.commit()
