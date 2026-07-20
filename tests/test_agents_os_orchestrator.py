from __future__ import annotations

import sys
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from hermes_cli.agents_os import connect, utc_now
from hermes_cli.agents_os_commands import confirm_command, create_command, get_command
from hermes_cli.agents_os_execution import (
    ProbeResult,
    RuntimeAdapterRegistry,
    RuntimeInvocation,
)
from hermes_cli.agents_os_memory import search_memory
from hermes_cli.agents_os_orchestrator import ExecutionCoordinator, execution_projection


class LocalProcessAdapter:
    name = "local-test"

    def __init__(self, *, mode: str) -> None:
        self.mode = mode

    def probe(self) -> ProbeResult:
        return ProbeResult(self.name, True, executable=sys.executable)

    def build_invocation(self, *, prompt: str, cwd: Path, **options: object) -> RuntimeInvocation:
        if self.mode == "exception":
            raise RuntimeError("adapter exploded")
        returncode = 7 if self.mode == "nonzero" else 0
        script = f"import sys; print({prompt!r}); sys.exit({returncode})"
        argv = (sys.executable, "-c", script)
        return RuntimeInvocation(self.name, argv, cwd, b"", argv)


def _coordinator(
    tmp_path: Path,
    mode: str,
    *,
    before_terminal_projection=None,
) -> ExecutionCoordinator:
    paths_home = tmp_path / "home"
    paths_home.mkdir()
    from hermes_cli.agents_os import resolve_paths

    paths = resolve_paths(home=paths_home)
    registry = RuntimeAdapterRegistry([LocalProcessAdapter(mode=mode)])
    return ExecutionCoordinator(
        paths,
        allowed_cwds=[tmp_path],
        registry=registry,
        before_terminal_projection=before_terminal_projection,
    )


def _queue(coordinator: ExecutionCoordinator, tmp_path: Path, *, marker: str) -> tuple[str, str, str]:
    task_id = f"task-{marker}"
    with connect(coordinator.paths) as conn:
        now = utc_now()
        conn.execute(
            "INSERT INTO tasks(id,title,status,created_at,updated_at) VALUES(?,?,?,?,?)",
            (task_id, marker, "ready", now, now),
        )
        command = create_command(
            conn,
            transcript=marker,
            idempotency_key=marker,
            metadata={"task_id": task_id, "profile_id": "test", "workflow": "test"},
        )
        command = confirm_command(conn, command["id"], expected_version=command["version"])
    projection = coordinator.queue(
        command_id=command["id"],
        runtime="local-test",
        cwd=tmp_path,
        approved_model_call=True,
        timeout_seconds=2,
    )
    return task_id, command["id"], projection["run_id"]


def _wait_for_terminal(coordinator: ExecutionCoordinator, run_id: str) -> str:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with connect(coordinator.paths) as conn:
            status = execution_projection(conn, run_id)["status"]
        if status in {"succeeded", "failed", "timed_out"}:
            return status
    pytest.fail("execution did not reach a terminal state")


def test_success_terminal_projection_is_atomic_and_memory_is_immediately_searchable(tmp_path: Path) -> None:
    finalizing = threading.Event()
    release_terminal_projection = threading.Event()

    def hold_before_terminal_projection() -> None:
        finalizing.set()
        if not release_terminal_projection.wait(timeout=3):
            raise TimeoutError("test did not release terminal projection")

    coordinator = _coordinator(
        tmp_path,
        "success",
        before_terminal_projection=hold_before_terminal_projection,
    )
    task_id, command_id, run_id = _queue(
        coordinator, tmp_path, marker="jarvis-memory-atomic"
    )

    assert finalizing.wait(timeout=3), "execution did not reach finalization barrier"
    try:
        # Use a read-only observer connection. ``connect`` intentionally runs
        # schema initialization and therefore needs a writer lock.
        with sqlite3.connect(coordinator.paths.db) as conn:
            conn.row_factory = sqlite3.Row
            # All success-side writes exist only inside the worker transaction;
            # observers must still see the previous non-terminal projection.
            assert execution_projection(conn, run_id)["status"] == "running"
            assert search_memory(
                conn, "jarvis", profile_id="test", scopes=["task"], task_id=task_id
            ) == []
    finally:
        release_terminal_projection.set()

    assert _wait_for_terminal(coordinator, run_id) == "succeeded"

    with connect(coordinator.paths) as conn:
        conn.execute("BEGIN")
        projection = execution_projection(conn, run_id)
        command = get_command(conn, command_id)
        run = conn.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
        memories = search_memory(
            conn, "jarvis", profile_id="test", scopes=["task"], task_id=task_id
        )
        assert projection["status"] == "succeeded"
        assert command["state"] == "succeeded"
        assert run["status"] == "succeeded"
        assert len(memories) == 1
        assert memories[0]["run_id"] == run_id


@pytest.mark.parametrize("mode", ["nonzero", "exception"])
def test_failed_execution_never_leaves_command_running(tmp_path: Path, mode: str) -> None:
    coordinator = _coordinator(tmp_path, mode)
    task_id, command_id, run_id = _queue(coordinator, tmp_path, marker=f"failure-{mode}")

    assert _wait_for_terminal(coordinator, run_id) == "failed"

    with connect(coordinator.paths) as conn:
        conn.execute("BEGIN")
        projection = execution_projection(conn, run_id)
        command = get_command(conn, command_id)
        run = conn.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
        candidate = conn.execute(
            "SELECT state FROM memory_candidates WHERE run_id=? AND task_id=?", (run_id, task_id)
        ).fetchone()
        assert projection["status"] == "failed"
        assert command["state"] == "failed"
        assert run["status"] == "failed"
        assert candidate["state"] == "candidate"
