"""Small runtime registry and bounded local subprocess runner."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Protocol


@dataclass(frozen=True)
class ProbeResult:
    runtime: str
    available: bool
    executable: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RuntimeInvocation:
    runtime: str
    argv: tuple[str, ...]
    cwd: Path
    stdin: bytes
    evidence_argv: tuple[str, ...]
    environment: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionResult:
    runtime: str
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    command_evidence: tuple[str, ...]

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.returncode == 0


class RuntimeAdapter(Protocol):
    name: str

    def probe(self) -> ProbeResult: ...
    def build_invocation(self, *, prompt: str, cwd: Path, **options: object) -> RuntimeInvocation: ...


class RuntimeAdapterRegistry:
    def __init__(self, adapters: Iterable[RuntimeAdapter] = ()) -> None:
        self._adapters = {adapter.name: adapter for adapter in adapters}

    def get(self, name: str) -> RuntimeAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise KeyError(f"unknown runtime: {name}") from exc


def execute_invocation(
    invocation: RuntimeInvocation,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int = 1_000_000,
    max_stderr_bytes: int = 250_000,
) -> ExecutionResult:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    started = time.monotonic()
    try:
        completed = subprocess.run(
            invocation.argv, cwd=invocation.cwd, input=invocation.stdin,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds,
            check=False, env=dict(invocation.environment) or None,
        )
        stdout, stderr, returncode, timed_out = completed.stdout, completed.stderr, completed.returncode, False
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, returncode, timed_out = exc.stdout or b"", exc.stderr or b"", -1, True
    return ExecutionResult(
        invocation.runtime, returncode, stdout[:max_stdout_bytes], stderr[:max_stderr_bytes],
        time.monotonic() - started, timed_out, len(stdout) > max_stdout_bytes,
        len(stderr) > max_stderr_bytes, invocation.evidence_argv,
    )
