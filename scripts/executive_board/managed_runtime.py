#!/usr/bin/env python3
"""Fail-closed lifecycle controller for one loopback Executive Board process."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class RuntimeControllerError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeReceipt:
    pid: int
    process_start_ticks: int
    executable: str
    host: str
    port: int
    listener_inode: int


@dataclass(frozen=True, order=True)
class Listener:
    family: str
    address: str
    port: int
    inode: int


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.1)
        return probe.connect_ex((host, port)) == 0


def _process_start_ticks(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        _prefix, separator, suffix = text.rpartition(")")
        if not separator:
            raise ValueError("malformed proc stat")
        return int(suffix.split()[19])
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeControllerError("process identity is unavailable") from exc


def _process_executable(pid: int) -> str:
    try:
        return str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except OSError as exc:
        raise RuntimeControllerError("process executable is unavailable") from exc


def _listener_inode(host: str, port: int) -> int:
    if host != "127.0.0.1":
        raise RuntimeControllerError("managed runtime requires IPv4 loopback")
    expected_address = "0100007F"
    expected_port = f"{port:04X}"
    try:
        lines = Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        raise RuntimeControllerError("listener table is unavailable") from exc
    for line in lines:
        fields = line.split()
        address, raw_port = fields[1].split(":", 1)
        if address == expected_address and raw_port == expected_port and fields[3] == "0A":
            return int(fields[9])
    raise RuntimeControllerError("expected loopback listener is not present")


def _pid_owns_socket(pid: int, inode: int) -> bool:
    fd_root = Path(f"/proc/{pid}/fd")
    try:
        for descriptor in fd_root.iterdir():
            try:
                if os.readlink(descriptor) == f"socket:[{inode}]":
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def _listener_table() -> set[Listener]:
    listeners: set[Listener] = set()
    for family, table in (
        ("ipv4", Path("/proc/net/tcp")),
        ("ipv6", Path("/proc/net/tcp6")),
    ):
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError as exc:
            raise RuntimeControllerError("listener table is unavailable") from exc
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            address, raw_port = fields[1].split(":", 1)
            listeners.add(
                Listener(
                    family=family,
                    address=address,
                    port=int(raw_port, 16),
                    inode=int(fields[9]),
                )
            )
    return listeners


def _owned_socket_inodes(pid: int) -> set[int]:
    inodes: set[int] = set()
    try:
        descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError as exc:
        raise RuntimeControllerError("process socket descriptors are unavailable") from exc
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            try:
                inodes.add(int(target[8:-1]))
            except ValueError:
                continue
    return inodes


def _stable_owned_listeners(pid: int) -> set[Listener]:
    """Take two identity-stable snapshots to close startup inspection races."""
    for _attempt in range(5):
        start_before = _process_start_ticks(pid)
        first_inodes = _owned_socket_inodes(pid)
        first = {
            listener
            for listener in _listener_table()
            if listener.inode in first_inodes
        }
        time.sleep(0.01)
        second_inodes = _owned_socket_inodes(pid)
        second = {
            listener
            for listener in _listener_table()
            if listener.inode in second_inodes
        }
        start_after = _process_start_ticks(pid)
        if start_before == start_after and first == second:
            return second
    raise RuntimeControllerError("listener attribution raced process startup")


def _assert_exact_listener_set(pid: int, host: str, port: int) -> Listener:
    if host != "127.0.0.1":
        raise RuntimeControllerError("managed runtime requires IPv4 loopback")
    listeners = _stable_owned_listeners(pid)
    expected = [
        listener
        for listener in listeners
        if listener.family == "ipv4"
        and listener.address == "0100007F"
        and listener.port == port
    ]
    if len(expected) != 1 or len(listeners) != 1:
        details = ",".join(
            f"{item.family}:{item.address}:{item.port}:{item.inode}"
            for item in sorted(listeners)
        )
        raise RuntimeControllerError(
            "managed PID has unexpected, wildcard, IPv6, inherited, or "
            f"additional listeners: {details}"
        )
    return expected[0]


class ManagedRuntimeController:
    """Start, attribute, health-check and stop exactly one owned process."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        command: Sequence[str],
        expected_executable: Path,
        cwd: Path | str = "/tmp",
        env: Mapping[str, str] | None = None,
        startup_timeout: float = 5.0,
    ) -> None:
        if host != "127.0.0.1":
            raise RuntimeControllerError("managed runtime must bind loopback-only")
        if not (1024 <= port <= 65535):
            raise RuntimeControllerError("invalid managed runtime port")
        if not command:
            raise RuntimeControllerError("managed runtime command is empty")
        self.host = host
        self.port = port
        self.command = tuple(str(part) for part in command)
        self.expected_executable = str(expected_executable.resolve())
        self.cwd = str(cwd)
        self.env = dict(env) if env is not None else None
        self.startup_timeout = startup_timeout
        self._process: subprocess.Popen[str] | None = None

    def _force_stop(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def _assert_identity(self, receipt: RuntimeReceipt) -> None:
        if self._process is None or self._process.pid != receipt.pid:
            raise RuntimeControllerError("runtime process ownership mismatch")
        if self._process.poll() is not None:
            raise RuntimeControllerError("managed runtime process is not running")
        if _process_start_ticks(receipt.pid) != receipt.process_start_ticks:
            raise RuntimeControllerError("runtime PID start-time mismatch")
        if _process_executable(receipt.pid) != receipt.executable:
            raise RuntimeControllerError("runtime executable identity mismatch")
        listener = _assert_exact_listener_set(
            receipt.pid, receipt.host, receipt.port
        )
        inode = listener.inode
        if inode != receipt.listener_inode or not _pid_owns_socket(receipt.pid, inode):
            raise RuntimeControllerError("runtime listener attribution mismatch")

    def start(self) -> RuntimeReceipt:
        if self._process is not None:
            raise RuntimeControllerError("managed runtime controller is single-use")
        if _port_open(self.host, self.port):
            raise RuntimeControllerError("managed runtime port is occupied")
        try:
            self._process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.env,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RuntimeControllerError(f"managed runtime start failed: {exc}") from exc
        try:
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise RuntimeControllerError(
                        "managed runtime exited before listener attribution"
                    )
                if _port_open(self.host, self.port):
                    executable = _process_executable(self._process.pid)
                    if executable != self.expected_executable:
                        raise RuntimeControllerError("managed runtime executable mismatch")
                    listener = _assert_exact_listener_set(
                        self._process.pid, self.host, self.port
                    )
                    inode = listener.inode
                    if not _pid_owns_socket(self._process.pid, inode):
                        raise RuntimeControllerError("listener is not owned by managed PID")
                    return RuntimeReceipt(
                        pid=self._process.pid,
                        process_start_ticks=_process_start_ticks(self._process.pid),
                        executable=executable,
                        host=self.host,
                        port=self.port,
                        listener_inode=inode,
                    )
                time.sleep(0.02)
            raise RuntimeControllerError("managed runtime listener startup timed out")
        except BaseException:
            self._force_stop()
            raise

    def health(
        self, receipt: RuntimeReceipt, *, timeout_seconds: float = 5.0
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self._assert_identity(receipt)
            try:
                with urllib.request.urlopen(
                    f"http://{receipt.host}:{receipt.port}/health", timeout=0.5
                ) as response:
                    payload = json.loads(response.read())
                if response.status == 200 and payload.get("status") == "ok":
                    return {
                        "status": "ok",
                        "http_status": 200,
                        "pid": receipt.pid,
                        "listener_attributed": True,
                    }
            except (OSError, json.JSONDecodeError):
                time.sleep(0.02)
        raise RuntimeControllerError("managed runtime health check timed out")

    def shutdown(self, receipt: RuntimeReceipt) -> dict[str, Any]:
        if self._process is not None and self._process.pid == receipt.pid and self._process.poll() is not None:
            if _port_open(receipt.host, receipt.port):
                raise RuntimeControllerError("listener exists after owned process stopped")
            return {
                "pid": receipt.pid,
                "stopped": True,
                "listener_closed": True,
                "already_stopped": True,
            }
        self._assert_identity(receipt)
        self._force_stop()
        if _port_open(receipt.host, receipt.port):
            raise RuntimeControllerError("managed runtime listener survived shutdown")
        return {
            "pid": receipt.pid,
            "stopped": True,
            "listener_closed": True,
            "already_stopped": False,
        }
