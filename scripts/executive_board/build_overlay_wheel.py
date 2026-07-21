#!/usr/bin/env python3
"""Build a deterministic Executive Board overlay wheel from official Hermes 0.19.0."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

BASELINE_SHA256 = "bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f"
DIST_INFO = "hermes_agent-0.19.0.dist-info"
OVERLAY_MODULES = (
    "hermes_cli/agents_os.py",
    "hermes_cli/agents_os_commands.py",
    "hermes_cli/agents_os_execution.py",
    "hermes_cli/agents_os_executive_board.py",
    "hermes_cli/agents_os_memory.py",
    "hermes_cli/agents_os_orchestrator.py",
    "hermes_cli/agents_os_web.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_digest(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={digest}"


def fixed_zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()

    baseline_bytes = args.baseline.read_bytes()
    if sha256(baseline_bytes) != BASELINE_SHA256:
        raise SystemExit("baseline wheel hash mismatch")
    commit = subprocess.check_output(
        ["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != args.expected_commit:
        raise SystemExit(f"source commit mismatch: {commit}")

    record_name = f"{DIST_INFO}/RECORD"
    with zipfile.ZipFile(io.BytesIO(baseline_bytes), "r") as archive:
        payloads = {name: archive.read(name) for name in archive.namelist() if name != record_name}
        modes = {name: archive.getinfo(name).external_attr for name in archive.namelist()}

    for relative in OVERLAY_MODULES:
        source = args.repo / relative
        payloads[relative] = source.read_bytes()
        modes[relative] = 0o100644 << 16

    rows: list[tuple[str, str, str]] = []
    for name in sorted(payloads):
        data = payloads[name]
        rows.append((name, record_digest(data), str(len(data))))
    rows.append((record_name, "", ""))
    buffer = io.StringIO(newline="")
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    payloads[record_name] = buffer.getvalue().encode("utf-8")
    modes[record_name] = 0o100644 << 16

    args.output.parent.mkdir(parents=True, exist_ok=True)
    timestamp = fixed_zip_time(args.source_date_epoch)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(payloads):
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = modes.get(name, 0o100644 << 16)
            archive.writestr(info, payloads[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    print(f"output={args.output}")
    print(f"sha256={sha256(args.output.read_bytes())}")
    print(f"entries={len(payloads)}")


if __name__ == "__main__":
    main()
