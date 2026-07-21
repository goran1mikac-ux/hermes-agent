#!/usr/bin/env python3
"""Verify source/wheel/installed parity for Executive Board modules."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import sys
import zipfile
from pathlib import Path

MODULES = (
    "agents_os",
    "agents_os_commands",
    "agents_os_execution",
    "agents_os_executive_board",
    "agents_os_memory",
    "agents_os_orchestrator",
    "agents_os_web",
)


def sha(path_or_bytes: Path | bytes) -> str:
    data = path_or_bytes if isinstance(path_or_bytes, bytes) else path_or_bytes.read_bytes()
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--wheel", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    rows = []
    failures = []
    with zipfile.ZipFile(args.wheel) as archive:
        for name in MODULES:
            relative = f"hermes_cli/{name}.py"
            source = args.repo / relative
            wheel_hash = sha(archive.read(relative))
            module = importlib.import_module(f"hermes_cli.{name}")
            installed = Path(module.__file__).resolve()
            row = {
                "module": name,
                "source_sha256": sha(source),
                "wheel_sha256": wheel_hash,
                "installed_sha256": sha(installed),
                "installed_origin": str(installed),
            }
            if len({row["source_sha256"], row["wheel_sha256"], row["installed_sha256"]}) != 1:
                failures.append(f"hash:{name}")
            if str(args.repo.resolve()) in str(installed):
                failures.append(f"source-shadow:{name}")
            rows.append(row)

    version = importlib.metadata.version("hermes-agent")
    if version != "0.19.0":
        failures.append(f"version:{version}")
    repo_on_sys_path = any(str(args.repo.resolve()) == str(Path(item).resolve()) for item in sys.path if item)
    if repo_on_sys_path:
        failures.append("repo-on-sys-path")
    report = {
        "version": version,
        "python": sys.version,
        "executable": sys.executable,
        "repo_on_sys_path": repo_on_sys_path,
        "modules": rows,
        "failures": failures,
        "pass": not failures,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
