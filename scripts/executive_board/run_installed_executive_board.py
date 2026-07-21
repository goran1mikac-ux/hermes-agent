#!/usr/bin/env python3
"""Verify and optionally launch installed Executive Board without source shadowing."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import ipaddress
import json
from pathlib import Path
from wsgiref.simple_server import make_server

EXPECTED_VERSION = "0.19.0"
MODULES = (
    "hermes_cli.agents_os",
    "hermes_cli.agents_os_commands",
    "hermes_cli.agents_os_execution",
    "hermes_cli.agents_os_executive_board",
    "hermes_cli.agents_os_memory",
    "hermes_cli.agents_os_orchestrator",
    "hermes_cli.agents_os_web",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18791)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    if not ipaddress.ip_address(args.host).is_loopback:
        raise SystemExit("refusing non-loopback bind")
    if not 1 <= args.port <= 65535:
        raise SystemExit("invalid port")
    if importlib.metadata.version("hermes-agent") != EXPECTED_VERSION:
        raise SystemExit("installed package version mismatch")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if digest(args.wheel) != manifest["wheel"]["sha256"]:
        raise SystemExit("wheel hash mismatch")
    for name in MODULES:
        module = importlib.import_module(name)
        origin = Path(module.__file__).resolve()
        if "site-packages" not in origin.parts:
            raise SystemExit(f"source shadowing detected for {name}: {origin}")
        expected = manifest["modules"][name]["sha256"]
        if digest(origin) != expected:
            raise SystemExit(f"installed module hash mismatch: {name}")

    if args.verify_only:
        print("EXECUTIVE_BOARD_0_19_0_LAUNCHER_VERIFICATION=PASS")
        return

    root = args.root.resolve()
    db_path = root / "state.sqlite"
    if not db_path.is_file():
        raise SystemExit(f"database does not exist: {db_path}")
    from hermes_cli.agents_os import AgentsOSPaths
    from hermes_cli.agents_os_web import create_app

    paths = AgentsOSPaths(root.parent, root, db_path, root / "artifacts", root / "outbox")
    app = create_app(paths)
    with make_server(args.host, args.port, app) as server:
        print(f"Executive Board listening on http://{args.host}:{args.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
