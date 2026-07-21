#!/usr/bin/env python3
"""Audit Executive Board overlay wheel against the official baseline."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

ALLOWED_DELTA = {
    "hermes_cli/agents_os.py",
    "hermes_cli/agents_os_commands.py",
    "hermes_cli/agents_os_execution.py",
    "hermes_cli/agents_os_executive_board.py",
    "hermes_cli/agents_os_memory.py",
    "hermes_cli/agents_os_orchestrator.py",
    "hermes_cli/agents_os_web.py",
    "hermes_agent-0.19.0.dist-info/RECORD",
}
RECORD = "hermes_agent-0.19.0.dist-info/RECORD"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def verify_record(files: dict[str, bytes]) -> tuple[int, list[str]]:
    failures: list[str] = []
    rows = csv.reader(io.StringIO(files[RECORD].decode("utf-8")))
    checked = 0
    for name, encoded, size in rows:
        if name == RECORD:
            if encoded or size:
                failures.append(f"record-self-entry-not-empty:{name}")
            continue
        if name not in files:
            failures.append(f"missing:{name}")
            continue
        data = files[name]
        checked += 1
        if size != str(len(data)):
            failures.append(f"size:{name}")
        algo, value = encoded.split("=", 1)
        if algo != "sha256":
            failures.append(f"algorithm:{name}:{algo}")
            continue
        actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if value != actual:
            failures.append(f"digest:{name}")
    return checked, failures


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    baseline = load(args.baseline)
    candidate = load(args.candidate)
    added = sorted(set(candidate) - set(baseline))
    removed = sorted(set(baseline) - set(candidate))
    changed = sorted(name for name in set(candidate) & set(baseline) if baseline[name] != candidate[name])
    delta = set(added) | set(removed) | set(changed)
    checked, record_failures = verify_record(candidate)
    forbidden_delta = sorted(
        name for name in delta
        if any(term in name.lower() for term in ("agents_os_tui", "jarvis", "voice", "stt", "tts", "seo", "idea_factory", "openclaw", "/nul"))
    )
    unexpected = sorted(delta - ALLOWED_DELTA)
    report = {
        "baseline_sha256": digest(args.baseline.read_bytes()),
        "candidate_sha256": digest(args.candidate.read_bytes()),
        "baseline_entries": len(baseline),
        "candidate_entries": len(candidate),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unexpected_delta": unexpected,
        "forbidden_delta": forbidden_delta,
        "record_checked": checked,
        "record_failures": record_failures,
        "pass": not removed and not unexpected and not forbidden_delta and not record_failures,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
