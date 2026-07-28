from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from scripts.executive_board.deploy_driver import DeployMode
from scripts.executive_board.deploy_driver_p2 import (
    P1_PLAN_HASH,
    P2DeploymentDriver,
    P2DeployPlan,
    P2RealBackend,
    create_p2_approval,
)
from scripts.executive_board.release_isolation import ReleaseRunGuard, ReleaseRunSpec
from scripts.executive_board.release_provenance import (
    TrustedEd25519PublicKey,
    build_root_manifest,
    key_id_for_public_key,
    public_key_bytes_from_private,
    sign_root_manifest,
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def sqlite_clone(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def _execute(args: argparse.Namespace) -> int:
    release = args.release.resolve()
    simulation = args.run_root.resolve()
    source = release / "source-artifacts"
    rollback_reference = simulation / "rollback-reference.sqlite"
    database = simulation / "home/agents_os/state.sqlite"
    checkpoints = simulation / "checkpoints"
    target_venv = args.venv.resolve()
    if checkpoints.exists():
        shutil.rmtree(checkpoints)
    if target_venv.exists():
        shutil.rmtree(target_venv)
    if database.exists():
        database.unlink()
    sqlite_clone(rollback_reference, database)

    wheel = release / "hermes_agent-0.19.0-py3-none-any.whl"
    manifest = release / "manifest.json"
    runbook = release / "P2-PRODUCTION-RUNBOOK.md"
    driver = source / "deploy_driver_p2.py"
    adapter = source / "canonical_adapter.py"
    launcher = source / "p2_installed_launcher.py"
    lock = release / "offline/requirements-p2.lock"
    wheelhouse_manifest = release / "offline/wheelhouse-manifest.json"
    port = free_port()
    if port == 18791:
        raise RuntimeError("simulation selected forbidden production port")

    plan_path = simulation / "P2-SIMULATION-PLAN.json"
    plan_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "isolated-installed-simulation",
                "production_deploy_executed": False,
                "run_id": args.run_id,
                "technical_owner": "codex",
                "ownership_token_sha256": os.environ["P2_RUN_OWNERSHIP_TOKEN_SHA256"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    artifact_hashes = {
        "wheel.whl": sha(wheel),
        "manifest.json": sha(manifest),
        "release-plan.json": sha(plan_path),
        "runbook.md": sha(runbook),
        "p2-driver.py": sha(driver),
        "dependency.lock": sha(lock),
        "canonical-adapter.py": sha(adapter),
        "installed-launcher.py": sha(launcher),
        "rollback.sqlite": sha(rollback_reference),
        "wheelhouse-manifest.json": sha(wheelhouse_manifest),
    }
    wheelhouse_index = json.loads(wheelhouse_manifest.read_text(encoding="utf-8"))
    artifact_hashes.update(
        {
            f"wheelhouse/{name}": digest
            for name, digest in wheelhouse_index["files"].items()
        }
    )
    simulation_signing_key = os.urandom(32)
    simulation_public_key = public_key_bytes_from_private(simulation_signing_key)
    root_document = build_root_manifest(
        artifact_hashes, simulation_public_key, trust_domain="simulation"
    )
    root_bytes, signature_bytes = sign_root_manifest(
        root_document, simulation_signing_key
    )
    root_manifest = simulation / "ROOT-MANIFEST.json"
    root_signature = simulation / "ROOT-MANIFEST.sig.json"
    root_manifest.write_bytes(root_bytes)
    root_signature.write_bytes(signature_bytes)
    key_id = key_id_for_public_key(simulation_public_key)
    provenance_trust_key = TrustedEd25519PublicKey(
        simulation_public_key, key_id, "simulation"
    )

    plan = P2DeployPlan(
        release=release,
        wheel=wheel,
        manifest=manifest,
        runbook=runbook,
        wheel_sha256=sha(wheel),
        manifest_sha256=sha(manifest),
        runbook_sha256=sha(runbook),
        canonical_db=database,
        target_venv=target_venv,
        host="127.0.0.1",
        port=port,
        target_environment="p2-isolated-installed-simulation",
        p2_driver=driver,
        p2_driver_sha256=sha(driver),
        dependency_lock=lock,
        dependency_lock_sha256=sha(lock),
        wheelhouse=release / "offline/wheelhouse",
        wheelhouse_manifest=wheelhouse_manifest,
        wheelhouse_manifest_sha256=sha(wheelhouse_manifest),
        canonical_adapter=adapter,
        canonical_adapter_sha256=sha(adapter),
        staged_launcher=launcher,
        staged_launcher_sha256=sha(launcher),
        rollback_reference=rollback_reference,
        rollback_reference_sha256=sha(rollback_reference),
        parent_p1_plan_hash=P1_PLAN_HASH,
        simulation=True,
        root_manifest=root_manifest,
        root_manifest_signature=root_signature,
        release_plan=plan_path,
        release_plan_sha256=sha(plan_path),
    )

    key = os.urandom(32)
    now = datetime.now(timezone.utc)
    approval = create_p2_approval(
        plan,
        args.deployment_id,
        key,
        now=now,
        ttl_seconds=300,
        nonce=args.deployment_id + "-single-use",
    )
    result = P2DeploymentDriver(
        plan,
        checkpoints,
        P2RealBackend(
            timeout=120,
            service_snapshot=lambda: {},
            provenance_trust_key=provenance_trust_key,
        ),
        clock=lambda: now,
    ).run(
        DeployMode.EXECUTE,
        args.deployment_id,
        approval=approval,
        approval_key=key,
    )
    result["run_id"] = args.run_id
    result["technical_owner"] = "codex"
    result["ownership_token_sha256"] = os.environ["P2_RUN_OWNERSHIP_TOKEN_SHA256"]
    result_path = simulation / "P2-SIMULATION-RESULT.json"
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("STATUS=" + str(result["status"]))
    print("PLAN_HASH=" + plan.canonical_hash)
    print("ROOT_MANIFEST_HASH=" + sha(root_manifest))
    print("PROVENANCE_KEY_ID=" + key_id)
    print("PORT=" + str(port))
    print("COMPLETED=" + str(len(result["completed_states"])))
    print("FAILED_STATE=" + str(result.get("failed_state")))
    print("ERROR=" + str(result.get("error")))
    return 0 if result["status"] == "DEPLOYED" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--worktree", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--canonical-db", type=Path, required=True)
    parser.add_argument("--canonical-inode", type=int, required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--deployment-id")
    args = parser.parse_args(argv)
    if args.deployment_id is None:
        args.deployment_id = args.run_id
    if args.deployment_id != args.run_id:
        parser.error("deployment ID must equal the unique run ID")
    spec = ReleaseRunSpec(
        run_id=args.run_id,
        technical_owner="codex",
        worktree=args.worktree,
        venv=args.venv,
        temp_root=args.run_root,
        database=args.run_root / "home/agents_os/state.sqlite",
        canonical_database=args.canonical_db,
        canonical_inode=args.canonical_inode,
        mode="simulation",
        lock_file=args.release_lock,
        ownership_file=args.run_root / "run-ownership.json",
    )
    with ReleaseRunGuard(spec):
        return _execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
