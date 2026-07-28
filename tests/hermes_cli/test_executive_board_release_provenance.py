from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from scripts.executive_board.release_provenance import (
    ProvenanceError,
    REQUIRED_RELEASE_ARTIFACTS,
    TrustedEd25519PublicKey,
    build_root_manifest,
    key_id_for_public_key,
    load_trusted_public_key,
    public_key_bytes_from_private,
    sign_root_manifest,
    verify_release_provenance,
    verify_snapshot_provenance,
)


def _hashes() -> dict[str, str]:
    return {name: f"{index + 1:064x}" for index, name in enumerate(sorted(REQUIRED_RELEASE_ARTIFACTS))}


def _signed(tmp_path: Path, domain: str = "production") -> tuple[Path, Path, TrustedEd25519PublicKey, bytes]:
    private = bytes(range(32))
    public = public_key_bytes_from_private(private)
    manifest = build_root_manifest(_hashes(), public, trust_domain=domain)
    manifest_bytes, signature_bytes = sign_root_manifest(manifest, private)
    manifest_path = tmp_path / "root-manifest.json"
    signature_path = tmp_path / "root-manifest.sig.json"
    manifest_path.write_bytes(manifest_bytes)
    signature_path.write_bytes(signature_bytes)
    return (
        manifest_path,
        signature_path,
        TrustedEd25519PublicKey(public, key_id_for_public_key(public), domain),
        private,
    )


def test_ed25519_root_manifest_binds_exact_snapshot_and_contains_no_private_key(
    tmp_path: Path,
) -> None:
    manifest, signature, trust_key, private = _signed(tmp_path)
    verified = verify_release_provenance(
        manifest, signature, trust_key, expected_domain="production"
    )
    verify_snapshot_provenance(verified, _hashes())
    assert private.hex() not in manifest.read_text(encoding="utf-8")
    assert private.hex() not in signature.read_text(encoding="utf-8")
    assert verified.key_id.startswith("ed25519-sha256:")


@pytest.mark.parametrize("target", ["manifest", "signature"])
def test_provenance_rejects_byte_mutation(tmp_path: Path, target: str) -> None:
    manifest, signature, trust_key, _ = _signed(tmp_path)
    path = manifest if target == "manifest" else signature
    payload = bytearray(path.read_bytes())
    payload[-2] ^= 1
    path.write_bytes(payload)
    with pytest.raises(ProvenanceError):
        verify_release_provenance(
            manifest, signature, trust_key, expected_domain="production"
        )


def test_provenance_rejects_unsigned_fallback(tmp_path: Path) -> None:
    manifest, _, trust_key, _ = _signed(tmp_path)
    with pytest.raises(ProvenanceError, match="unsigned fallback"):
        verify_release_provenance(
            manifest, None, trust_key, expected_domain="production"
        )


def test_production_rejects_simulation_trust_root(tmp_path: Path) -> None:
    manifest, signature, simulation_key, _ = _signed(tmp_path, "simulation")
    with pytest.raises(ProvenanceError, match="may not be reused"):
        verify_release_provenance(
            manifest, signature, simulation_key, expected_domain="production"
        )


def test_provenance_rejects_wrong_key(tmp_path: Path) -> None:
    manifest, signature, trust_key, _ = _signed(tmp_path)
    other_public = public_key_bytes_from_private(bytes(reversed(range(32))))
    wrong = TrustedEd25519PublicKey(
        other_public, key_id_for_public_key(other_public), "production"
    )
    with pytest.raises(ProvenanceError):
        verify_release_provenance(
            manifest, signature, wrong, expected_domain="production"
        )
    assert wrong.key_id != trust_key.key_id


def test_provenance_rejects_snapshot_hash_or_file_set_mismatch(tmp_path: Path) -> None:
    manifest, signature, trust_key, _ = _signed(tmp_path)
    verified = verify_release_provenance(
        manifest, signature, trust_key, expected_domain="production"
    )
    changed = _hashes()
    changed["wheel.whl"] = "f" * 64
    with pytest.raises(ProvenanceError, match="does not exactly match"):
        verify_snapshot_provenance(verified, changed)
    missing = _hashes()
    missing.pop("runbook.md")
    with pytest.raises(ProvenanceError, match="does not exactly match"):
        verify_snapshot_provenance(verified, missing)


def test_root_manifest_rejects_path_traversal_and_missing_required_artifact() -> None:
    public = public_key_bytes_from_private(bytes(range(32)))
    missing = _hashes()
    missing.pop("release-plan.json")
    with pytest.raises(ProvenanceError, match="missing required"):
        build_root_manifest(missing, public, trust_domain="production")
    traversal = _hashes()
    traversal["../escape"] = "a" * 64
    with pytest.raises(ProvenanceError, match="unsafe"):
        build_root_manifest(traversal, public, trust_domain="production")


def test_manifest_serialization_is_canonical(tmp_path: Path) -> None:
    manifest, _, _, _ = _signed(tmp_path)
    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest.read_bytes().endswith(b"\n")
    assert list(parsed) == ["algorithm", "artifacts", "key_id", "schema_version", "trust_domain"]


def test_trust_root_loader_enforces_domain_owner_mode_and_symlink(
    tmp_path: Path,
) -> None:
    public = public_key_bytes_from_private(bytes(range(32)))
    key_id = key_id_for_public_key(public)
    trust = tmp_path / "production-trust-root.json"
    trust.write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "trust_domain": "production",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    trust.chmod(0o600)
    loaded = load_trusted_public_key(trust, expected_domain="production")
    assert loaded.key_id == key_id
    with pytest.raises(ProvenanceError, match="domain mismatch"):
        load_trusted_public_key(trust, expected_domain="simulation")
    trust.chmod(0o644)
    with pytest.raises(ProvenanceError, match="permissions"):
        load_trusted_public_key(trust, expected_domain="production")
    trust.chmod(0o600)
    alias = tmp_path / "alias.json"
    alias.symlink_to(trust)
    with pytest.raises(ProvenanceError, match="unsafe"):
        load_trusted_public_key(alias, expected_domain="production")
