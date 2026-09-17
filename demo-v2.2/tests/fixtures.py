"""Independent real-Cosign fixture builder for verifier tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any


PROFILE = "sentinel-demo-mvp/v0.1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
BUNDLE_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
ROOT_TYPE = "https://sentinel.example/demo/evidence-manifest/v1"
GOVERNANCE_TYPE = "https://sentinel.example/demo/governance/v1"
SBOM_TYPE = "https://cyclonedx.org/bom"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptor(data: bytes, media_type: str) -> dict[str, Any]:
    return {"digest": digest(data), "size": len(data), "mediaType": media_type}


class MemoryStore:
    def __init__(self) -> None:
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}

    def read_manifest(self, object_digest: str) -> bytes:
        try:
            return self.manifests[object_digest]
        except KeyError as exc:
            raise FileNotFoundError(object_digest) from exc

    def read_blob(self, object_digest: str) -> bytes:
        try:
            return self.blobs[object_digest]
        except KeyError as exc:
            raise FileNotFoundError(object_digest) from exc


class SignedFixture:
    """Owns temporary signing material and exact in-memory OCI objects."""

    def __init__(self, cosign: str) -> None:
        self.cosign = cosign
        self._temporary = tempfile.TemporaryDirectory(prefix="sentinel-verifier-test-")
        self.directory = Path(self._temporary.name)
        self.private_key = self.directory / "signing.key"
        self.public_key = self.directory / "signing.pub"
        self.password = "fixture-only-password"
        self.store = MemoryStore()
        self.run_id = "fixture-run-001"
        self.policy_bytes = canonical(
            {
                "profile": PROFILE,
                "allowMockGovernance": True,
                "productionAcceptance": False,
                "requiredRoles": ["sbom", "governance"],
                "sbomSpecVersion": "1.6",
            }
        )
        self._generate_key()
        self._build()

    def close(self) -> None:
        self._temporary.cleanup()

    def _run(self, command: list[str]) -> None:
        environment = os.environ.copy()
        environment["COSIGN_PASSWORD"] = self.password
        subprocess.run(
            command,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )

    def _generate_key(self) -> None:
        self._run(
            [
                self.cosign,
                "generate-key-pair",
                "--output-key-prefix",
                str(self.directory / "signing"),
            ]
        )

    def _sign_predicate(
        self, predicate_type: str, predicate: dict[str, Any], label: str
    ) -> bytes:
        predicate_path = self.directory / f"{label}.predicate.json"
        bundle_path = self.directory / f"{label}.bundle.json"
        target_path = self.directory / "image.manifest.json"
        predicate_path.write_bytes(canonical(predicate))
        target_path.write_bytes(self.image_bytes)
        self._run(
            [
                self.cosign,
                "attest-blob",
                "--predicate",
                str(predicate_path),
                "--type",
                predicate_type,
                "--key",
                str(self.private_key),
                "--bundle",
                str(bundle_path),
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--yes",
                str(target_path),
            ]
        )
        return bundle_path.read_bytes()

    def _add_artifact(self, predicate_type: str, predicate: dict[str, Any], label: str) -> dict[str, Any]:
        bundle = self._sign_predicate(predicate_type, predicate, label)
        payload = descriptor(bundle, BUNDLE_MEDIA)
        self.store.blobs[payload["digest"]] = bundle
        artifact = canonical(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "artifactType": BUNDLE_MEDIA,
                "config": descriptor(b"{}", "application/vnd.oci.empty.v1+json"),
                "layers": [payload],
                "subject": {
                    "mediaType": OCI_MANIFEST,
                    "digest": self.image_digest,
                    "size": len(self.image_bytes),
                },
            }
        )
        artifact_descriptor = descriptor(artifact, OCI_MANIFEST)
        self.store.manifests[artifact_descriptor["digest"]] = artifact
        return {"artifact": artifact_descriptor, "payload": payload}

    def _build(self) -> None:
        config = b'{"architecture":"amd64","os":"linux"}'
        layer = b"sentinel test image layer\n"
        config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
        layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
        self.store.blobs[config_descriptor["digest"]] = config
        self.store.blobs[layer_descriptor["digest"]] = layer
        self.image_bytes = canonical(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": config_descriptor,
                "layers": [layer_descriptor],
            }
        )
        self.image_digest = digest(self.image_bytes)
        self.store.manifests[self.image_digest] = self.image_bytes
        policy_digest = digest(self.policy_bytes)

        sbom_predicate = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        }
        governance_predicate = {
            "profile": PROFILE,
            "fixture": True,
            "productionApproval": False,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": policy_digest,
            "checks": {
                "buildPassed": True,
                "testsPassed": True,
                "sbomGenerated": True,
            },
        }
        self.sbom_ref = self._add_artifact(SBOM_TYPE, sbom_predicate, "sbom")
        self.governance_ref = self._add_artifact(
            GOVERNANCE_TYPE, governance_predicate, "governance"
        )
        entries = [
            {
                "role": "sbom",
                "predicateType": SBOM_TYPE,
                **copy.deepcopy(self.sbom_ref),
            },
            {
                "role": "governance",
                "predicateType": GOVERNANCE_TYPE,
                **copy.deepcopy(self.governance_ref),
            },
        ]
        root_predicate = {
            "profile": PROFILE,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": policy_digest,
            "entries": entries,
        }
        self.root_ref = self._add_artifact(ROOT_TYPE, root_predicate, "root")
        self.request = {
            "profile": PROFILE,
            "image": "registry.invalid/sentinel/demo@" + self.image_digest,
            "manifest": copy.deepcopy(self.root_ref),
            "runId": self.run_id,
            "policySha256": policy_digest,
            "publicKeySha256": digest(self.public_key.read_bytes()),
        }

    def remove_role_object(self, role: str) -> None:
        reference = self.sbom_ref if role == "sbom" else self.governance_ref
        del self.store.manifests[reference["artifact"]["digest"]]

    def corrupt_image_under_pinned_digest(self) -> None:
        self.store.manifests[self.image_digest] = self.image_bytes + b"\n"

    def corrupt_root_signature_and_repin(self) -> None:
        old_payload_digest = self.root_ref["payload"]["digest"]
        bundle = json.loads(self.store.blobs.pop(old_payload_digest))
        signature = base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"])
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(
            bytes([signature[0] ^ 1]) + signature[1:]
        ).decode()
        bundle_bytes = canonical(bundle)
        new_payload = descriptor(bundle_bytes, BUNDLE_MEDIA)
        self.store.blobs[new_payload["digest"]] = bundle_bytes

        old_artifact_digest = self.root_ref["artifact"]["digest"]
        artifact = json.loads(self.store.manifests.pop(old_artifact_digest))
        artifact["layers"] = [copy.deepcopy(new_payload)]
        artifact_bytes = canonical(artifact)
        new_artifact = descriptor(artifact_bytes, OCI_MANIFEST)
        self.store.manifests[new_artifact["digest"]] = artifact_bytes
        self.root_ref = {"artifact": new_artifact, "payload": new_payload}
        self.request["manifest"] = copy.deepcopy(self.root_ref)

    def replace_governance_checks(self, checks: dict[str, Any]) -> None:
        """Create a fully re-signed graph containing the supplied check values."""
        governance_predicate = {
            "profile": PROFILE,
            "fixture": True,
            "productionApproval": False,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": digest(self.policy_bytes),
            "checks": checks,
        }
        self.governance_ref = self._add_artifact(
            GOVERNANCE_TYPE, governance_predicate, "replacement-governance"
        )
        entries = [
            {
                "role": "sbom",
                "predicateType": SBOM_TYPE,
                **copy.deepcopy(self.sbom_ref),
            },
            {
                "role": "governance",
                "predicateType": GOVERNANCE_TYPE,
                **copy.deepcopy(self.governance_ref),
            },
        ]
        root_predicate = {
            "profile": PROFILE,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": digest(self.policy_bytes),
            "entries": entries,
        }
        self.root_ref = self._add_artifact(
            ROOT_TYPE, root_predicate, "replacement-root"
        )
        self.request["manifest"] = copy.deepcopy(self.root_ref)
