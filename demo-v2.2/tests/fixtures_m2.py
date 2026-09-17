"""Independent real-Cosign M2 fixture builder for verifier tests."""

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


PROFILE = "sentinel-demo-m2/v0.1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
BUNDLE_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
ROOT_TYPE = "https://sentinel.example/demo/evidence-manifest/v1"
GOVERNANCE_TYPE = "https://sentinel.example/demo/governance/v1"
PROVENANCE_TYPE = "https://sentinel.example/demo/provenance/v1"
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


class M2SignedFixture:
    """Own temporary keys and resettable, exact M2 OCI objects."""

    def __init__(self, cosign: str) -> None:
        self.cosign = cosign
        self._temporary = tempfile.TemporaryDirectory(prefix="sentinel-m2-verifier-test-")
        self.directory = Path(self._temporary.name)
        self.private_key = self.directory / "signing.key"
        self.public_key = self.directory / "signing.pub"
        self.password = "fixture-only-password"
        self.run_id = "fixture-m2-run-001"
        self.source_digest = digest(b"fn main() { println!(\"sentinel\"); }\n")
        self.binary_digest = digest(b"fixture-binary\n")
        self.policy_bytes = canonical(
            {
                "profile": PROFILE,
                "allowMockGovernance": True,
                "productionAcceptance": False,
                "requiredRoles": ["sbom", "governance", "provenance"],
                "sbomSpecVersion": "1.6",
            }
        )
        self._generate_key()
        self._build()
        self._snapshot()

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
        self,
        predicate_type: str,
        predicate: dict[str, Any],
        label: str,
        subject_bytes: bytes | None = None,
    ) -> bytes:
        predicate_path = self.directory / f"{label}.predicate.json"
        bundle_path = self.directory / f"{label}.bundle.json"
        target_path = self.directory / f"{label}.subject"
        predicate_path.write_bytes(canonical(predicate))
        target_path.write_bytes(self.image_bytes if subject_bytes is None else subject_bytes)
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

    def _add_artifact(
        self,
        predicate_type: str,
        predicate: dict[str, Any],
        label: str,
        *,
        signed_subject_bytes: bytes | None = None,
        oci_subject_digest: str | None = None,
    ) -> dict[str, Any]:
        bundle = self._sign_predicate(
            predicate_type, predicate, label, subject_bytes=signed_subject_bytes
        )
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
                    "digest": oci_subject_digest or self.image_digest,
                    "size": len(self.image_bytes),
                },
            }
        )
        artifact_descriptor = descriptor(artifact, OCI_MANIFEST)
        self.store.manifests[artifact_descriptor["digest"]] = artifact
        return {"artifact": artifact_descriptor, "payload": payload}

    def _governance_predicate(self, checks: dict[str, Any]) -> dict[str, Any]:
        return {
            "profile": PROFILE,
            "fixture": True,
            "productionApproval": False,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": digest(self.policy_bytes),
            "checks": checks,
        }

    def _provenance_predicate(self) -> dict[str, Any]:
        return {
            "profile": PROFILE,
            "fixture": True,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": digest(self.policy_bytes),
            "sourceSha256": self.source_digest,
            "binarySha256": self.binary_digest,
            "builder": "sentinel-demo",
        }

    def _root_entries(self) -> list[dict[str, Any]]:
        return [
            {
                "role": role,
                "predicateType": predicate_type,
                **copy.deepcopy(getattr(self, f"{role}_ref")),
            }
            for role, predicate_type in (
                ("sbom", SBOM_TYPE),
                ("governance", GOVERNANCE_TYPE),
                ("provenance", PROVENANCE_TYPE),
            )
        ]

    def _replace_root(self, label: str) -> None:
        root_predicate = {
            "profile": PROFILE,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "policySha256": digest(self.policy_bytes),
            "entries": self._root_entries(),
        }
        self.root_ref = self._add_artifact(ROOT_TYPE, root_predicate, label)
        self.request["manifest"] = copy.deepcopy(self.root_ref)

    def _build(self) -> None:
        self.store = MemoryStore()
        config = b'{"architecture":"amd64","os":"linux"}'
        layer = b"sentinel m2 test image layer\n"
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

        self.sbom_predicate = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [],
        }
        self.sbom_ref = self._add_artifact(SBOM_TYPE, self.sbom_predicate, "sbom")
        self.governance_ref = self._add_artifact(
            GOVERNANCE_TYPE,
            self._governance_predicate(
                {"buildPassed": True, "testsPassed": True, "sbomGenerated": True}
            ),
            "governance",
        )
        self.provenance_ref = self._add_artifact(
            PROVENANCE_TYPE, self._provenance_predicate(), "provenance"
        )
        self.request = {
            "profile": PROFILE,
            "image": "registry.invalid/sentinel/demo@" + self.image_digest,
            "manifest": {},
            "runId": self.run_id,
            "policySha256": digest(self.policy_bytes),
            "publicKeySha256": digest(self.public_key.read_bytes()),
        }
        self._replace_root("root")

    def _snapshot(self) -> None:
        self._base_manifests = copy.deepcopy(self.store.manifests)
        self._base_blobs = copy.deepcopy(self.store.blobs)
        self._base_request = copy.deepcopy(self.request)
        self._base_refs = {
            role: copy.deepcopy(getattr(self, f"{role}_ref"))
            for role in ("sbom", "governance", "provenance", "root")
        }

    def reset(self) -> None:
        self.store.manifests = copy.deepcopy(self._base_manifests)
        self.store.blobs = copy.deepcopy(self._base_blobs)
        self.request = copy.deepcopy(self._base_request)
        for role, reference in self._base_refs.items():
            setattr(self, f"{role}_ref", copy.deepcopy(reference))

    def remove_root_artifact(self) -> None:
        del self.store.manifests[self.root_ref["artifact"]["digest"]]

    def remove_role_payload(self, role: str) -> None:
        reference = getattr(self, f"{role}_ref")
        del self.store.blobs[reference["payload"]["digest"]]

    def remove_role_artifact(self, role: str) -> None:
        reference = getattr(self, f"{role}_ref")
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
        self.governance_ref = self._add_artifact(
            GOVERNANCE_TYPE,
            self._governance_predicate(checks),
            "replacement-governance",
        )
        self._replace_root("root-with-replacement-governance")

    def replace_signed_subject(self, role: str) -> None:
        predicate_type, predicate = self._role_signing_values(role)
        reference = self._add_artifact(
            predicate_type,
            predicate,
            f"wrong-signed-subject-{role}",
            signed_subject_bytes=b"different subject\n",
        )
        setattr(self, f"{role}_ref", reference)
        self._replace_root(f"root-with-wrong-signed-subject-{role}")

    def replace_oci_subject(self, role: str) -> None:
        predicate_type, predicate = self._role_signing_values(role)
        reference = self._add_artifact(
            predicate_type,
            predicate,
            f"wrong-oci-subject-{role}",
            oci_subject_digest=digest(b"different subject\n"),
        )
        setattr(self, f"{role}_ref", reference)
        self._replace_root(f"root-with-wrong-oci-subject-{role}")

    def replace_predicate_type(self, role: str, actual_type: str) -> None:
        _, predicate = self._role_signing_values(role)
        reference = self._add_artifact(
            actual_type, predicate, f"unknown-predicate-{role}"
        )
        setattr(self, f"{role}_ref", reference)
        self._replace_root(f"root-with-unknown-predicate-{role}")

    def _role_signing_values(self, role: str) -> tuple[str, dict[str, Any]]:
        if role == "sbom":
            return SBOM_TYPE, copy.deepcopy(self.sbom_predicate)
        if role == "governance":
            return GOVERNANCE_TYPE, self._governance_predicate(
                {"buildPassed": True, "testsPassed": True, "sbomGenerated": True}
            )
        if role == "provenance":
            return PROVENANCE_TYPE, self._provenance_predicate()
        raise ValueError(f"unknown fixture role: {role}")
