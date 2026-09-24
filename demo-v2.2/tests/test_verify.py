from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from sentinel_demo.verify import verify_bundle
from fixtures import SignedFixture, canonical, digest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_COSIGN = PROJECT_ROOT / ".tools" / "cosign"
COSIGN = os.environ.get("COSIGN_BIN") or (
    str(PROJECT_COSIGN)
    if PROJECT_COSIGN.is_file()
    else shutil.which("cosign") or str(PROJECT_COSIGN)
)


class VerifyBundleAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        if not Path(COSIGN).is_file():
            self.fail(f"required real Cosign binary is absent: {COSIGN}")
        self.fixture = SignedFixture(COSIGN)

    def tearDown(self) -> None:
        self.fixture.close()

    def verify(self) -> dict:
        return verify_bundle(
            self.fixture.request,
            self.fixture.policy_bytes,
            self.fixture.public_key,
            self.fixture.store,
            COSIGN,
        )

    def test_happy_path_passes(self) -> None:
        result = self.verify()
        self.assertEqual(0, result["exitCode"])
        self.assertEqual("PASS", result["status"])

    def test_missing_sbom_holds(self) -> None:
        self.fixture.remove_role_object("sbom")
        result = self.verify()
        self.assertEqual(2, result["exitCode"])
        self.assertEqual(["MISSING_SBOM"], result["reasonCodes"])

    def test_missing_governance_holds(self) -> None:
        self.fixture.remove_role_object("governance")
        result = self.verify()
        self.assertEqual(2, result["exitCode"])
        self.assertEqual(["MISSING_GOVERNANCE"], result["reasonCodes"])

    def test_digest_mismatch_is_blocked(self) -> None:
        self.fixture.corrupt_image_under_pinned_digest()
        result = self.verify()
        self.assertEqual(3, result["exitCode"])
        self.assertEqual(["DIGEST_MISMATCH"], result["reasonCodes"])

    def test_bad_signature_is_blocked_after_outer_descriptors_are_repinned(self) -> None:
        self.fixture.corrupt_root_signature_and_repin()
        result = self.verify()
        self.assertEqual(3, result["exitCode"])
        self.assertEqual(["INVALID_SIGNATURE"], result["reasonCodes"])

    def test_missing_manifest_holds(self) -> None:
        del self.fixture.store.manifests[
            self.fixture.request["manifest"]["artifact"]["digest"]
        ]
        result = self.verify()
        self.assertEqual(2, result["exitCode"])
        self.assertEqual(["MISSING_MANIFEST"], result["reasonCodes"])

    def test_numeric_governance_check_cannot_equal_json_true(self) -> None:
        self.fixture.replace_governance_checks(
            {"buildPassed": 1, "testsPassed": True, "sbomGenerated": True}
        )
        result = self.verify()
        self.assertEqual(3, result["exitCode"])
        self.assertEqual(["INVALID_GOVERNANCE"], result["reasonCodes"])

    def test_non_finite_json_policy_values_are_malformed(self) -> None:
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token):
                policy = canonical(
                    {
                        "profile": "sentinel-demo-mvp/v0.1",
                        "allowMockGovernance": True,
                        "productionAcceptance": False,
                        "requiredRoles": ["sbom", "governance"],
                        "sbomSpecVersion": "1.6",
                    }
                ).replace(b'"1.6"', token)
                self.fixture.request["policySha256"] = digest(policy)
                result = verify_bundle(
                    self.fixture.request,
                    policy,
                    self.fixture.public_key,
                    self.fixture.store,
                    COSIGN,
                )
                self.assertEqual(4, result["exitCode"])
                self.assertEqual(["MALFORMED_POLICY"], result["reasonCodes"])

    def test_cosign_name_is_resolved_from_callers_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sentinel-cosign-path-") as directory:
            Path(directory, "cosign").symlink_to(Path(COSIGN).resolve())
            with mock.patch.dict(os.environ, {"PATH": directory}):
                result = verify_bundle(
                    self.fixture.request,
                    self.fixture.policy_bytes,
                    self.fixture.public_key,
                    self.fixture.store,
                    "cosign",
                )
        self.assertEqual(0, result["exitCode"])
        self.assertEqual(["VERIFIED"], result["reasonCodes"])

    def test_public_key_path_swap_after_pin_cannot_change_verification_key(self) -> None:
        attacker = SignedFixture(COSIGN)
        trusted_key = self.fixture.public_key.read_bytes()

        class KeySwapStore:
            def __init__(self) -> None:
                self.swapped = False

            def read_manifest(inner_self, object_digest: str) -> bytes:
                if not inner_self.swapped:
                    self.fixture.public_key.write_bytes(attacker.public_key.read_bytes())
                    inner_self.swapped = True
                return attacker.store.read_manifest(object_digest)

            def read_blob(inner_self, object_digest: str) -> bytes:
                return attacker.store.read_blob(object_digest)

        try:
            attacker.request["publicKeySha256"] = digest(trusted_key)
            result = verify_bundle(
                attacker.request,
                attacker.policy_bytes,
                self.fixture.public_key,
                KeySwapStore(),
                COSIGN,
            )
        finally:
            self.fixture.public_key.write_bytes(trusted_key)
            attacker.close()

        self.assertEqual(3, result["exitCode"])
        self.assertEqual(["INVALID_SIGNATURE"], result["reasonCodes"])


if __name__ == "__main__":
    unittest.main()
