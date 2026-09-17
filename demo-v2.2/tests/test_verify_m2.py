from __future__ import annotations

import os
from pathlib import Path
import shutil
import unittest

from fixtures_m2 import M2SignedFixture
from sentinel_demo.verify import verify_bundle


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_COSIGN = PROJECT_ROOT / ".tools" / "cosign"
COSIGN = os.environ.get("COSIGN_BIN") or (
    str(PROJECT_COSIGN)
    if PROJECT_COSIGN.is_file()
    else shutil.which("cosign") or str(PROJECT_COSIGN)
)


class VerifyBundleM2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not Path(COSIGN).is_file():
            raise AssertionError(f"required real Cosign binary is absent: {COSIGN}")
        cls.fixture = M2SignedFixture(COSIGN)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def setUp(self) -> None:
        self.fixture.reset()

    def verify(self) -> dict:
        return verify_bundle(
            self.fixture.request,
            self.fixture.policy_bytes,
            self.fixture.public_key,
            self.fixture.store,
            COSIGN,
        )

    def assert_decision(self, exit_code: int, reason: str, status: str) -> None:
        result = self.verify()
        self.assertEqual("sentinel-demo-m2/v0.1", result["profile"])
        self.assertEqual(exit_code, result["exitCode"])
        self.assertEqual([reason], result["reasonCodes"])
        self.assertEqual(status, result["status"])
        if exit_code != 0:
            self.assertNotEqual("PASS", result["status"])

    def test_complete_m2_evidence_graph_verifies(self) -> None:
        result = self.verify()
        self.assertEqual(0, result["exitCode"])
        self.assertEqual(["VERIFIED"], result["reasonCodes"])
        self.assertEqual("PASS", result["status"])
        self.assertEqual(
            {
                "request": True,
                "policy": True,
                "publicKey": True,
                "image": True,
                "manifest": True,
                "sbom": True,
                "governance": True,
                "provenance": True,
            },
            result["checks"],
        )

    def test_missing_root_artifact_is_missing_manifest(self) -> None:
        self.fixture.remove_root_artifact()
        self.assert_decision(10, "MISSING_MANIFEST", "HOLD")

    def test_missing_sbom_payload_identifies_role(self) -> None:
        self.fixture.remove_role_payload("sbom")
        self.assert_decision(11, "MISSING_SBOM", "HOLD")

    def test_missing_governance_payload_identifies_role(self) -> None:
        self.fixture.remove_role_payload("governance")
        self.assert_decision(12, "MISSING_GOVERNANCE", "HOLD")

    def test_missing_provenance_payload_identifies_role(self) -> None:
        self.fixture.remove_role_payload("provenance")
        self.assert_decision(13, "MISSING_PROVENANCE", "HOLD")

    def test_missing_non_root_oci_artifact_is_missing_attestation(self) -> None:
        self.fixture.remove_role_artifact("governance")
        self.assert_decision(14, "MISSING_ATTESTATION", "HOLD")

    def test_content_under_pinned_digest_is_digest_mismatch(self) -> None:
        self.fixture.corrupt_image_under_pinned_digest()
        self.assert_decision(20, "DIGEST_MISMATCH", "BLOCKED")

    def test_invalid_dsse_signature_is_invalid_signature(self) -> None:
        self.fixture.corrupt_root_signature_and_repin()
        self.assert_decision(30, "INVALID_SIGNATURE", "BLOCKED")

    def test_valid_signature_over_wrong_subject_is_subject_mismatch(self) -> None:
        self.fixture.replace_signed_subject("provenance")
        self.assert_decision(40, "SUBJECT_MISMATCH", "BLOCKED")

    def test_wrong_oci_subject_is_subject_mismatch(self) -> None:
        self.fixture.replace_oci_subject("sbom")
        self.assert_decision(40, "SUBJECT_MISMATCH", "BLOCKED")

    def test_well_shaped_false_governance_check_is_policy_violation(self) -> None:
        self.fixture.replace_governance_checks(
            {"buildPassed": True, "testsPassed": False, "sbomGenerated": True}
        )
        self.assert_decision(50, "POLICY_VIOLATION", "BLOCKED")

    def test_valid_unknown_signed_predicate_is_unknown_predicate(self) -> None:
        self.fixture.replace_predicate_type(
            "provenance", "https://sentinel.example/demo/unexpected/v1"
        )
        self.assert_decision(60, "UNKNOWN_PREDICATE", "BLOCKED")


if __name__ == "__main__":
    unittest.main()
