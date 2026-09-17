"""Protect golden fixtures and unrelated work; exercise the public mutation CLI."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from sentinel_demo.mutations import seal, check_golden, inventory
from sentinel_demo.store import DirectoryStore, descriptor

ROOT = Path(__file__).resolve().parents[1]


class MutationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.golden = self.root / "golden"
        store = DirectoryStore(self.golden / "bundle")
        raw = b'{"fixture":true}'
        payload = descriptor(raw, "test/json")
        store.write(raw)
        entry = {"role": "sbom", "payload": payload, "artifact": payload}
        statement = json.dumps({"predicate": {"entries": [entry]}}).encode()
        bundle = json.dumps({"dsseEnvelope": {"payload": base64.b64encode(statement).decode()}}).encode()
        root = descriptor(bundle, "test/json")
        store.write(bundle)
        (self.golden / "verification-request.json").write_text(json.dumps({"manifest": {"payload": root, "artifact": root}}))
        (self.golden / "demo.pub").write_text("public fixture only")
        (self.golden / "governance-policy.yml").write_text("{}")
        self.pin = seal(self.golden)

    def invoke(self, output, scenario="missing-sbom", pin=None):
        return subprocess.run([sys.executable, "-m", "sentinel_demo", "mutate",
                               "--golden", str(self.golden), "--golden-pin", pin or self.pin,
                               "--scenario", scenario, "--output", str(output)],
                              cwd=ROOT, capture_output=True, timeout=10)

    def test_copy_is_idempotent_and_golden_stays_byte_identical(self):
        before = inventory(self.golden)
        output = self.root / "work"
        self.assertEqual(0, self.invoke(output).returncode)
        first = inventory(output)
        self.assertEqual(0, self.invoke(output).returncode)
        self.assertEqual(first, inventory(output))
        self.assertEqual(before, inventory(self.golden))
        check_golden(self.golden, self.pin)

    def test_golden_overlap_and_unrelated_directory_are_never_deleted(self):
        for output in (self.golden, self.golden / "work", self.root):
            with self.subTest(output=output):
                self.assertEqual(99, self.invoke(output).returncode)
                check_golden(self.golden, self.pin)
        output = self.root / "unrelated"
        output.mkdir()
        (output / "keep.txt").write_text("keep")
        self.assertEqual(99, self.invoke(output).returncode)
        self.assertEqual("keep", (output / "keep.txt").read_text())

    def test_changed_golden_or_wrong_pin_is_rejected(self):
        output = self.root / "work"
        self.assertEqual(99, self.invoke(output, pin="sha256:" + "0" * 64).returncode)
        (self.golden / "demo.pub").write_text("changed")
        self.assertEqual(99, self.invoke(output).returncode)
        self.assertFalse(output.exists())

    def test_unknown_scenario_is_an_error_and_leaves_no_work(self):
        output = self.root / "work"
        self.assertEqual(99, self.invoke(output, "unknown").returncode)
        self.assertFalse(output.exists())
        check_golden(self.golden, self.pin)

    def test_suite_cannot_write_reports_inside_golden(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/run_mutation_suite.py"),
                                 "--golden", str(self.golden), "--golden-pin", self.pin,
                                 "--output", str(self.golden / "reports"),
                                 "--cosign", str(self.root / "unused-cosign")],
                                capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        check_golden(self.golden, self.pin)

    def test_symlinked_destination_and_golden_content_are_rejected(self):
        output = self.root / "work"
        output.symlink_to(self.golden, target_is_directory=True)
        self.assertEqual(99, self.invoke(output).returncode)
        check_golden(self.golden, self.pin)
        (self.golden / "link").symlink_to(self.root / "outside")
        self.assertEqual(99, self.invoke(self.root / "other").returncode)

    def test_golden_failure_keeps_gate_closed_even_when_matrix_succeeded(self):
        for state in ("failure", "cancelled", "skipped", "", "unknown"):
            with self.subTest(state=state):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/ci_gate.py"),
                                         "--acceptance-result", "success", "--golden-result", state,
                                         "--output", str(self.root / "gate.json")],
                                        capture_output=True, timeout=10)
                self.assertEqual(1, result.returncode)
                self.assertEqual("BLOCKED", json.loads((self.root / "gate.json").read_bytes())["status"])


if __name__ == "__main__":
    unittest.main()
