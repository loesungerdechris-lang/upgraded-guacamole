"""Exercise the actual CI gate process and its persisted decision."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CIGateTests(unittest.TestCase):
    def invoke(self, result, output):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci_gate.py"),
             "--acceptance-result", result, "--output", str(output)],
            capture_output=True, text=True, timeout=10,
        )

    def test_success_persists_a_technical_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "gate.json"
            process = self.invoke("success", output)
            self.assertEqual(0, process.returncode, process.stderr)
            report = json.loads(output.read_bytes())
            self.assertEqual("PASS", report["status"])
            self.assertIs(False, report["productionAcceptance"])
            self.assertEqual("success", report["acceptanceResult"])

    def test_every_non_success_result_keeps_gate_closed(self):
        for state in ("failure", "cancelled", "skipped", "", "unknown", "Success"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / "gate.json"
                process = self.invoke(state, output)
                self.assertEqual(1, process.returncode, process.stderr)
                report = json.loads(output.read_bytes())
                self.assertEqual("BLOCKED", report["status"])
                self.assertIs(False, report["productionAcceptance"])
                self.assertEqual("ACCEPTANCE_NOT_SUCCESSFUL", report["reasonCode"])

    def test_unwritable_report_cannot_print_or_return_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "directory"
            output.mkdir()
            process = self.invoke("success", output)
            self.assertEqual(4, process.returncode, process.stderr)
            self.assertNotIn("PASS", process.stdout)


if __name__ == "__main__":
    unittest.main()
