"""Adversarial regressions for contract drift, false coverage and missing CI proof."""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("crosswalk", ROOT / "scripts/crosswalk.py")
CW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CW)
REQ = CW.FOLDER + "/requirements.yaml"
OBS = CW.FOLDER + "/evidence/m2-observation.json"


class CrosswalkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        paths = {ROOT / REQ, ROOT / OBS, ROOT / (CW.FOLDER + "/crosswalk.schema.json"),
                 ROOT / (CW.FOLDER + "/crosswalk.md"), ROOT / (CW.FOLDER + "/crosswalk.mmd"),
                 ROOT / "docs/acceptance/m2-baseline.md", ROOT / "tests/exit-codes.yaml",
                 ROOT / "tests/crosswalk/expected-requirements.txt"}
        for pattern in CW.SOURCE_PATTERNS:
            paths.update(p for p in ROOT.glob(pattern) if p.is_file())
        for source in paths:
            target = self.root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def change(self, relative, function):
        path = self.root / relative
        data = json.loads(path.read_bytes())
        function(data)
        path.write_text(json.dumps(data))

    def repin_observation(self):
        value = "sha256:" + hashlib.sha256((self.root / OBS).read_bytes()).hexdigest()
        self.change(REQ, lambda r: r["baseline"].update(sha256=value))

    def rejected(self):
        # Do not let generated-view staleness mask a missing contract check.
        with self.assertRaises(CW.Invalid):
            CW.validate_data(self.root)

    def test_valid_contract_computes_counts_and_generates_identical_views(self):
        report = CW.run(self.root)
        self.assertEqual((16, 10, 1, 5, 10), tuple(report[k] for k in
                         ("requirements", "covered", "partial", "open", "mutationScenarios")))
        self.assertIs(False, report["productionAcceptance"])
        before = (self.root / (CW.FOLDER + "/crosswalk.md")).read_bytes()
        CW.run(self.root, generate=True)
        self.assertEqual(before, (self.root / (CW.FOLDER + "/crosswalk.md")).read_bytes())

    def test_duplicate_requirement_id_with_different_title_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][1].update(id=d["requirements"][0]["id"]))
        self.rejected()

    def test_missing_requirement_even_outside_m2_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"].pop())
        self.rejected()

    def test_unknown_requirement_id_format_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0].update(id="requirement-1"))
        self.rejected()

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / REQ
        path.write_text(path.read_text().replace('"version": "2.2"',
                                                '"version": "2.2", "version": "2.2"', 1))
        self.rejected()

    def test_nonfinite_json_is_rejected(self):
        path = self.root / REQ
        path.write_text(path.read_text().replace('"version": "2.2"', '"version": NaN', 1))
        self.rejected()

    def test_empty_inventory_is_rejected(self):
        self.change(REQ, lambda d: d.update(requirements=[]))
        self.rejected()

    def test_unknown_referenced_mutation_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0]["tests"][0].update(scenario="nonexistent"))
        self.rejected()

    def test_unmapped_real_mutation_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0].update(tests=[]))
        self.rejected()

    def test_duplicate_m2_mapping_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][1].update(tests=d["requirements"][0]["tests"]))
        self.rejected()

    def test_exit_code_mismatch_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0]["tests"][0].update(exit_code=11))
        self.rejected()

    def test_symbolic_code_mismatch_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0]["tests"][0].update(exit_name="UNKNOWN"))
        self.rejected()

    def test_noninteger_contract_code_is_rejected(self):
        self.change("tests/exit-codes.yaml", lambda d: d["exit_codes"].update(VERIFIED=False))
        self.rejected()

    def test_nonexistent_verification_rule_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0].update(rule="imaginary_check"))
        self.rejected()

    def test_wrong_predicate_binding_is_rejected(self):
        self.change(REQ, lambda d: d["requirements"][0]["evidence"][0].update(
            predicate_type="https://example.invalid/wrong"))
        self.rejected()

    def test_future_item_cannot_claim_covered(self):
        self.change(REQ, lambda d: d["requirements"][-1].update(coverage="covered"))
        self.rejected()

    def test_frozen_m2_requirement_cannot_be_demoted(self):
        def mutate(data):
            by_id = {item["id"]: item for item in data["requirements"]}
            by_id["M2-MUT-09"].update(milestone="M3", coverage="open", tests=[])
        self.change(REQ, mutate)
        with self.assertRaisesRegex(CW.Invalid, "Frozen M2 requirement must remain in M2"):
            CW.validate_data(self.root)

    def test_each_m2_requirement_has_exactly_one_mutation(self):
        self.change(REQ, lambda d: d["requirements"][0]["tests"].append(
            d["requirements"][1]["tests"][0]))
        with self.assertRaisesRegex(CW.Invalid, "exactly one test per covered requirement"):
            CW.validate_data(self.root)

    def test_full_v22_coverage_claim_is_rejected(self):
        self.change(REQ, lambda d: d.update(v22_coverage="complete"))
        self.rejected()

    def test_production_acceptance_claim_is_rejected(self):
        self.change(REQ, lambda d: d.update(production_acceptance=True))
        self.rejected()

    def test_removed_mock_disclosure_is_rejected(self):
        self.change(REQ, lambda d: d["limitations"].update(governance_mock=False))
        self.rejected()

    def test_external_schema_reference_is_rejected_without_fetching(self):
        self.change(CW.FOLDER + "/crosswalk.schema.json",
                    lambda d: d.update({"$ref": "https://example.invalid/schema.json"}))
        self.rejected()

    def test_stale_markdown_even_with_ids_present_is_rejected(self):
        path = self.root / (CW.FOLDER + "/crosswalk.md")
        path.write_text(path.read_text().replace("Overall v2.2 Coverage: INCOMPLETE",
                                                "Overall v2.2 Coverage: COMPLETE"))
        with self.assertRaisesRegex(CW.Invalid, "Generated view is stale"):
            CW.run(self.root)

    def test_stale_mermaid_is_rejected(self):
        with (self.root / (CW.FOLDER + "/crosswalk.mmd")).open("a") as stream:
            stream.write('  BAD["unproved"]\n')
        with self.assertRaisesRegex(CW.Invalid, "Generated view is stale"):
            CW.run(self.root)

    def test_changed_source_cannot_reuse_old_evidence(self):
        for relative in ("demo-v2.2/sentinel_demo/verify.py", "demo-v2.2/sentinel"):
            with self.subTest(source=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n# changed runtime\n")
                with self.assertRaisesRegex(CW.Invalid, "Stale baseline for changed source"):
                    CW.validate_data(self.root)
                path.write_bytes(original)

    def test_changed_observation_without_new_pin_is_rejected(self):
        self.change(OBS, lambda d: d.update(tests_passed=99))
        self.rejected()

    def test_rehashed_wrong_observed_code_is_rejected(self):
        def mutate(d):
            job = next(j for j in d["jobs"] if j["name"] == "mutation-suite (missing-sbom)")
            job["proof_lines"] = ["missing-sbom: expected=11 actual=0 test=PASS"]
        self.change(OBS, mutate)
        self.repin_observation()
        self.rejected()

    def test_rehashed_wrong_job_url_is_rejected(self):
        self.change(OBS, lambda d: d["jobs"][0].update(url="https://github.com/wrong/run"))
        self.repin_observation()
        self.rejected()

    def test_missing_baseline_job_is_rejected(self):
        self.change(OBS, lambda d: d["jobs"].pop())
        self.repin_observation()
        self.rejected()

    def test_wrong_baseline_commit_is_rejected(self):
        self.change(OBS, lambda d: d.update(commit="0" * 40))
        self.repin_observation()
        self.rejected()

    def test_symlink_input_is_rejected(self):
        path = self.root / REQ
        copy = self.root / "copy.json"
        path.replace(copy)
        path.symlink_to(copy)
        self.rejected()

    def test_missing_input_is_an_error_not_an_accepted_rejection(self):
        (self.root / REQ).unlink()
        result = subprocess.run([sys.executable, str(ROOT / "scripts/crosswalk.py"), "validate",
                                 "--root", str(self.root)], capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertEqual("ERROR", json.loads(result.stdout)["status"])

    def test_unwritable_result_cannot_return_pass(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/crosswalk.py"), "validate",
                                 "--root", str(self.root), "--output", str(self.root)],
                                capture_output=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertNotIn(b'"status": "PASS"', result.stdout)


class CrosswalkGateTests(unittest.TestCase):
    def test_all_non_success_states_keep_each_gate_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            for failed in ("failure", "cancelled", "skipped", "", "unknown", "Success"):
                for argument in ("--validation", "--evidence"):
                    with self.subTest(state=failed, prerequisite=argument):
                        command = [sys.executable, str(ROOT / "scripts/crosswalk_gate.py"),
                                   "--validation", "success", "--evidence", "success",
                                   "--output", str(Path(folder) / "gate.json")]
                        command[command.index(argument) + 1] = failed
                        result = subprocess.run(command, capture_output=True, timeout=10)
                        self.assertEqual(1, result.returncode)

    def test_both_success_and_persisted_result_are_required(self):
        with tempfile.TemporaryDirectory() as folder:
            command = [sys.executable, str(ROOT / "scripts/crosswalk_gate.py"),
                       "--validation", "success", "--evidence", "success", "--output",
                       str(Path(folder) / "gate.json")]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(0, result.returncode)
            report = json.loads(Path(command[-1]).read_bytes())
            self.assertIs(False, report["productionAcceptance"])
            command[-1] = folder
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(2, result.returncode)


if __name__ == "__main__":
    unittest.main()
