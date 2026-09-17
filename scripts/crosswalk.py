#!/usr/bin/env python3
"""Validate the local M2 crosswalk contract and generate its review views."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = "docs/evidence-bundle-v2.2"
MAX_INPUT = 2 * 1024 * 1024
REPO = "loesungerdechris-lang/upgraded-guacamole"
BASE_URL = "https://github.com/" + REPO
SOURCE_PATTERNS = (
    "demo-v2.2/sentinel_demo/*.py", "demo-v2.2/scripts/*.py",
    "demo-v2.2/tests/*.py", "demo-v2.2/tests/mutations/*.yaml",
    "demo-v2.2/policy/*", "demo-v2.2/source/*", "demo-v2.2/toolchain.lock.json",
    "demo-v2.2/sentinel", "demo-v2.2/expected/*.json",
)


class Invalid(ValueError):
    """A contract or synchronization failure, distinct from infrastructure errors."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def bounded(root, relative):
    path = root / relative
    require(not Path(relative).is_absolute(), "Absolute input path")
    require(path.resolve().is_relative_to(root.resolve()), "Input path escapes repository")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Symlink input")
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    require(len(raw) <= MAX_INPUT, "Input exceeds size bound: " + relative)
    return raw


def load(root, relative):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result

    def reject(value):
        raise Invalid("Non-finite JSON value: " + value)

    try:
        return json.loads(bounded(root, relative), object_pairs_hook=unique,
                          parse_constant=reject)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Invalid("Expected strict JSON-subset YAML: " + relative) from exc


def plain(value):
    """Keep values inside one Markdown cell; metadata, not prose, carries claims."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;").replace("|", "&#124;").replace("`", "&#96;")


def file_link(path):
    return "../../" + path


def validate_data(root):
    from jsonschema import Draft202012Validator

    requirements = load(root, FOLDER + "/requirements.yaml")
    schema = load(root, FOLDER + "/crosswalk.schema.json")
    # This schema is self-contained. No remote reference retrieval is permitted.
    def local_refs(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef"}:
                    require(isinstance(item, str) and item.startswith("#"),
                            "External schema reference")
                local_refs(item)
        elif isinstance(value, list):
            for item in value:
                local_refs(item)
    local_refs(schema)
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(requirements), key=str)
    require(not errors, "Schema violation: " + (errors[0].message if errors else ""))
    require(requirements["production_acceptance"] is False, "Production acceptance overclaim")
    items = requirements["requirements"]
    ids = [r["id"] for r in items]
    require(len(ids) == len(set(ids)), "Duplicate requirement ID")
    expected_ids = bounded(root, "tests/crosswalk/expected-requirements.txt").decode().splitlines()
    require(len(expected_ids) == len(set(expected_ids)) and set(ids) == set(expected_ids),
            "Requirement inventory differs from separately reviewed expected IDs")

    contract = load(root, "tests/exit-codes.yaml")
    require(set(contract) == {"profile", "exit_codes", "other_error"}, "Exit contract structure")
    require(contract["profile"] == "sentinel-demo-m2/v0.1", "Exit contract profile")
    codes = contract["exit_codes"]
    require(isinstance(codes, dict) and codes, "Empty exit contract")
    require(all(isinstance(k, str) and re.fullmatch(r"[A-Z]+(?:_[A-Z]+)*", k)
                and type(v) is int and 0 <= v < 90 for k, v in codes.items()),
            "Malformed symbolic/numeric exit code")
    require(len(set(codes.values())) == len(codes) and codes.get("VERIFIED") == 0,
            "Duplicate exit values or missing success code")
    require(type(contract["other_error"]) is int and contract["other_error"] == 90,
            "Unexpected generic error code")

    # Load the reviewed verifier only after baseline source pin validation below.
    cases = {}
    catalog_path = root / "demo-v2.2/tests/mutations"
    for path in sorted(catalog_path.glob("*.yaml")):
        case = load(root, path.relative_to(root).as_posix())
        require(set(case) == {"scenario", "operation", "role", "expectedExit"},
                "Mutation definition structure")
        require(case["scenario"] == path.stem and path.stem not in cases,
                "Duplicate mutation or file/scenario mismatch")
        require(type(case["expectedExit"]) is int, "Mutation exit is not an integer")
        cases[path.stem] = case
    require(bool(cases), "No mutation definitions")
    mappings = {}
    for requirement in items:
        require(not requirement["id"].startswith("M2-MUT-")
                or requirement["milestone"] == "M2", "Frozen M2 requirement must remain in M2")
        require(all(t in cases for t in requirement["related_tests"]), "Unknown related test")
        for implementation in requirement["implementation"]:
            bounded(root, implementation)
        if requirement["milestone"] != "M2":
            require(requirement["coverage"] != "covered" and not requirement["tests"],
                    "Unvalidated future requirement cannot be covered or claim acceptance tests")
            continue
        require(requirement["id"].startswith("M2-MUT-"), "Non-M2 ID in M2 denominator")
        require(requirement["coverage"] == "covered" and len(requirement["tests"]) == 1,
                "M2 completion requires exactly one test per covered requirement")
        for test in requirement["tests"]:
            scenario = test["scenario"]
            require(scenario in cases, "Referenced mutation is not defined: " + scenario)
            require(scenario not in mappings, "Mutation mapped to more than one M2 requirement")
            require(test["exit_name"] in codes and codes[test["exit_name"]] == test["exit_code"]
                    == cases[scenario]["expectedExit"], "Exit-code mismatch: " + scenario)
            mappings[scenario] = (requirement, test)
    require(set(mappings) == set(cases), "Mutation without an M2 requirement mapping")
    require(set(codes) == {"VERIFIED"} | {t["exit_name"] for _, t in mappings.values()},
            "Unmapped or missing exit-contract code")

    pin = requirements["baseline"]
    require(sha(bounded(root, pin["path"])) == pin["sha256"], "Baseline snapshot hash mismatch")
    observation = load(root, pin["path"])
    require(observation["repository"] == REPO and observation["commit"] == pin["commit"]
            and observation["run_id"] == pin["run_id"], "Baseline commit/run/repository mismatch")
    require(observation["kind"] == "reviewed-github-observation"
            and observation["production_acceptance"] is False, "Baseline authority overclaim")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", observation["golden_pin"]) is not None,
            "Invalid golden pin")
    pins = observation["source_pins"]
    paths = {p.relative_to(root).as_posix() for pattern in SOURCE_PATTERNS
             for p in root.glob(pattern) if p.is_file()}
    require(paths == set(pins), "Baseline source inventory changed; obtain new evidence")
    for path, expected in pins.items():
        require(sha(bounded(root, path)) == expected, "Stale baseline for changed source: " + path)

    spec = importlib.util.spec_from_file_location("crosswalk_demo_verify",
                                                root / "demo-v2.2/sentinel_demo/verify.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    predicate_types = {"manifest": verifier.ROOT_TYPE, "sbom": verifier.SBOM_TYPE,
                       "governance": verifier.GOVERNANCE_TYPE,
                       "provenance": verifier.PROVENANCE_TYPE}
    for scenario, (requirement, _) in mappings.items():
        require(requirement["implementation"] == ["demo-v2.2/sentinel_demo/verify.py"],
                "M2 rule must reference the reviewed verifier")
        require(callable(getattr(verifier, requirement["rule"], None)),
                "Unknown verifier rule: " + requirement["rule"])
        for evidence in requirement["evidence"]:
            # Root-manifest mutations use role=null in the existing catalog.
            require(evidence["role"] == (cases[scenario]["role"] or "manifest")
                    and evidence["predicate_type"] == predicate_types.get(evidence["role"]),
                    "Evidence role/predicate differs from verifier and mutation: " + scenario)
    for name, expected in codes.items():
        result = verifier._result(verifier.M2_PROFILE, "PASS" if expected == 0 else "BLOCKED",
                                  name, {}, "")
        require(result["exitCode"] == expected, "Verifier/exit contract drift: " + name)
    require(verifier._result(verifier.M2_PROFILE, "ERROR", "INTERNAL_ERROR", {}, "")[
        "exitCode"] == contract["other_error"], "Verifier error-code drift")

    expected_jobs = {"verify-golden", "SENTINEL demo gate"} | {
        "mutation-suite (" + s + ")" for s in cases}
    jobs = observation["jobs"]
    require(len(jobs) == len(expected_jobs)
            and {j["name"] for j in jobs} == expected_jobs, "Baseline job inventory mismatch")
    require(len({j["id"] for j in jobs}) == len(jobs), "Duplicate baseline job ID")
    run_url = BASE_URL + "/actions/runs/" + str(pin["run_id"])
    by_name = {j["name"]: j for j in jobs}
    for job in jobs:
        require(job["conclusion"] == "success", "Non-success baseline job")
        require(type(job["id"]) is int and job["id"] > 0
                and job["url"] == run_url + "/job/" + str(job["id"]), "Wrong baseline job URL")
    for scenario, (_, test) in mappings.items():
        lines = by_name["mutation-suite (" + scenario + ")"]["proof_lines"]
        matches = [re.search(r"\b" + re.escape(scenario)
                   + r": expected=(\d+) actual=(\d+) test=PASS$", line) for line in lines]
        matches = [m for m in matches if m]
        require(len(matches) == 1 and tuple(map(int, matches[0].groups()))
                == (test["exit_code"], test["exit_code"]), "Missing/mismatched CI proof: " + scenario)
    golden = "\n".join(by_name["verify-golden"]["proof_lines"])
    counts = re.findall(r"Ran (\d+) tests in", golden)
    require(len(counts) == 1 and type(observation["tests_passed"]) is int
            and int(counts[0]) == observation["tests_passed"], "Baseline test-count mismatch")
    require("GOLDEN PASS " + observation["golden_pin"] in golden, "No matching golden PASS")
    require(any(line.endswith("SENTINEL CI GATE: PASS") for line in
                by_name["SENTINEL demo gate"]["proof_lines"]), "No passing baseline gate")
    expected_artifacts = {"sentinel-m2-golden", "sentinel-m2-pin", "sentinel-demo-gate"} | {
        "sentinel-m2-" + scenario for scenario in cases}
    artifacts = observation["artifacts"]
    require(len(artifacts) == len(expected_artifacts)
            and {a["name"] for a in artifacts} == expected_artifacts, "Artifact inventory mismatch")
    require(all(a["commit"] == pin["commit"] and re.fullmatch(r"sha256:[0-9a-f]{64}", a["digest"])
                for a in artifacts), "Artifact head/digest mismatch")
    return requirements, observation, mappings


def render(requirements, observation, mappings):
    items = requirements["requirements"]
    counts = Counter(r["coverage"] for r in items)
    run_url = BASE_URL + "/actions/runs/" + str(observation["run_id"])
    jobs = {j["name"]: j for j in observation["jobs"]}
    mmd = ["flowchart LR", "  %% Generated M2 traceability; canonical v2.2 mapping is not established."]
    for index, (scenario, (requirement, test)) in enumerate(sorted(mappings.items()), 1):
        mmd.append(f'  R{index}["{requirement["id"]}"] --> T{index}["{scenario}"]'
                   f' --> E{index}["Exit {test["exit_code"]}: observed"]')
    diagram = "\n".join(mmd) + "\n"
    text = """# Evidence Bundle v2.2 Crosswalk

<!-- Generated by scripts/crosswalk.py generate. Edit requirements.yaml, then regenerate. -->

## Status and authority

**Draft · validated scope: M2 · M2 Coverage: COMPLETE · Overall v2.2 Coverage: INCOMPLETE · Production Acceptance: NOT ESTABLISHED.**

`requirements.yaml` is the reviewed source for this local crosswalk, in the strict
JSON subset of YAML. It is not the missing canonical Evidence-v2.2 specification.
`M2-MUT-*` IDs retain the existing M2 contract; `GOV-*` and `TR-*` are provisional
planning IDs. Every canonical reference is unassigned. Schema and consistency
validation cannot establish the truth of a requirement or independent CI authenticity.

Governance remains a **Governance-Mock**; provenance remains **Demo-Provenance**.
HSM, Azure Key Vault and production trust anchors have not been validated.

## Requirement → evidence → attestation → verification → test → CI proof

The evidence locator identifies a referenced CAS object or signed predicate,
not an unsigned convenience export such as `sbom.json`.

| Requirement | Implementation / rule | Evidence / attestation predicate | Mutation | Exit | Coverage | CI proof |
|---|---|---|---|---:|---|---|
"""
    for scenario, (requirement, test) in sorted(mappings.items(), key=lambda pair: pair[1][0]["id"]):
        evidence = "; ".join(plain(e["locator"]) + " — `" + plain(e["predicate_type"]) + "`"
                             for e in requirement["evidence"])
        implementation = requirement["implementation"][0]
        text += (f'| **{requirement["id"]}** {plain(requirement["title"])} '
                 f'| [{plain(requirement["rule"])}]({file_link(implementation)}) '
                 f'| {evidence} | [{scenario}](../../demo-v2.2/tests/mutations/{scenario}.yaml) '
                 f'| {test["exit_code"]} | Covered (M2 only) '
                 f'| [Expected rejection observed]({jobs["mutation-suite (" + scenario + ")"]["url"]}) |\n')
    text += "\n## Mutation → requirement (reverse mapping)\n\n| Mutation | Requirement | Symbolic code |\n|---|---|---|\n"
    for scenario, (requirement, test) in sorted(mappings.items()):
        text += f'| {scenario} | {requirement["id"]} | `{test["exit_name"]}` |\n'
    text += "\n## Future crosswalk items — excluded from the M2 denominator\n\n"
    text += "| Provisional ID | Requirement | Milestone | Coverage | Limitation / related evidence |\n|---|---|---|---|---|\n"
    for requirement in items:
        if requirement["milestone"] != "M2":
            related = ", ".join(requirement["related_tests"]) or "none"
            text += (f'| {requirement["id"]} | {plain(requirement["title"])} '
                     f'| {requirement["milestone"]} | {requirement["coverage"]} '
                     f'| {plain(requirement["limitation"])} Related demo test: {related}. |\n')
    text += (f'\n## Calculated coverage\n\nLocal inventory: **{len(items)}** requirements; '
             f'covered **{counts["covered"]}**, partial **{counts["partial"]}**, open **{counts["open"]}**.\n\n'
             f'M2: **{sum(r["milestone"] == "M2" and r["coverage"] == "covered" for r in items)}'
             f'/{sum(r["milestone"] == "M2" for r in items)}** requirements '
             'mapped and observed. Full v2.2: **INCOMPLETE; canonical denominator unknown**. '
             'No fabricated 24-requirement count or production coverage percentage.\n\n'
             f'Baseline [run {observation["run_id"]}]({run_url}), commit '
             f'`{observation["commit"]}`: **{observation["tests_passed"]} tests**, '
             f'**{len(observation["jobs"])} successful jobs**, **{len(mappings)} expected rejections**, '
             'Golden PASS. Current CI results are separate from this frozen baseline.\n\n'
             '## Traceability diagram\n\n[Mermaid source](crosswalk.mmd). The diagram is a view, not independent evidence.\n\n'
             '```mermaid\n' + diagram + '```\n\n'
             '## Review and evidence boundaries\n\n'
             '- [M2 baseline](../acceptance/m2-baseline.md) identifies the tested commit and artifact digests.\n'
             '- [M2 mutation contract](../mutation-coverage-matrix.md) defines the exact rejection scope.\n'
             '- [M3 Governance Realization plan](m3-governance-realization.md) is planning, not implementation.\n'
             '- [CI and merge enforcement](review-and-gates.md) distinguishes a green check from server-side protection.\n'
             '- The offline validator checks a reviewed GitHub observation and pinned source files; it does not contact GitHub or verify an independently signed CI receipt.\n'
             '- A coordinated edit of all contracts and the validator can change the rules; independent review and server-side protection remain necessary.\n')
    baseline = ("# Evidence Bundle v2.2 — Milestone M2 Baseline\n\n"
                "<!-- Generated from the reviewed m2-observation.json snapshot. -->\n\n"
                f'Baseline ID: **M2-{observation["date"]}-{observation["commit"][:7]}**. '
                'Architecture Demonstrator; technical M2 reference, human acceptance pending.\n\n'
                '| Field | Frozen value |\n|---|---|\n'
                f'| Date | {observation["date"]} (UTC) |\n'
                f'| Commit | [`{observation["commit"]}`]({BASE_URL}/commit/{observation["commit"]}) |\n'
                f'| Source tree | `{observation["tree"]}` |\n'
                f'| PR | [#69 M1]({BASE_URL}/pull/69), [#70 M2]({BASE_URL}/pull/70), both separate from merge approval |\n'
                f'| Workflow Run | [{observation["run_id"]}]({run_url}) |\n'
                f'| Tests | {observation["tests_passed"]}/{observation["tests_passed"]} PASS |\n'
                f'| Jobs | {len(observation["jobs"])}/{len(observation["jobs"])} PASS |\n'
                f'| Mutations | {len(mappings)}/{len(mappings)} expected rejection codes observed; all tests PASS |\n'
                f'| Coverage | COMPLETE (M2 Scope); overall v2.2 INCOMPLETE |\n'
                f'| Golden | PASS; `{observation["golden_pin"]}` |\n\n'
                '## Versioned observation\n\n'
                '[m2-observation.json](../evidence-bundle-v2.2/evidence/m2-observation.json) '
                'preserves job identities, selected public log observations, artifact digests and '
                f'{len(observation["source_pins"])} source-file pins. These pins must match the '
                'current demo before this baseline can support its crosswalk. New runtime/code/catalog '
                'changes need a new reviewed run and observation; documentation-only changes do not '
                'inherit a green CI result automatically.\n\n'
                'This is a versioned reference, not WORM storage or a signed independent CI receipt. '
                'The full raw artifact ZIPs and logs are not committed. GitHub artifact expiry starts at '
                f'{min(a["expires_at"] for a in observation["artifacts"])}; their digests and references remain here, but do not preserve their bytes. '
                'A durable external archive remains open. No release or Git tag was created.\n\n'
                '## Artifact inventory\n\n| Artifact | ID | SHA-256 archive digest | Expires (UTC) |\n|---|---:|---|---|\n')
    for artifact in sorted(observation["artifacts"], key=lambda a: a["name"]):
        baseline += (f'| {artifact["name"]} | {artifact["id"]} | `{artifact["digest"]}` '
                     f'| {artifact["expires_at"]} |\n')
    baseline += ("\n## Remaining limits\n\nGovernance Mock; Demo-Provenance; missing canonical v2.2 crosswalk; "
                 "no HSM, Azure Key Vault or production trust validation. `productionAcceptance:false`. "
                 "M3 Governance Realization, M4 trust paths and M5 full v2.2 acceptance remain open.\n")
    return {FOLDER + "/crosswalk.md": text, FOLDER + "/crosswalk.mmd": diagram,
            "docs/acceptance/m2-baseline.md": baseline}


def run(root, generate=False):
    requirements, observation, mappings = validate_data(root)
    documents = render(requirements, observation, mappings)
    for relative, content in documents.items():
        if generate:
            path = root / relative
            require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
                    "Unsafe generated output")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        else:
            require(bounded(root, relative) == content.encode(), "Generated view is stale: " + relative)
    counts = Counter(r["coverage"] for r in requirements["requirements"])
    return {"status": "PASS", "requirements": sum(counts.values()), **dict(counts),
            "mutationScenarios": len(mappings), "m2Scope": "COMPLETE", "v22Overall": "INCOMPLETE",
            "productionAcceptance": False, "baselineCommit": observation["commit"],
            "baselineRun": observation["run_id"], "exitCode": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "generate"])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run(args.root.resolve(), args.command == "generate")
    except Invalid as exc:
        result = {"status": "FAIL", "reason": str(exc), "exitCode": 1, "productionAcceptance": False}
    except Exception as exc:
        result = {"status": "ERROR", "reason": str(exc), "exitCode": 2, "productionAcceptance": False}
    if args.output:
        try:
            sys.path.insert(0, str(ROOT / "demo-v2.2"))
            from sentinel_demo.cli import atomic_json
            atomic_json(args.output, result)
        except Exception as exc:
            print("Crosswalk report error:", str(exc), file=sys.stderr)
            return 2
    print(json.dumps(result, sort_keys=True))
    return result["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
