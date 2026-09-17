#!/usr/bin/env python3
"""Assert actual verifier process codes; mutation failures alone are not success."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel_demo.mutations import check_golden, catalog, inventory
from sentinel_demo.cli import atomic_json


def execute(golden, pin, output, cosign, selected="all"):
    if golden.is_relative_to(output) or output.is_relative_to(golden):
        raise ValueError("Suite output and golden bundle must not overlap")
    check_golden(golden, pin)
    cases = catalog()
    names = sorted(cases) if selected == "all" else [selected]
    if any(name not in cases for name in names):
        raise ValueError("Unknown scenario")
    output.mkdir(parents=True, exist_ok=True)

    def verify(directory, report):
        proc = subprocess.run([sys.executable, "-m", "sentinel_demo", "verify-bundle",
                               "--request", str(directory / "verification-request.json"),
                               "--policy", str(directory / "governance-policy.yml"),
                               "--key", str(directory / "demo.pub"), "--offline", str(directory / "bundle"),
                               "--cosign", str(cosign), "--output", str(report)],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)
        report.with_suffix(".log").write_text(proc.stdout + proc.stderr)
        return proc.returncode

    if verify(golden, output / "golden-before.json") != 0:
        raise RuntimeError("Golden verification did not return zero")
    results = []
    for name in names:
        work = output / name
        command = [sys.executable, "-m", "sentinel_demo", "mutate", "--golden", str(golden),
                   "--golden-pin", pin, "--scenario", name, "--output", str(work)]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, timeout=60)
        first = inventory(work)
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, timeout=60)
        if inventory(work) != first:
            raise RuntimeError("Mutation is not idempotent: " + name)
        actual = verify(work, output / (name + ".json"))
        expected = cases[name]["expectedExit"]
        accepted = actual == expected
        results.append({"scenario": name, "expectedExit": expected, "actualExit": actual,
                        "accepted": accepted, "idempotent": True})
        print(f"{name}: expected={expected} actual={actual} test={'PASS' if accepted else 'FAIL'}", flush=True)
    check_golden(golden, pin)
    golden_after = verify(golden, output / "golden-after.json")
    accepted = golden_after == 0 and all(item["accepted"] for item in results)
    atomic_json(output / "mutation-results.json", {"goldenPin": pin, "goldenAfterExit": golden_after,
                "scenarios": results, "status": "PASS" if accepted else "FAIL", "productionAcceptance": False})
    return 0 if accepted else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--golden", type=Path, required=True)
    parser.add_argument("--golden-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--scenario", default="all")
    args = parser.parse_args()
    try:
        return execute(args.golden.resolve(), args.golden_pin, args.output.resolve(),
                       args.cosign.resolve(), args.scenario)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print("MUTATION SUITE ERROR:", str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
