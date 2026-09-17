#!/usr/bin/env python3
"""Close the technical CI gate unless GitHub reports matrix success."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_demo.cli import atomic_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance-result", required=True)
    parser.add_argument("--golden-result", default="success")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    accepted = args.acceptance_result == "success" and args.golden_result == "success"
    result = {
        "profile": "sentinel-demo-ci-gate/v1",
        "acceptanceResult": args.acceptance_result,
        "goldenResult": args.golden_result,
        "status": "PASS" if accepted else "BLOCKED",
        "reasonCode": "ACCEPTANCE_SUCCESSFUL" if accepted else "ACCEPTANCE_NOT_SUCCESSFUL",
        "exitCode": 0 if accepted else 1,
        "productionAcceptance": False,
    }
    try:
        atomic_json(args.output, result)
    except OSError as exc:
        print("Cannot persist CI decision:", str(exc), file=sys.stderr)
        return 4
    print("SENTINEL CI GATE:", result["status"])
    return result["exitCode"]


if __name__ == "__main__":
    sys.exit(main())
