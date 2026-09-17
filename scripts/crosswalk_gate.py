#!/usr/bin/env python3
"""Only exact success from every named prerequisite opens a technical gate."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demo-v2.2"))
from sentinel_demo.cli import atomic_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    states = {"validation": args.validation}
    if args.evidence is not None:
        states["evidence"] = args.evidence
    accepted = all(state == "success" for state in states.values())
    result = {"status": "PASS" if accepted else "BLOCKED", "prerequisites": states,
              "productionAcceptance": False, "exitCode": 0 if accepted else 1}
    try:
        atomic_json(args.output, result)
    except OSError as exc:
        print("Gate report error:", str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return result["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
