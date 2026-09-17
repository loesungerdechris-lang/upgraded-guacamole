#!/usr/bin/env python3
"""Build and verify one live M2 golden bundle, then seal the finished export."""
import argparse
from pathlib import Path
import sys

from run_demo import run, M2_PROFILE, ROOT
from sentinel_demo.mutations import seal, catalog
from sentinel_demo.cli import atomic_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, default=ROOT / ".tools")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pin-output", type=Path, required=True)
    args = parser.parse_args()
    output, pin_output = args.output.resolve(), args.pin_output.resolve()
    if pin_output.is_relative_to(output):
        parser.error("Store the trusted pin outside the sealed golden directory")
    run(args.tools.resolve(), output, "happy-path", profile=M2_PROFILE)
    pin = seal(output)
    atomic_json(pin_output, {"goldenPin": pin, "scenarios": sorted(catalog())})
    print("GOLDEN PASS", pin)
    return 0


if __name__ == "__main__":
    sys.exit(main())
