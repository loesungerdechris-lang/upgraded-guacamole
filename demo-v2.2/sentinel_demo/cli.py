"""Read-only CLI. JSON reports are written atomically; exit zero requires PASS."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .store import DirectoryStore, RegistryStore, MAX_BLOB
from .verify import verify_bundle


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def _read_input(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_BLOB + 1)
    if len(data) > MAX_BLOB:
        raise ValueError("Input exceeds demo size limit")
    return data


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".sentinel-", delete=False) as stream:
            name = stream.name
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-bundle")
    verify.add_argument("--request", required=True, type=Path)
    verify.add_argument("--policy", required=True, type=Path)
    verify.add_argument("--key", required=True, type=Path)
    verify.add_argument("--offline", type=Path)
    verify.add_argument("--cosign", default="cosign")
    verify.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        request = json.loads(_read_input(args.request), object_pairs_hook=_unique,
                             parse_constant=_reject_constant)
        if not isinstance(request, dict) or not isinstance(request.get("image"), str):
            raise ValueError("Expected a request object with an image reference")
        store = DirectoryStore(args.offline) if args.offline else RegistryStore(request["image"].split("@")[0])
        result = verify_bundle(request, _read_input(args.policy), args.key, store, args.cosign)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"profile": "sentinel-demo-mvp/v0.1", "status": "ERROR", "exitCode": 4,
                  "reasonCodes": ["INPUT_ERROR"], "checks": [], "productionAcceptance": False,
                  "limitations": [str(exc)]}
    try:
        atomic_json(args.output, result)
    except OSError as exc:
        print("Cannot persist verification result:", str(exc), file=sys.stderr)
        return 4
    print("SENTINEL VERIFY-BUNDLE — DEMO ONLY")
    print("Image Digest:", result.get("imageDigest", "unavailable"))
    print("Bundle Status:", result["status"])
    print("Reasons:", ", ".join(result["reasonCodes"]))
    print("Production acceptance: false; mock governance; no compliance assessment")
    print("Exit Code:", result["exitCode"])
    return result["exitCode"]


if __name__ == "__main__":
    sys.exit(main())
