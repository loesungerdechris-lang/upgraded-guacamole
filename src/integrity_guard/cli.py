"""Local CLI. Its OS exit code, not report text, controls the calling process."""

from __future__ import annotations

import argparse
from pathlib import Path

from .io import read_result, write_result
from .policy import policy_digest
from .semantic_validation import validate_result


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "Integrity Guard: invalid command arguments.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(description="Deterministic pre-merge static integrity checks")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--repo", type=Path, required=True)
    scan.add_argument("--base", required=True)
    scan.add_argument("--head", required=True)
    scan.add_argument("--repository", required=True)
    scan.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("result", type=Path)
    validate.add_argument("--base", required=True)
    validate.add_argument("--head", required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--process-exit-code", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        expected = {
            "repository": args.repository,
            "base_sha": args.base,
            "head_sha": args.head,
            "policy_digest": policy_digest(),
        }
        if args.command == "scan":
            from .scanner import scan_repository

            # Refuse stale output. Each caller must allocate a new output path.
            if args.output.exists() or args.output.is_symlink():
                print("Integrity Guard: FAIL (output path already exists).")
                return 30
            result = scan_repository(args.repo, args.base, args.head, args.repository)
            validate_result(result, expected_context=expected)
            write_result(args.output, result)
        else:
            result = read_result(args.result)
            validate_result(
                result, expected_context=expected, process_exit_code=args.process_exit_code
            )
        print(f"Integrity Guard: {result['status']}; exit={result['exit_code']}.")
        return result["exit_code"]
    except Exception:
        # Raw exceptions may contain source lines, paths, secrets or server responses.
        print("Integrity Guard: FAIL (invalid or unavailable result).")
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
