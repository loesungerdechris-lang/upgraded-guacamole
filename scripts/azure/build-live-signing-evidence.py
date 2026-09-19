#!/usr/bin/env python3
"""Build one public SENTINEL live-signing evidence bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from sentinel_core.azure_cli_signing import (
    AzureCliKeyVaultDigestSigner,
    AzureCliSigningError,
)
from sentinel_core.live_evidence import (
    LiveEvidenceContext,
    LiveEvidenceError,
    PublicKeyMetadata,
    PublicTrustPolicy,
    build_live_evidence_bundle,
    write_live_evidence_bundle,
)

_MAX_METADATA_BYTES = 131_072


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Sign a deterministic SENTINEL receipt through an authenticated "
            "Azure CLI context and emit only independently verified public evidence."
        )
    )
    parser.add_argument("--key-metadata", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--not-before", required=True)
    parser.add_argument("--not-after", required=True)
    return parser


def _load_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise LiveEvidenceError("public key metadata must be a regular file")
    try:
        size = path.stat().st_size
    except OSError:
        raise LiveEvidenceError("public key metadata could not be inspected") from None
    if size <= 0 or size > _MAX_METADATA_BYTES:
        raise LiveEvidenceError("public key metadata size is outside the allowed range")

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise LiveEvidenceError("public key metadata is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise LiveEvidenceError("public key metadata must be a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        metadata = PublicKeyMetadata.from_mapping(_load_metadata(args.key_metadata))
        context = LiveEvidenceContext(
            repository=args.repository,
            commit_sha=args.commit_sha,
            workflow=args.workflow,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            created_at=args.created_at,
        )
        trust_policy = PublicTrustPolicy(
            role="release_signer",
            status="active",
            not_before=args.not_before,
            not_after=args.not_after,
        )
        signer = AzureCliKeyVaultDigestSigner()
        bundle = build_live_evidence_bundle(
            metadata=metadata,
            context=context,
            trust_policy=trust_policy,
            signer=signer,
        )
        output = write_live_evidence_bundle(bundle, args.output_dir)
    except (AzureCliSigningError, LiveEvidenceError) as exc:
        print(f"SENTINEL live evidence failed: {exc}", file=sys.stderr)
        return 1

    summary = {
        "status": bundle.verification_report["status"],
        "verified": bundle.verification_report["verified"],
        "receipt_hash": bundle.verification_report["receipt_hash"],
        "output_directory": str(output),
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
