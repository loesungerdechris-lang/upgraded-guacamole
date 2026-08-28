#!/usr/bin/env python3
"""Build one public multi-signature SENTINEL portable evidence bundle."""

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
from sentinel_core.portable_evidence import (
    PortableEvidenceContext,
    PortableEvidenceError,
    PortableSignerBinding,
    build_portable_evidence_bundle,
    write_portable_evidence_bundle,
)

_MAX_BINDING_BYTES = 131_072
_MAX_BINDINGS = 16
_ZERO_HASH = "sha256:" + "0" * 64
_BINDING_FIELDS = frozenset(
    {"kid", "role", "status", "not_before", "not_after", "jwk"}
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a complete SENTINEL release receipt, sign its exact canonical "
            "payload through an authenticated Azure CLI context, independently "
            "verify every signature and emit a five-file portable evidence bundle."
        )
    )
    parser.add_argument(
        "--binding",
        required=True,
        action="append",
        type=Path,
        help=(
            "Public signer binding JSON. Repeat once per required signing key. "
            "The file may contain only kid, role, status, not_before, not_after and jwk."
        ),
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--entity-type", required=True)
    parser.add_argument("--entity-id", required=True)
    parser.add_argument("--release-class", required=True, choices=("A", "B"))
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--policy-version", required=True)
    parser.add_argument(
        "--required-role",
        required=True,
        action="append",
        help="Required signer role. Repeat once per required role.",
    )
    parser.add_argument("--min-signatures", required=True, type=int)
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--previous-hash", default=_ZERO_HASH)
    return parser


def _load_binding(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PortableEvidenceError("public signer binding must be a regular file")
    try:
        size = path.stat().st_size
    except OSError:
        raise PortableEvidenceError(
            "public signer binding could not be inspected"
        ) from None
    if size <= 0 or size > _MAX_BINDING_BYTES:
        raise PortableEvidenceError(
            "public signer binding size is outside the allowed range"
        )
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(text)
    except (OSError, UnicodeError, ValueError):
        raise PortableEvidenceError(
            "public signer binding is not valid UTF-8 JSON"
        ) from None
    if not isinstance(value, dict):
        raise PortableEvidenceError("public signer binding must be a JSON object")
    if frozenset(value) != _BINDING_FIELDS:
        raise PortableEvidenceError(
            "public signer binding must contain exactly kid, role, status, "
            "not_before, not_after and jwk"
        )
    return value


def _bindings(
    paths: Sequence[Path],
    signer: AzureCliKeyVaultDigestSigner,
) -> list[PortableSignerBinding]:
    if not paths or len(paths) > _MAX_BINDINGS:
        raise PortableEvidenceError("public signer binding count is invalid")
    bindings: list[PortableSignerBinding] = []
    for path in paths:
        value = _load_binding(path)
        bindings.append(
            PortableSignerBinding(
                key_id=value.get("kid"),
                signer_role=value.get("role"),
                public_jwk=value.get("jwk"),
                status=value.get("status"),
                not_before=value.get("not_before"),
                not_after=value.get("not_after"),
                signer=signer,
            )
        )
    return bindings


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        signer = AzureCliKeyVaultDigestSigner()
        context = PortableEvidenceContext(
            repository=args.repository,
            commit_sha=args.commit_sha,
            workflow=args.workflow,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            created_at=args.created_at,
        )
        bundle = build_portable_evidence_bundle(
            context=context,
            receipt_id=args.receipt_id,
            entity_type=args.entity_type,
            entity_id=args.entity_id,
            release_class=args.release_class,
            policy_id=args.policy_id,
            policy_version=args.policy_version,
            required_roles=args.required_role,
            min_signatures=args.min_signatures,
            signer_bindings=_bindings(args.binding, signer),
            sequence=args.sequence,
            previous_hash=args.previous_hash,
        )
        output = write_portable_evidence_bundle(bundle, args.output_dir)
    except (AzureCliSigningError, PortableEvidenceError) as exc:
        print(f"SENTINEL portable evidence failed: {exc}", file=sys.stderr)
        return 1

    summary = {
        "status": bundle.verification_report["status"],
        "verified": bundle.verification_report["verified"],
        "receipt_hash": bundle.verification_report["receipt_hash"],
        "valid_signatures": bundle.verification_report["valid_signatures"],
        "required_signatures": bundle.verification_report["required_signatures"],
        "output_directory": str(output),
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
