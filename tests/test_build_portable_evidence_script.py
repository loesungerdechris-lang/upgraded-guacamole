from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from sentinel_core.portable_evidence import PortableEvidenceError

_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "azure"
    / "build-portable-evidence.py"
)
_SPEC = importlib.util.spec_from_file_location("build_portable_evidence_script", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _binding() -> dict[str, object]:
    return {
        "kid": (
            "https://sentinel-marketing.vault.azure.net/keys/"
            "campaign-release/11111111111111111111111111111111"
        ),
        "role": "marketing_lead",
        "status": "active",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "A" * 43,
            "y": "B" * 43,
            "ext": True,
        },
    }


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_load_binding_accepts_only_exact_public_outer_shape(tmp_path: Path) -> None:
    path = _write(tmp_path / "binding.json", _binding())
    assert _MODULE._load_binding(path) == _binding()

    value = {**_binding(), "client_secret": "forbidden"}
    path = _write(tmp_path / "extra.json", value)
    with pytest.raises(PortableEvidenceError, match="contain exactly"):
        _MODULE._load_binding(path)


def test_load_binding_rejects_symlink_and_oversized_file(tmp_path: Path) -> None:
    source = _write(tmp_path / "source.json", _binding())
    link = tmp_path / "binding-link.json"
    link.symlink_to(source)
    with pytest.raises(PortableEvidenceError, match="regular file"):
        _MODULE._load_binding(link)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (_MODULE._MAX_BINDING_BYTES + 1) + b"}")
    with pytest.raises(PortableEvidenceError, match="outside the allowed range"):
        _MODULE._load_binding(oversized)


def test_parser_rejects_public_class_c_before_execution() -> None:
    arguments = [
        "--binding",
        "binding.json",
        "--output-dir",
        "out",
        "--repository",
        "owner/repo",
        "--commit-sha",
        "a" * 40,
        "--workflow",
        "Portable Evidence",
        "--run-id",
        "1",
        "--run-attempt",
        "1",
        "--created-at",
        "2026-07-05T13:45:00Z",
        "--receipt-id",
        "REC-1",
        "--entity-type",
        "strategic_campaign",
        "--entity-id",
        "CAMPAIGN-1",
        "--release-class",
        "C",
        "--policy-id",
        "policy",
        "--policy-version",
        "1.0.0",
        "--required-role",
        "legal_officer",
        "--min-signatures",
        "1",
    ]
    with pytest.raises(SystemExit):
        _MODULE._parser().parse_args(arguments)
