"""Schema loading and JSON validation for SENTINEL evidence records."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


class SchemaValidationError(ValueError):
    """Raised when an evidence record does not match the configured schema."""


def repository_root() -> Path:
    """Return the repository root based on the package location."""

    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_evidence_schema() -> dict[str, Any]:
    """Load the bootstrap evidence JSON schema from the repository."""

    schema_path = repository_root() / "schemas" / "evidence.schema.json"
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise SchemaValidationError("Evidence schema root must be a JSON object")
    return schema


@lru_cache(maxsize=1)
def evidence_validator() -> Draft202012Validator:
    """Return a cached JSON Schema validator for evidence records."""

    return Draft202012Validator(load_evidence_schema())


def validate_evidence_schema(record: dict[str, Any]) -> None:
    """Validate an evidence record against the bootstrap schema.

    Raises:
        SchemaValidationError: if validation fails.
    """

    validator = evidence_validator()
    errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.path) or "<root>"
        raise SchemaValidationError(f"Schema validation failed at {location}: {first.message}")
