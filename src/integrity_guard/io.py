"""Bounded, strict result transport. Never include input values in errors."""

from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any

MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32


class InvalidResult(ValueError):
    """An untrusted report could not be decoded safely."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidResult("Duplicate JSON key.")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise InvalidResult("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise InvalidResult("Non-finite JSON number.")
    return number


def _check_depth(data: bytes) -> None:
    depth = 0
    quoted = escaped = False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise InvalidResult("JSON nesting exceeds the configured limit.")
        elif char in (93, 125):
            depth -= 1


def decode_json(data: bytes) -> Any:
    if len(data) > MAX_RESULT_BYTES:
        raise InvalidResult("JSON exceeds the configured size limit.")
    try:
        _check_depth(data)
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidResult("Invalid JSON input.") from exc


def read_result(path: Path) -> dict:
    """Read a regular report; a missing/oversized/symlink report is not a pass."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            import stat

            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise InvalidResult("Result is not a regular file.")
            data = stream.read(MAX_RESULT_BYTES + 1)
        result = decode_json(data)
        if not isinstance(result, dict):
            raise InvalidResult("Result must be a JSON object.")
        return result
    except (OSError, ValueError) as exc:
        raise InvalidResult("Result unavailable or invalid.") from exc


def write_result(path: Path, result: dict) -> None:
    """Publish one complete report atomically with private local permissions."""
    data = (json.dumps(result, ensure_ascii=True, allow_nan=False, sort_keys=True) + "\n").encode()
    if len(data) > MAX_RESULT_BYTES:
        raise InvalidResult("Result exceeds the configured size limit.")
    descriptor, name = tempfile.mkstemp(prefix=".guard-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
