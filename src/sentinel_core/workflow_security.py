"""Fail-closed validation for GitHub Actions dependency and checkout syntax."""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

_REMOTE_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
_LOCAL_ACTION_RE = re.compile(r"^\./[^\s#]+$")
_USES_RE = re.compile(
    r"^(?P<indent>\s*)(?P<dash>-\s+)?uses:\s+(?P<value>[^\s#]+)\s*$"
)
_WITH_RE = re.compile(r"^(?P<indent>\s*)with:\s*$")
_PERSIST_RE = re.compile(
    r"^(?P<indent>\s*)persist-credentials:\s+(?P<value>true|false)\s*$"
)
_STEP_START_RE = re.compile(r"^(?P<indent>\s*)-\s+")
_USES_KEY_RE = re.compile(r"(?:^|[\s{,])(?:['\"]uses['\"]|uses)\s*:")
_PERSIST_KEY_RE = re.compile(
    r"(?:^|[\s{,])(?:['\"]persist-credentials['\"]|persist-credentials)\s*:"
)
_CHECKOUT_RE = re.compile(r"^actions/checkout@[0-9a-fA-F]{40}$")


def _without_yaml_comment(line: str) -> str:
    """Remove a YAML comment marker that appears outside quoted text."""

    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
            continue
        if quote == char:
            quote = None
            continue
        if quote is None and char == "#":
            return line[:index].rstrip()
    return line.rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _step_bounds(lines: Sequence[str], uses_index: int) -> tuple[int, int] | None:
    """Return the containing block-style step bounds for one uses line."""

    uses_code = _without_yaml_comment(lines[uses_index])
    uses_match = _USES_RE.fullmatch(uses_code)
    if uses_match is None:
        return None

    if uses_match.group("dash") is not None:
        start = uses_index
        step_indent = len(uses_match.group("indent"))
    else:
        uses_indent = len(uses_match.group("indent"))
        start = -1
        step_indent = -1
        for index in range(uses_index - 1, -1, -1):
            code = _without_yaml_comment(lines[index])
            if not code.strip():
                continue
            match = _STEP_START_RE.match(code)
            if match is not None and len(match.group("indent")) < uses_indent:
                start = index
                step_indent = len(match.group("indent"))
                break
            if _indent(code) < uses_indent:
                break
        if start < 0:
            return None

    end = len(lines)
    for index in range(start + 1, len(lines)):
        code = _without_yaml_comment(lines[index])
        if not code.strip():
            continue
        if _indent(code) < step_indent:
            end = index
            break
        match = _STEP_START_RE.match(code)
        if match is not None and len(match.group("indent")) == step_indent:
            end = index
            break
    return start, end


def _mapping_bounds(lines: Sequence[str], start: int, end: int) -> tuple[int, int]:
    """Return the content bounds of one exact block-style mapping key."""

    key_indent = _indent(_without_yaml_comment(lines[start]))
    block_end = end
    for index in range(start + 1, end):
        code = _without_yaml_comment(lines[index])
        if not code.strip():
            continue
        if _indent(code) <= key_indent:
            block_end = index
            break
    return start + 1, block_end


def _validate_checkout_inputs(
    lines: Sequence[str],
    *,
    source: str,
    step_start: int,
    step_end: int,
    uses_line: int,
    uses_indent: int,
) -> list[str]:
    """Require exactly one false persist-credentials value under checkout with."""

    failures: list[str] = []
    with_lines: list[int] = []
    all_persist: list[tuple[int, int, str]] = []

    for index in range(step_start, step_end):
        code = _without_yaml_comment(lines[index])
        with_match = _WITH_RE.fullmatch(code)
        if with_match is not None and len(with_match.group("indent")) == uses_indent:
            with_lines.append(index)
        persist_match = _PERSIST_RE.fullmatch(code)
        if persist_match is not None:
            all_persist.append(
                (
                    index,
                    len(persist_match.group("indent")),
                    persist_match.group("value"),
                )
            )

    if len(with_lines) != 1:
        failures.append(
            f"{source}:{uses_line}: checkout must contain exactly one block-style with mapping"
        )
        return failures

    with_line = with_lines[0]
    content_start, content_end = _mapping_bounds(lines, with_line, step_end)
    content_lines = [
        index
        for index in range(content_start, content_end)
        if _without_yaml_comment(lines[index]).strip()
    ]
    if not content_lines:
        failures.append(
            f"{source}:{uses_line}: checkout with mapping must contain persist-credentials: false"
        )
        return failures

    first_level_indent = min(
        _indent(_without_yaml_comment(lines[index])) for index in content_lines
    )
    direct_persist = [
        (index, value)
        for index, indent, value in all_persist
        if content_start <= index < content_end and indent == first_level_indent
    ]
    outside_persist = [
        index
        for index, _, _ in all_persist
        if not (content_start <= index < content_end)
    ]

    if outside_persist:
        failures.append(
            f"{source}:{outside_persist[0] + 1}: persist-credentials must be inside checkout with"
        )
    if len(direct_persist) != 1 or direct_persist[0][1] != "false":
        failures.append(
            f"{source}:{uses_line}: checkout must set persist-credentials: false exactly once "
            "as a direct with input"
        )
    return failures


def validate_workflow_text(text: str, *, source: str = "<memory>") -> list[str]:
    """Return all fail-closed workflow validation errors."""

    lines = text.splitlines()
    failures: list[str] = []
    allowed_uses: list[int] = []

    for index, raw_line in enumerate(lines, start=1):
        code = _without_yaml_comment(raw_line)
        if not code.strip():
            continue

        uses_match = _USES_RE.fullmatch(code)
        has_uses_key = _USES_KEY_RE.search(code) is not None
        if has_uses_key and uses_match is None:
            failures.append(
                f"{source}:{index}: unsupported or ambiguous uses syntax; use block-style `uses: value`"
            )
        elif uses_match is not None:
            value = uses_match.group("value")
            allowed_uses.append(index - 1)
            if value.startswith("./"):
                if _LOCAL_ACTION_RE.fullmatch(value) is None:
                    failures.append(f"{source}:{index}: invalid local action path: {value}")
            elif _REMOTE_ACTION_RE.fullmatch(value) is None:
                failures.append(
                    f"{source}:{index}: remote action is not pinned to a 40-hex commit: {value}"
                )

        persist_match = _PERSIST_RE.fullmatch(code)
        has_persist_key = _PERSIST_KEY_RE.search(code) is not None
        if has_persist_key and persist_match is None:
            failures.append(
                f"{source}:{index}: unsupported or ambiguous persist-credentials syntax"
            )

    checked_steps: set[tuple[int, int]] = set()
    for uses_index in allowed_uses:
        bounds = _step_bounds(lines, uses_index)
        if bounds is None or bounds in checked_steps:
            continue
        checked_steps.add(bounds)
        start, end = bounds
        step_uses: list[tuple[int, int, str]] = []

        for block_index in range(start, end):
            code = _without_yaml_comment(lines[block_index])
            block_uses = _USES_RE.fullmatch(code)
            if block_uses is not None:
                step_uses.append(
                    (
                        block_index + 1,
                        len(block_uses.group("indent")),
                        block_uses.group("value"),
                    )
                )

        if len(step_uses) > 1:
            locations = ", ".join(str(line) for line, _, _ in step_uses)
            failures.append(f"{source}:{locations}: step contains duplicate uses keys")

        for uses_line, uses_indent, value in step_uses:
            if _CHECKOUT_RE.fullmatch(value) is None:
                continue
            failures.extend(
                _validate_checkout_inputs(
                    lines,
                    source=source,
                    step_start=start,
                    step_end=end,
                    uses_line=uses_line,
                    uses_indent=uses_indent,
                )
            )

    return failures


def workflow_paths(inputs: Iterable[Path]) -> list[Path]:
    """Expand workflow files and directories deterministically."""

    resolved: set[Path] = set()
    for item in inputs:
        if item.is_dir():
            resolved.update(item.glob("*.yml"))
            resolved.update(item.glob("*.yaml"))
        elif item.suffix in {".yml", ".yaml"}:
            resolved.add(item)
    return sorted(resolved)


def validate_workflow_paths(paths: Iterable[Path]) -> list[str]:
    """Validate all supplied workflow paths."""

    failures: list[str] = []
    for path in workflow_paths(paths):
        failures.extend(
            validate_workflow_text(path.read_text(encoding="utf-8"), source=str(path))
        )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fail-closed workflow validator."""

    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    failures = validate_workflow_paths(args.paths)
    if failures:
        parser.exit(1, "\n".join(failures) + "\n")
    print(f"validated {len(workflow_paths(args.paths))} workflow files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
