"""Bounded, read-only scanning of committed Git objects.

The scanner never checks out, imports, or executes the proposed tree. It covers
new/changed UTF-8 text blobs and a deliberately small set of credential patterns;
it is not a general vulnerability scanner or a credential-validity service.
Unsupported content is an incomplete scan, never a clean result.
"""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .policy import MAX_FINDINGS, REQUIRED_CHECK_IDS, policy_digest

MAX_FILES = 1_000
MAX_FILE_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 20 * 1024 * 1024
MAX_PATH_BYTES = 1_024
COMMAND_TIMEOUT_SECONDS = 10.0
SCAN_TIMEOUT_SECONDS = 120.0

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z")
_RAW_HEADER = re.compile(
    rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDT])\Z"
)
_PRIVATE_KEY = re.compile(
    rb"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY|PRIVATE KEY|"
    rb"PGP PRIVATE KEY BLOCK)-----"
)
_CREDENTIALS = (
    ("GitHub token", re.compile(rb"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])")),
    (
        "GitHub fine-grained token",
        re.compile(rb"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])"),
    ),
    ("AWS access key ID", re.compile(rb"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")),
    ("Google API key", re.compile(rb"(?<![A-Za-z0-9_])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")),
    ("Stripe live key", re.compile(rb"(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{24,}(?![A-Za-z0-9])")),
)
_PROTECTED_FILES = frozenset({
    ".github/CODEOWNERS", "pyproject.toml", "requirements/integrity-guard.txt",
    "tests/__init__.py", "src/__init__.py",
})
# Pytest loads conftest.py at any directory depth. Python startup hooks and
# test/build configuration are also executable policy inputs, not ordinary
# source changes. This is a bounded trust boundary, not a proof of test coverage.
_PROTECTED_BASENAMES = frozenset({
    "conftest.py", "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml",
    "setup.cfg", "setup.py", "tox.ini", "sitecustomize.py", "usercustomize.py",
})
_PROTECTED_PREFIXES = ("src/integrity_guard/", ".github/workflows/")
_WRITE_ALL = re.compile(r"^\s*['\"]?permissions['\"]?\s*:\s*['\"]?write-all(?:['\"]?\s*(?:$|[#},]))")
_USES = re.compile(r"^\s*(?:-\s*)?['\"]?uses['\"]?\s*:\s*(['\"]?)([^\s'\"#]+)\1\s*(?:#.*)?$")
_UNSAFE_PR_EXPRESSION = re.compile(
    r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body))\s*\}\}"
)
_RUN = re.compile(r"^(\s*)(-\s*)?['\"]?run['\"]?\s*:\s*(.*)$")


class _ScanFault(Exception):
    """A fixed, non-sensitive failure category; never include Git stderr."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _Change:
    path: str
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    status: str


def _kill(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
    process.wait()


def _git(repo: Path, args: list[str], *, limit: int, deadline: float) -> bytes:
    """Run only Git builtins with bounded stdout, a deadline and no inherited Git config."""

    executable = shutil.which("git", path="/usr/bin:/bin")
    if executable is None:
        raise _ScanFault(50, "The Git executable is unavailable.")
    remaining = min(COMMAND_TIMEOUT_SECONDS, deadline - time.monotonic())
    if remaining <= 0:
        raise _ScanFault(22, "The scan exceeded its time limit.")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    command = [
        executable, "--no-pager", "--no-replace-objects",
        "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
        "-c", f"core.attributesFile={os.devnull}", "-c", "protocol.allow=never",
        "-c", "diff.external=", "-C", str(repo), *args,
    ]
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment,
            close_fds=True, start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        raise _ScanFault(50, "A required Git operation could not start.") from exc
    output = bytearray()
    cutoff = time.monotonic() + remaining
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = cutoff - time.monotonic()
                if remaining <= 0:
                    raise _ScanFault(22, "A required Git operation timed out.")
                events = selector.select(min(remaining, 0.1))
                if not events:
                    continue
                block = os.read(process.stdout.fileno(), 65_536)
                if not block:
                    break
                output.extend(block)
                if len(output) > limit:
                    raise _ScanFault(20, "A required Git response exceeded its size limit.")
        try:
            returncode = process.wait(timeout=max(0.001, cutoff - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise _ScanFault(22, "A required Git operation timed out.") from exc
        if returncode != 0:
            raise _ScanFault(21, "A required Git operation failed.")
        return bytes(output)
    finally:
        _kill(process)
        if process.stdout is not None:
            process.stdout.close()


def _path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ScanFault(20, "A changed path is not supported UTF-8 text.") from exc
    if (
        not raw or len(raw) > MAX_PATH_BYTES or path.startswith("/") or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or not path.isprintable()
    ):
        raise _ScanFault(20, "A changed path cannot be represented safely.")
    if _PRIVATE_KEY.search(raw) or any(pattern.search(raw) for _, pattern in _CREDENTIALS):
        raise _ScanFault(20, "A changed path contains credential-shaped data and was withheld.")
    return path


def _changes(raw: bytes) -> list[_Change]:
    if not raw:
        return []
    fields = raw.split(b"\0")
    if fields[-1] != b"" or (len(fields) - 1) % 2:
        raise _ScanFault(20, "Git returned an incomplete change inventory.")
    if (len(fields) - 1) // 2 > MAX_FILES:
        raise _ScanFault(20, "The changed-file count exceeds the supported limit.")
    changes = []
    seen: set[str] = set()
    for index in range(0, len(fields) - 1, 2):
        match = _RAW_HEADER.fullmatch(fields[index])
        if match is None:
            raise _ScanFault(20, "Git returned an unsupported change record.")
        path = _path(fields[index + 1])
        if path in seen:
            raise _ScanFault(20, "Git returned a duplicate changed path.")
        seen.add(path)
        old_mode, new_mode, old_oid, new_oid, status = (
            item.decode("ascii") for item in match.groups()
        )
        deletion = status == "D"
        if deletion != (new_oid == "0" * 40 and new_mode == "000000"):
            raise _ScanFault(20, "Git returned inconsistent deletion metadata.")
        changes.append(_Change(path, old_mode, new_mode, old_oid, new_oid, status))
    return changes


def _finding(rule_id: str, path: str, message: str, *, line: int | None = None) -> dict:
    finding = {
        "rule_id": rule_id,
        "severity": "critical" if rule_id in {"INT-001", "INT-002"} else "high",
        "confidence": "high", "blocking": True, "message": message, "path": path,
    }
    if line is not None:
        finding["line"] = line
    return finding


def _add(findings: list[dict], finding: dict) -> None:
    if finding not in findings:
        if len(findings) >= MAX_FINDINGS:
            raise _ScanFault(20, "The finding count exceeds the supported limit.")
        findings.append(finding)


def _secrets(blob: bytes, path: str, findings: list[dict]) -> None:
    for match in _PRIVATE_KEY.finditer(blob):
        _add(findings, _finding(
            "INT-002", path, "A private-key header was detected; the value is withheld.",
            line=blob.count(b"\n", 0, match.start()) + 1,
        ))
    for description, pattern in _CREDENTIALS:
        for match in pattern.finditer(blob):
            _add(findings, _finding(
                "INT-001", path,
                f"A credential-shaped value ({description}) was detected; the value is withheld.",
                line=blob.count(b"\n", 0, match.start()) + 1,
            ))


def _workflows(text: str, path: str, findings: list[dict]) -> None:
    if not path.startswith(".github/workflows/"):
        return
    run_indent: int | None = None
    for number, line in enumerate(text.split("\n"), 1):
        indent = len(line) - len(line.lstrip())
        if line.strip() and run_indent is not None and indent <= run_indent:
            run_indent = None
        in_script = run_indent is not None
        run = _RUN.fullmatch(line)
        if run is not None:
            in_script = True
            if run.group(3).strip() in {"|", "|-", "|+", ">", ">-", ">+"}:
                run_indent = len(run.group(1)) + len(run.group(2) or "")
        if line.lstrip().startswith("#") and not in_script:
            continue
        messages = []
        if not in_script and _WRITE_ALL.search(line):
            messages.append("The workflow requests write-all permissions.")
        use = _USES.fullmatch(line) if not in_script else None
        if use is not None:
            target = use.group(2)
            if target.startswith("./"):
                if ".." in target.split("/"):
                    messages.append("A local action reference escapes its declared directory.")
            elif target.startswith("docker://"):
                if not re.fullmatch(r"docker://[^@\s]+@sha256:[0-9a-f]{64}", target):
                    messages.append("A container action is not pinned to a complete image digest.")
            elif not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", target):
                messages.append("An external action is not pinned to a complete commit SHA.")
        # This conservative lexical finding does not claim to parse all YAML.
        # Any workflow edit already requires the protected-file upgrade path.
        if in_script and _UNSAFE_PR_EXPRESSION.search(line):
            messages.append("Untrusted pull-request text is interpolated directly in a run script.")
        for message in messages:
            _add(findings, _finding("INT-030", path, message, line=number))


def _read_blob(repo: Path, change: _Change, deadline: float, budget: list[int]) -> tuple[bytes, str]:
    if change.new_mode not in {"100644", "100755"}:
        raise _ScanFault(20, "A changed symlink, submodule, or unsupported file mode needs review.")
    size_bytes = _git(repo, ["cat-file", "-s", change.new_oid], limit=32, deadline=deadline)
    if not re.fullmatch(rb"[0-9]+\n", size_bytes):
        raise _ScanFault(20, "Git returned an invalid blob size.")
    size = int(size_bytes)
    if size > MAX_FILE_BYTES or budget[0] + size > MAX_SCAN_BYTES:
        raise _ScanFault(20, "The changed content exceeds the supported scan size.")
    # Reserve bytes before reading: unsupported encodings and failed reads count
    # against the total budget too, not just successfully scanned text.
    budget[0] += size
    blob = _git(repo, ["cat-file", "blob", change.new_oid], limit=size, deadline=deadline)
    digest = hashlib.sha1(
        b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob, usedforsecurity=False
    ).hexdigest()
    if len(blob) != size or digest != change.new_oid:
        raise _ScanFault(20, "The retrieved blob does not match its Git object identity.")
    if blob.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise _ScanFault(20, "A Git LFS pointer cannot establish that the external content was scanned.")
    if any(byte < 32 and byte not in {9, 10, 12, 13} for byte in blob):
        raise _ScanFault(20, "A changed binary or unsupported text blob needs review.")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ScanFault(20, "A changed non-UTF-8 blob needs review.") from exc
    return blob, text


def scan_repository(repo_path: Path, base_sha: str, head_sha: str, repository: str) -> dict:
    """Return a closed-by-default report for changes since the unique merge base.

    Caller-supplied context is not proof of GitHub identity. The publisher must
    bind it to trusted event/API data and validate this report before use.
    """

    checks = {
        check_id: {"check_id": check_id, "status": "ERROR", "complete": False}
        for check_id in REQUIRED_CHECK_IDS
    }
    findings: list[dict] = []
    faults: list[_ScanFault] = []
    deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
    try:
        if (
            not isinstance(base_sha, str) or _SHA.fullmatch(base_sha) is None
            or not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None
            or not isinstance(repository, str) or _REPOSITORY.fullmatch(repository) is None
        ):
            raise _ScanFault(30, "The supplied repository or commit identifiers are invalid.")
        try:
            repo = Path(repo_path).resolve(strict=True)
        except (OSError, TypeError, ValueError) as exc:
            raise _ScanFault(50, "The local repository is unavailable.") from exc
        top = _git(repo, ["rev-parse", "--show-toplevel"], limit=MAX_PATH_BYTES, deadline=deadline)
        if Path(os.fsdecode(top.rstrip(b"\n"))).resolve() != repo:
            raise _ScanFault(30, "The supplied path is not the repository root.")
        if _git(repo, ["rev-parse", "--is-shallow-repository"], limit=16, deadline=deadline) != b"false\n":
            raise _ScanFault(20, "A complete commit graph is required for the merge-base calculation.")
        for commit in (base_sha, head_sha):
            if _git(repo, ["cat-file", "-t", commit], limit=16, deadline=deadline) != b"commit\n":
                raise _ScanFault(20, "An expected commit object is unavailable.")
        bases = _git(repo, ["merge-base", "--all", base_sha, head_sha], limit=1024, deadline=deadline).splitlines()
        if len(bases) != 1 or _SHA.fullmatch(bases[0].decode("ascii", errors="replace")) is None:
            raise _ScanFault(20, "The comparison does not have exactly one supported merge base.")
        raw = _git(
            repo, ["diff", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff",
                   "--no-textconv", "--ignore-submodules=none", bases[0].decode("ascii"), head_sha, "--"],
            limit=(MAX_FILES + 1) * (MAX_PATH_BYTES + 160), deadline=deadline,
        )
        changes = _changes(raw)
        checks["diff"].update(status="PASS", complete=True)
        for change in changes:
            if (
                change.path in _PROTECTED_FILES or change.path.startswith(_PROTECTED_PREFIXES)
                or change.path.rsplit("/", 1)[-1] in _PROTECTED_BASENAMES
                or (change.path.startswith("tests/test_integrity_") and change.path.endswith(".py"))
            ):
                removed = change.status == "D"
                _add(findings, _finding(
                    "INT-010" if removed else "INT-011", change.path,
                    "A protected guard or workflow file was removed." if removed else
                    "A protected guard or workflow file was changed; a separate trusted upgrade is required.",
                ))
        checks["guard"].update(
            status="FAIL" if any(f["rule_id"] in {"INT-010", "INT-011"} for f in findings) else "PASS",
            complete=True,
        )
        budget = [0]
        for change in changes:
            if change.status == "D":
                continue
            try:
                blob, text = _read_blob(repo, change, deadline, budget)
                _secrets(blob, change.path, findings)
                _workflows(text, change.path, findings)
            except _ScanFault as fault:
                faults.append(fault)
                if fault.code == 22 or "size" in str(fault) or "finding count" in str(fault):
                    break
        for check_id, rules in (
            ("secrets", {"INT-001", "INT-002"}), ("workflows", {"INT-030"}),
        ):
            checks[check_id].update(
                status="ERROR" if faults else (
                    "FAIL" if any(f["rule_id"] in rules for f in findings) else "PASS"
                ),
                complete=not faults,
            )
    except _ScanFault as fault:
        faults.append(fault)
    except Exception:
        # This API boundary never exports exception text, filenames from Git
        # diagnostics, environment data, or scanned source lines.
        faults.append(_ScanFault(99, "An unexpected scanner error prevented completion."))

    complete = all(check["complete"] for check in checks.values())
    if any(f["rule_id"] in {"INT-010", "INT-011"} for f in findings):
        code = 40
    elif faults:
        code = faults[0].code
    elif not complete:
        code = 20
    elif any(f["blocking"] for f in findings):
        code = 10
    else:
        code = 0
    summary = (
        f"{len(findings)} blocking finding(s); "
        + ("all prescribed scans completed." if complete else "prescribed scans are incomplete.")
    )
    if faults:
        summary += " " + str(faults[0])
    return {
        "schema_version": "1.0", "status": "PASS" if code == 0 else "FAIL",
        "exit_code": code, "complete": complete, "summary": summary, "findings": findings,
        "context": {
            "repository": repository, "base_sha": base_sha, "head_sha": head_sha,
            "policy_digest": policy_digest(),
        },
        "checks": list(checks.values()),
    }
