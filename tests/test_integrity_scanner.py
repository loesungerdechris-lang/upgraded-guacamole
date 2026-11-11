"""Behavioral regressions against real, isolated Git repositories."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from integrity_guard import scanner
from integrity_guard.semantic_validation import validate_result


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True, env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout.strip()


def write(repo: Path, name: str, content: str | bytes) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def commit(repo: Path, message: str = "fixture") -> str:
    git(repo, "add", "--all")
    git(repo, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repository"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Integrity fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "core.filemode", "true")
    write(repo, "README.md", "A synthetic fixture.\n")
    return repo, commit(repo, "base")


def scan(repo: Path, base: str, head: str) -> dict:
    result = scanner.scan_repository(repo, base, head, "example/project")
    validate_result(result, expected_context=result["context"], process_exit_code=result["exit_code"])
    assert {check["check_id"] for check in result["checks"]} == {
        "diff", "guard", "secrets", "workflows",
    }
    return result


def test_clean_text_is_a_complete_pass(repository):
    repo, base = repository
    write(repo, "src/app.py", "def add(a, b):\n    return a + b\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 0
    assert result["complete"] is True
    assert result["findings"] == []
    assert all(check["status"] == "PASS" for check in result["checks"])


def test_unchanged_revision_has_a_complete_empty_diff(repository):
    repo, base = repository
    assert scan(repo, base, base)["exit_code"] == 0


@pytest.mark.parametrize("token", [
    "ghp_" + "A" * 36,
    "github_pat_" + "a" * 22 + "_" + "B" * 59,
    "AKIA" + "A" * 16,
    "AIza" + "x" * 35,
    "sk_live_" + "a" * 24,
])
def test_recognized_credentials_block_without_publishing_values(repository, token):
    repo, base = repository
    write(repo, "settings.txt", "header\ncredential=" + token + "\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 10
    assert result["complete"] is True
    assert {finding["rule_id"] for finding in result["findings"]} == {"INT-001"}
    assert result["findings"][0]["line"] == 2
    assert token not in json.dumps(result)


def test_entire_changed_blob_is_scanned_not_only_added_lines(repository):
    repo, _ = repository
    token = "ghp_" + "B" * 36
    write(repo, "settings.txt", "credential=" + token + "\nold=true\n")
    base = commit(repo)
    write(repo, "settings.txt", "credential=" + token + "\nold=false\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 10
    assert result["findings"][0]["line"] == 1


@pytest.mark.parametrize("kind", ["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"])
def test_private_key_headers_block_without_exporting_content(repository, kind):
    repo, base = repository
    header = "-----BEGIN " + kind + "-----"
    write(repo, "key.txt", header + "\nSYNTHETIC-PRIVATE-BODY\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 10
    assert result["findings"][0]["rule_id"] == "INT-002"
    assert "SYNTHETIC-PRIVATE-BODY" not in json.dumps(result)


@pytest.mark.parametrize("name", [
    "src/integrity_guard/policy.py", ".github/workflows/guard.yml", ".github/CODEOWNERS",
    "pyproject.toml", "sitecustomize.py", "usercustomize.py",
    "requirements/integrity-guard.txt", "tests/test_integrity_policy.py",
])
def test_new_protected_files_require_a_trusted_upgrade(repository, name):
    repo, base = repository
    write(repo, name, "# synthetic content\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert result["complete"] is True
    assert result["findings"][0]["rule_id"] == "INT-011"


def test_protected_deletion_is_not_silently_accepted(repository):
    repo, _ = repository
    name = "src/integrity_guard/old.py"
    write(repo, name, "# guarded\n")
    base = commit(repo)
    (repo / name).unlink()
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert result["findings"][0]["rule_id"] == "INT-010"


@pytest.mark.parametrize("name", [
    "nested/deeper/conftest.py", "nested/deeper/pytest.ini", "nested/deeper/.pytest.ini",
    "nested/deeper/pytest.toml", "nested/deeper/.pytest.toml", "nested/deeper/setup.cfg",
    "nested/deeper/setup.py", "nested/deeper/tox.ini", "nested/deeper/sitecustomize.py",
    "nested/deeper/usercustomize.py", "tests/__init__.py", "src/__init__.py",
])
def test_test_runner_configuration_and_initialization_are_protected(repository, name):
    repo, base = repository
    write(repo, name, "# synthetic trusted-runner boundary\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert result["complete"] is True
    assert any(f["rule_id"] == "INT-011" and f["path"] == name for f in result["findings"])


def test_nested_conftest_cannot_turn_an_early_pytest_exit_into_guard_success(repository):
    repo, _ = repository
    test_path = "tests/deep/nested/test_failure.py"
    write(repo, test_path, "def test_expected_failure():\n    assert False\n")
    base = commit(repo)
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path]
    environment = {
        **os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    before = subprocess.run(
        command, cwd=repo, env=environment, capture_output=True, text=True, timeout=15,
    )
    assert before.returncode == 1
    assert "1 failed" in before.stdout

    conftest = "tests/deep/nested/conftest.py"
    write(repo, conftest, "import pytest\n\ndef pytest_sessionstart(session):\n"
          "    pytest.exit('synthetic early exit', returncode=0)\n")
    head = commit(repo)
    after = subprocess.run(
        command, cwd=repo, env=environment, capture_output=True, text=True, timeout=15,
    )
    assert after.returncode == 0
    assert "synthetic early exit" in after.stdout + after.stderr
    assert "1 failed" not in after.stdout

    result = scan(repo, base, head)
    assert result["exit_code"] == 40
    assert result["complete"] is True
    assert any(f["rule_id"] == "INT-011" and f["path"] == conftest for f in result["findings"])


@pytest.mark.parametrize("content", [
    b"binary\x00content", b"\xffnot-utf-8", "hello".encode("utf-16"),
    b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 1\n",
])
def test_unsupported_content_is_incomplete_not_clean(repository, content):
    repo, base = repository
    write(repo, "asset.dat", content)
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 20
    assert result["complete"] is False
    assert any(check["status"] == "ERROR" for check in result["checks"])


def test_deleting_unsupported_content_does_not_require_scanning_deleted_bytes(repository):
    repo, _ = repository
    write(repo, "asset.dat", b"old\0binary")
    base = commit(repo)
    (repo / "asset.dat").unlink()
    assert scan(repo, base, commit(repo))["exit_code"] == 0


def test_symlink_is_neither_followed_nor_declared_clean(repository, tmp_path):
    repo, base = repository
    token = "ghp_" + "C" * 36
    outside = tmp_path / "outside.txt"
    outside.write_text(token, encoding="utf-8")
    (repo / "link.txt").symlink_to(outside)
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 20
    assert token not in json.dumps(result)


def test_new_submodule_is_incomplete_without_following_it(repository):
    repo, base = repository
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},vendor")
    git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "submodule")
    result = scan(repo, base, git(repo, "rev-parse", "HEAD"))
    assert result["exit_code"] == 20


def test_mode_only_change_still_scans_the_committed_blob(repository):
    repo, _ = repository
    write(repo, "script.sh", "# " + "ghp_" + "D" * 36 + "\n")
    base = commit(repo)
    (repo / "script.sh").chmod(0o755)
    assert scan(repo, base, commit(repo))["exit_code"] == 10


def test_known_guard_violation_survives_an_additional_incomplete_scan(repository):
    repo, base = repository
    write(repo, "src/integrity_guard/policy.py", "# changed\n")
    write(repo, "image.bin", b"\x00\xff")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert result["complete"] is False
    assert any(f["rule_id"] == "INT-011" for f in result["findings"])


def test_missing_commit_cannot_pass(repository):
    repo, base = repository
    result = scan(repo, base, "f" * 40)
    assert result["status"] == "FAIL"
    assert result["complete"] is False


@pytest.mark.parametrize("bad_sha", ["main", "--help", "a" * 39, "A" * 40, "a" * 40 + "\n", None])
def test_invalid_sha_is_rejected_before_git_execution(repository, monkeypatch, bad_sha):
    repo, base = repository

    def forbidden(*_args, **_kwargs):
        pytest.fail("Git must not receive an invalid revision")

    monkeypatch.setattr(scanner, "_git", forbidden)
    result = scanner.scan_repository(repo, base, bad_sha, "example/project")
    assert result["exit_code"] == 30
    assert result["complete"] is False


def test_scanner_ignores_dirty_worktree_content(repository):
    repo, base = repository
    write(repo, "app.txt", "clean\n")
    head = commit(repo)
    write(repo, "app.txt", "ghp_" + "E" * 36)
    assert scan(repo, base, head)["exit_code"] == 0


def test_scanner_does_not_execute_external_diff_or_inherit_git_object_overrides(repository, tmp_path, monkeypatch):
    repo, base = repository
    write(repo, "app.txt", "clean\n")
    head = commit(repo)
    marker = tmp_path / "must-not-exist"
    executable = tmp_path / "external-diff"
    executable.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    executable.chmod(0o755)
    git(repo, "config", "diff.external", str(executable))
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", str(executable))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "missing-object-directory"))
    assert scan(repo, base, head)["exit_code"] == 0
    assert not marker.exists()


@pytest.mark.parametrize("name", ["bad\nname.txt", "ghp_" + "Z" * 36])
def test_unsafe_or_sensitive_paths_are_withheld(repository, name):
    repo, base = repository
    write(repo, name, "content\n")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 20
    assert name not in json.dumps(result)


def test_file_count_limit_is_not_silently_truncated(repository, monkeypatch):
    repo, base = repository
    write(repo, "one.txt", "one\n")
    write(repo, "two.txt", "two\n")
    monkeypatch.setattr(scanner, "MAX_FILES", 1)
    assert scan(repo, base, commit(repo))["exit_code"] == 20


def test_individual_file_limit_is_incomplete(repository, monkeypatch):
    repo, base = repository
    write(repo, "large.txt", "123456789\n")
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 5)
    assert scan(repo, base, commit(repo))["exit_code"] == 20


def test_total_budget_also_counts_unscannable_blobs(repository, monkeypatch):
    repo, base = repository
    write(repo, "a.bin", b"\x00" * 30)
    write(repo, "b.bin", b"\x00" * 30)
    write(repo, "c.txt", "ghp_" + "Q" * 36)
    monkeypatch.setattr(scanner, "MAX_SCAN_BYTES", 45)
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 20
    assert result["findings"] == []


def test_finding_limit_cannot_create_a_partial_success(repository, monkeypatch):
    repo, base = repository
    write(repo, "keys.txt", "ghp_" + "G" * 36 + "\n" + "ghp_" + "H" * 36 + "\n")
    monkeypatch.setattr(scanner, "MAX_FINDINGS", 1)
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 20
    assert result["complete"] is False
    assert len(result["findings"]) == 1


def test_ambiguous_merge_base_requires_review(repository):
    repo, root = repository
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    left = git(repo, "commit-tree", tree, "-p", root, "-m", "left")
    right = git(repo, "commit-tree", tree, "-p", root, "-m", "right")
    base = git(repo, "commit-tree", tree, "-p", left, "-p", right, "-m", "base merge")
    head = git(repo, "commit-tree", tree, "-p", right, "-p", left, "-m", "head merge")
    result = scan(repo, base, head)
    assert result["exit_code"] == 20
    assert result["complete"] is False


def test_workflow_diagnostics_identify_evident_risks(repository):
    repo, base = repository
    write(repo, ".github/workflows/example.yml", """name: example
permissions: write-all
jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo "${{ github.event.pull_request.title }}"
""")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert sum(f["rule_id"] == "INT-030" for f in result["findings"]) == 3


def test_environment_binding_is_not_misreported_as_shell_interpolation(repository):
    repo, base = repository
    write(repo, ".github/workflows/example.yml", """name: example
jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "$PR_TITLE"
""")
    result = scan(repo, base, commit(repo))
    assert result["exit_code"] == 40
    assert all(f["rule_id"] != "INT-030" for f in result["findings"])


@pytest.mark.parametrize("kind", ["timeout", "oversized"])
def test_git_subprocess_is_killed_on_timeout_or_excessive_output(tmp_path, monkeypatch, kind):
    executable = tmp_path / "git-fixture"
    program = (
        "import time\ntime.sleep(10)\n" if kind == "timeout" else
        "import os\nos.write(1, b'x' * 1000000)\n"
    )
    executable.write_text("#!/usr/bin/python3\n" + program, encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(scanner.shutil, "which", lambda *_args, **_kwargs: str(executable))
    monkeypatch.setattr(scanner, "COMMAND_TIMEOUT_SECONDS", 0.1)
    started = time.monotonic()
    with pytest.raises(scanner._ScanFault) as error:
        scanner._git(tmp_path, ["status"], limit=64, deadline=started + 1)
    assert error.value.code == (22 if kind == "timeout" else 20)
    assert time.monotonic() - started < 2


def test_unexpected_runner_failure_never_returns_success(repository, monkeypatch):
    repo, base = repository

    def broken(*_args, **_kwargs):
        raise RuntimeError("synthetic-sensitive-error-body")

    monkeypatch.setattr(scanner, "_git", broken)
    result = scan(repo, base, base)
    assert result["exit_code"] == 99
    assert "synthetic-sensitive-error-body" not in json.dumps(result)
