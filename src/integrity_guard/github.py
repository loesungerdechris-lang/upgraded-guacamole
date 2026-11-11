"""Trusted GitHub adapter. PR objects are data; PR code is never checked out or run.

Only this adapter has network side effects. Validators and scanners remain local.
Run from the protected base checkout, with a dedicated ephemeral runner and token.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .io import MAX_RESULT_BYTES, decode_json, read_result
from .policy import policy_digest
from .reporting import CHECK_NAME, LABEL_FAIL, LABEL_PASS, annotation_batches, check_output
from .semantic_validation import validate_result

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class ApiError(RuntimeError):
    def __init__(self, status: int = 0):
        super().__init__("GitHub API request failed.")
        self.status = status


class ExecutionError(RuntimeError):
    def __init__(self, code: int):
        super().__init__("Trusted execution could not complete.")
        self.code = code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward an authenticated request to a redirect target.
        raise ApiError(code)


class GitHubClient:
    def __init__(self, token: str, repository: str):
        if not token or not _REPOSITORY.fullmatch(repository):
            raise ApiError()
        if any(part in {".", ".."} for part in repository.split("/")):
            raise ApiError()
        self._token = token
        self._base = f"https://api.github.com/repos/{repository}"
        self._opener = build_opener(_NoRedirect())

    def request(self, method: str, suffix: str, data: dict | None = None):
        if not suffix.startswith("/") or ".." in suffix or "?" in suffix:
            raise ApiError()
        body = None if data is None else json.dumps(data, allow_nan=False).encode()
        request = Request(
            self._base + suffix,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "LoesungErde-Integrity-Guard/1.0",
            },
        )
        try:
            with self._opener.open(request, timeout=20) as response:
                raw = response.read(MAX_RESULT_BYTES + 1)
            return decode_json(raw) if raw else None
        except HTTPError as exc:
            raise ApiError(exc.code) from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise ApiError() from None


@dataclass(frozen=True)
class PullRequestContext:
    repository: str
    number: int
    base_sha: str
    head_sha: str
    base_ref: str
    run_id: str

    @property
    def result_context(self) -> dict:
        return {
            "repository": self.repository,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "policy_digest": policy_digest(),
        }


def context_from_event(event: dict, environment: dict) -> PullRequestContext:
    """Identity comes from GitHub's trusted event, never PR-produced artifacts."""
    try:
        if environment["GITHUB_EVENT_NAME"] != "pull_request_target":
            raise ValueError
        if environment.get("GITHUB_API_URL", "https://api.github.com") != "https://api.github.com":
            raise ValueError
        repository = environment["GITHUB_REPOSITORY"]
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise ValueError
        if any(part in {".", ".."} for part in repository.split("/")):
            raise ValueError
        pr = event["pull_request"]
        number = event["number"]
        base, head = pr["base"], pr["head"]
        run_id = environment["GITHUB_RUN_ID"]
        if type(number) is not int or not 0 < number < 2**63:
            raise ValueError
        if event["repository"]["full_name"] != repository:
            raise ValueError
        if base["repo"]["full_name"] != repository or base["ref"] != "main":
            raise ValueError
        if not all(isinstance(sha, str) and _SHA.fullmatch(sha)
                   for sha in (base["sha"], head["sha"])):
            raise ValueError
        if not isinstance(run_id, str) or not run_id.isascii() or not run_id.isdigit():
            raise ValueError
        return PullRequestContext(repository, number, base["sha"], head["sha"], "main", run_id)
    except (KeyError, TypeError, ValueError):
        raise ExecutionError(30) from None


def is_current(client: GitHubClient, context: PullRequestContext) -> bool:
    pr = client.request("GET", f"/pulls/{context.number}")
    try:
        return (
            pr["state"] == "open"
            and pr["head"]["sha"] == context.head_sha
            and pr["base"]["sha"] == context.base_sha
            and pr["base"]["ref"] == context.base_ref
            and pr["base"]["repo"]["full_name"] == context.repository
        )
    except (KeyError, TypeError):
        raise ApiError() from None


def update_label(client: GitHubClient, context: PullRequestContext, *, passed: bool) -> None:
    """Labels are advisory, and never substitute for the SHA-bound check."""
    if not is_current(client, context):
        return
    remove, add = (LABEL_FAIL, LABEL_PASS) if passed else (LABEL_PASS, LABEL_FAIL)
    try:
        client.request("DELETE", f"/issues/{context.number}/labels/{quote(remove, safe='')}")
    except ApiError as exc:
        if exc.status != 404:
            raise
    # Recheck after the DELETE: a synchronize event may have changed the head.
    if is_current(client, context):
        client.request("POST", f"/issues/{context.number}/labels", {"labels": [add]})


def _git_environment(token: str, repository: str) -> dict[str, str]:
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    # No inherited hooks, helpers, replacement objects, GIT_DIR or GIT_CONFIG_*.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": f"http.https://github.com/{repository}.git.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {encoded}",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_CONFIG_KEY_2": "core.fsmonitor",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "credential.helper",
        "GIT_CONFIG_VALUE_3": "",
        "GIT_CONFIG_KEY_4": "http.followRedirects",
        "GIT_CONFIG_VALUE_4": "false",
    }


def _run_isolated(command: list[str], *, env: dict, timeout: int, cwd=None) -> int:
    """Bound the whole process tree, including git's remote helpers."""
    with subprocess.Popen(
        command, env=env, cwd=cwd, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
    ) as process:
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def fetch_pr_objects(root: Path, context: PullRequestContext, token: str) -> None:
    """Fetch objects from the base repository; never fetch an arbitrary fork URL."""
    try:
        env = _git_environment(token, context.repository)
        # The installed trusted source must be exactly the event's base revision.
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"], env=env,
            capture_output=True, timeout=10, check=True,
        ).stdout.decode().strip()
        if head != context.base_sha:
            raise ExecutionError(40)
        code = _run_isolated(
            ["git", "-C", str(root), "fetch", "--no-tags", "--no-recurse-submodules",
             f"https://github.com/{context.repository}.git", f"refs/pull/{context.number}/head"],
            env=env, timeout=120,
        )
        if code != 0:
            raise ExecutionError(50)
        fetched = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "FETCH_HEAD"], env=env,
            capture_output=True, timeout=10, check=True,
        ).stdout.decode().strip()
        if fetched != context.head_sha:
            raise ExecutionError(20)
    except subprocess.TimeoutExpired:
        raise ExecutionError(22) from None
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        raise ExecutionError(50) from None


def execute_scan(root: Path, context: PullRequestContext) -> tuple[dict, int]:
    """Observe the real child exit; discard stale artifacts and all child logging."""
    bootstrap = (
        "import sys; sys.path.insert(0, sys.argv.pop(1)); "
        "from integrity_guard.cli import main; raise SystemExit(main())"
    )
    with tempfile.TemporaryDirectory(prefix="integrity-guard-") as temporary:
        output = Path(temporary) / "result.json"
        command = [
            sys.executable, "-I", "-c", bootstrap, str(root / "src"),
            "scan", "--repo", str(root), "--base", context.base_sha,
            "--head", context.head_sha, "--repository", context.repository,
            "--output", str(output),
        ]
        try:
            returncode = _run_isolated(
                command,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"},
                cwd=temporary, timeout=240,
            )
            result = read_result(output)
            validate_result(
                result, expected_context=context.result_context,
                process_exit_code=returncode,
            )
            return result, returncode
        except subprocess.TimeoutExpired:
            raise ExecutionError(22) from None
        except Exception:
            raise ExecutionError(30) from None


def publish_result(
    client: GitHubClient, context: PullRequestContext, check_id: int, result: dict, code: int
) -> None:
    validate_result(result, expected_context=context.result_context, process_exit_code=code)
    output = check_output(result)
    # Never finalize success before every annotation has been accepted.
    for batch in annotation_batches(result):
        client.request("PATCH", f"/check-runs/{check_id}", {
            "status": "in_progress", "output": {**output, "annotations": batch},
        })
    if not is_current(client, context):
        raise ExecutionError(20)
    conclusion = "success" if code == 0 else "failure"
    client.request("PATCH", f"/check-runs/{check_id}", {
        "status": "completed", "conclusion": conclusion, "output": output,
    })


def run_guard(
    client: GitHubClient, context: PullRequestContext, root: Path, token: str
) -> int:
    check_id = None
    code = 99
    try:
        if not is_current(client, context):
            raise ExecutionError(20)
        created = client.request("POST", "/check-runs", {
            "name": CHECK_NAME, "head_sha": context.head_sha, "status": "in_progress",
            "external_id": context.run_id,
            "details_url": f"https://github.com/{context.repository}/actions/runs/{context.run_id}",
            "output": {"title": CHECK_NAME, "summary": "Mandatory static checks are running."},
        })
        candidate_id = created.get("id") if isinstance(created, dict) else None
        if (
            type(candidate_id) is not int or candidate_id <= 0
            or created.get("name") != CHECK_NAME
            or created.get("head_sha") != context.head_sha
            or created.get("status") != "in_progress"
        ):
            raise ApiError()
        check_id = candidate_id
        try:
            update_label(client, context, passed=False)
        except ApiError:
            print("Integrity Guard: optional label synchronization unavailable.")
        fetch_pr_objects(root, context, token)
        result, code = execute_scan(root, context)
        publish_result(client, context, check_id, result, code)
        try:
            update_label(client, context, passed=code == 0)
        except ApiError:
            print("Integrity Guard: optional label synchronization unavailable.")
        print(f"Integrity Guard: check completed; exit={code}.")
        return code
    except ExecutionError as exc:
        code = exc.code
    except ApiError:
        code = 50
    except Exception:
        code = 30
    if check_id is not None:
        try:
            client.request("PATCH", f"/check-runs/{check_id}", {
                "status": "completed", "conclusion": "failure",
                "output": {"title": CHECK_NAME, "summary": (
                    f"Mandatory execution/reporting was not completed (exit {code}). "
                    "No positive integrity confirmation is available."
                )},
            })
        except ApiError:
            print("Integrity Guard: failure reporting unavailable; check remains unconfirmed.")
    print(f"Integrity Guard: FAIL; exit={code}.")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description="Trusted GitHub integrity adapter")
    parser.add_argument("--trusted-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = args.trusted_root.resolve(strict=True)
        if root != Path(__file__).resolve().parents[2]:
            raise ExecutionError(40)
        event = read_result(Path(os.environ["GITHUB_EVENT_PATH"]))
        context = context_from_event(event, dict(os.environ))
        token = os.environ["GUARD_GITHUB_TOKEN"]
        client = GitHubClient(token, context.repository)
        return run_guard(client, context, root, token)
    except Exception:
        print("Integrity Guard: FAIL (invalid trusted execution context).")
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
