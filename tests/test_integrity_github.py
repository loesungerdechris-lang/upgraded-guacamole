"""Adversarial adapter tests: no real API calls or repository mutations."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import signal
import subprocess
from urllib.error import HTTPError

import pytest

from integrity_guard import github
from integrity_guard.policy import REQUIRED_CHECK_IDS
from integrity_guard.reporting import CHECK_NAME, LABEL_PASS


@pytest.fixture
def context():
    return github.PullRequestContext("example/project", 17, "a" * 40, "b" * 40, "main", "123")


def report(context, *, findings=None):
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "exit_code": 0,
        "complete": True,
        "context": context.result_context,
        "checks": [
            {"check_id": check, "status": "PASS", "complete": True}
            for check in REQUIRED_CHECK_IDS
        ],
        "findings": [] if findings is None else findings,
    }


def warnings(count):
    return [
        {
            "rule_id": "INT-060",
            "severity": "info",
            "confidence": "high",
            "blocking": False,
            "message": "Untrusted scanner text must not be published",
            "path": "src/example.py",
            "line": index + 1,
        }
        for index in range(count)
    ]


class FakeClient:
    def __init__(self, context):
        self.current = {
            "state": "open",
            "draft": True,
            "head": {"sha": context.head_sha},
            "base": {
                "sha": context.base_sha,
                "ref": context.base_ref,
                "repo": {"full_name": context.repository},
            },
        }
        self.created = {
            "id": 99,
            "name": CHECK_NAME,
            "head_sha": context.head_sha,
            "status": "in_progress",
        }
        self.accepted = []
        self.failure = None
        self.after_request = None

    def request(self, method, path, data=None):
        call = (method, path, deepcopy(data))
        if self.failure is not None:
            self.failure(*call)
        self.accepted.append(call)
        if self.after_request is not None:
            self.after_request(*call)
        if method == "GET":
            return deepcopy(self.current)
        if method == "POST" and path == "/check-runs":
            return deepcopy(self.created)
        return {}

    @property
    def conclusions(self):
        return [data["conclusion"] for _, _, data in self.accepted
                if isinstance(data, dict) and "conclusion" in data]


def configured_run(monkeypatch, context, result=None, code=0):
    monkeypatch.setattr(github, "fetch_pr_objects", lambda *_: None)
    monkeypatch.setattr(github, "execute_scan", lambda *_: (
        report(context) if result is None else result, code
    ))
    return FakeClient(context)


def test_draft_executes_real_scan_and_only_then_publishes_success(monkeypatch, context):
    client = configured_run(monkeypatch, context)
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 0
    assert client.conclusions == ["success"]
    created = next(data for method, path, data in client.accepted
                   if method == "POST" and path == "/check-runs")
    assert created["head_sha"] == context.head_sha
    assert created["name"] == CHECK_NAME
    assert created["status"] == "in_progress"


@pytest.mark.parametrize("key,value", [
    ("head_sha", "c" * 40),
    ("base_sha", "c" * 40),
    ("repository", "elsewhere/project"),
    ("policy_digest", "c" * 64),
])
def test_result_for_other_context_cannot_publish_success(monkeypatch, context, key, value):
    result = report(context)
    result["context"][key] = value
    client = configured_run(monkeypatch, context, result)
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 30
    assert client.conclusions == ["failure"]


@pytest.mark.parametrize("observed_code", [1, 10, 21, -9, 256, True])
def test_pass_json_cannot_override_actual_failure(monkeypatch, context, observed_code):
    client = configured_run(monkeypatch, context, code=observed_code)
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 30
    assert client.conclusions == ["failure"]


@pytest.mark.parametrize("invalid", ["missing", "skipped", "cancelled", "failure"])
def test_missing_or_unexpected_mandatory_state_never_passes(monkeypatch, context, invalid):
    result = report(context)
    if invalid == "missing":
        result["checks"].pop()
    else:
        result["checks"][0]["status"] = invalid
    client = configured_run(monkeypatch, context, result)
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 30
    assert client.conclusions == ["failure"]


@pytest.mark.parametrize("error", [github.ExecutionError(22), RuntimeError("synthetic-secret")])
def test_scanner_timeout_or_crash_never_publishes_success(monkeypatch, context, error, capsys):
    client = configured_run(monkeypatch, context)

    def crash(*_):
        raise error

    monkeypatch.setattr(github, "execute_scan", crash)
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") != 0
    assert client.conclusions == ["failure"]
    assert "synthetic-secret" not in capsys.readouterr().out


@pytest.mark.parametrize("field,value", [
    ("id", True), ("id", 0), ("name", "Other Check"),
    ("head_sha", "c" * 40), ("status", "completed"),
])
def test_inconsistent_created_check_is_not_finalized_as_success(
    monkeypatch, context, field, value
):
    client = configured_run(monkeypatch, context)
    client.created[field] = value
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") != 0
    assert "success" not in client.conclusions


def test_missing_api_create_id_never_reaches_success(monkeypatch, context):
    client = configured_run(monkeypatch, context)
    client.created = {}
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 50
    assert "success" not in client.conclusions


def test_all_51_annotations_are_accepted_before_success(context):
    client = FakeClient(context)
    github.publish_result(client, context, 99, report(context, findings=warnings(51)), 0)
    updates = [data for method, _, data in client.accepted if method == "PATCH"]
    assert [len(data["output"].get("annotations", [])) for data in updates] == [50, 1, 0]
    assert all(data["status"] == "in_progress" for data in updates[:-1])
    assert updates[-1]["conclusion"] == "success"


def test_failed_second_annotation_batch_never_finishes_success(monkeypatch, context):
    client = configured_run(monkeypatch, context, report(context, findings=warnings(51)))
    batches = 0

    def fail_second_batch(method, path, data):
        nonlocal batches
        if method == "PATCH" and "annotations" in data.get("output", {}):
            batches += 1
            if batches == 2:
                raise github.ApiError(503)

    client.failure = fail_second_batch
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 50
    assert batches == 2
    assert client.conclusions == ["failure"]


def test_new_head_during_scan_blocks_final_success(monkeypatch, context):
    client = configured_run(monkeypatch, context, report(context, findings=warnings(1)))

    def advance_after_annotation(method, path, data):
        if method == "PATCH" and "annotations" in data.get("output", {}):
            client.current["head"]["sha"] = "c" * 40

    client.after_request = advance_after_annotation
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 20
    assert client.conclusions == ["failure"]


def test_stale_event_does_not_touch_current_check_or_labels(monkeypatch, context):
    client = configured_run(monkeypatch, context)
    client.current["head"]["sha"] = "c" * 40
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 20
    assert [method for method, _, _ in client.accepted] == ["GET"]


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_only_404_is_ignored_when_removing_a_label(context, status):
    client = FakeClient(context)

    def reject_delete(method, *_):
        if method == "DELETE":
            raise github.ApiError(status)

    client.failure = reject_delete
    with pytest.raises(github.ApiError) as caught:
        github.update_label(client, context, passed=True)
    assert caught.value.status == status
    assert not any(method == "POST" for method, _, _ in client.accepted)


def test_missing_old_label_does_not_prevent_sync(context):
    client = FakeClient(context)

    def missing_label(method, *_):
        if method == "DELETE":
            raise github.ApiError(404)

    client.failure = missing_label
    github.update_label(client, context, passed=True)
    assert client.accepted[-1][2] == {"labels": [LABEL_PASS]}


def test_optional_label_failure_cannot_create_pass_from_failed_check(monkeypatch, context):
    result = report(context)
    result.update(status="FAIL", exit_code=21, complete=False)
    result["checks"][0].update(status="ERROR", complete=False)
    client = configured_run(monkeypatch, context, result, 21)

    def no_label_permission(method, path, data):
        if "/labels" in path:
            raise github.ApiError(403)

    client.failure = no_label_permission
    assert github.run_guard(client, context, Path("/trusted"), "synthetic-token") == 21
    assert client.conclusions == ["failure"]


def event_and_environment(context):
    event = {
        "action": "opened",
        "number": context.number,
        "repository": {"full_name": context.repository},
        "pull_request": {"number": context.number, **FakeClient(context).current},
    }
    environment = {
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REPOSITORY": context.repository,
        "GITHUB_RUN_ID": context.run_id,
    }
    return event, environment


def test_event_identity_accepts_draft_without_bypass(context):
    event, environment = event_and_environment(context)
    assert github.context_from_event(event, environment) == context


@pytest.mark.parametrize("variant", [
    "missing", "boolean-number", "wrong-repo", "wrong-base", "invalid-head",
    "wrong-trigger", "alternate-api", "bad-run-id", "shape",
])
def test_untrusted_or_malformed_event_is_rejected(context, variant):
    event, environment = event_and_environment(context)
    if variant == "missing":
        del event["pull_request"]
    elif variant == "boolean-number":
        event["number"] = True
    elif variant == "wrong-repo":
        event["repository"]["full_name"] = "other/project"
    elif variant == "wrong-base":
        event["pull_request"]["base"]["ref"] = "untrusted"
    elif variant == "invalid-head":
        event["pull_request"]["head"]["sha"] = "b" * 40 + "\n"
    elif variant == "wrong-trigger":
        environment["GITHUB_EVENT_NAME"] = "pull_request"
    elif variant == "alternate-api":
        environment["GITHUB_API_URL"] = "https://untrusted.invalid"
    elif variant == "bad-run-id":
        environment["GITHUB_RUN_ID"] = "../../elsewhere"
    else:
        event = []
    with pytest.raises(github.ExecutionError) as caught:
        github.context_from_event(event, environment)
    assert caught.value.code == 30


def test_git_auth_environment_does_not_inherit_attacker_configuration(monkeypatch, context):
    monkeypatch.setenv("GIT_DIR", "/attacker")
    monkeypatch.setenv("GIT_SSH_COMMAND", "untrusted-command")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "900")
    monkeypatch.setenv("GUARD_GITHUB_TOKEN", "do-not-inherit")
    monkeypatch.setenv("PYTHONPATH", "/attacker")
    env = github._git_environment("synthetic-token", context.repository)
    assert not {"GIT_DIR", "GIT_SSH_COMMAND", "GUARD_GITHUB_TOKEN", "PYTHONPATH"} & env.keys()
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert env["GIT_CONFIG_VALUE_1"] == "/dev/null"
    assert env["GIT_CONFIG_VALUE_4"] == "false"
    assert all("synthetic-token" not in value for value in env.values())


def test_http_error_hides_server_body_and_credentials(context):
    client = github.GitHubClient("synthetic-token", context.repository)

    class FailingOpener:
        def open(self, request, timeout):
            assert request.full_url.startswith("https://api.github.com/repos/example/project/")
            assert request.get_header("Authorization") == "Bearer synthetic-token"
            raise HTTPError(request.full_url, 403, "sensitive-server-response", {}, None)

    client._opener = FailingOpener()
    with pytest.raises(github.ApiError) as caught:
        client.request("GET", "/pulls/17")
    assert caught.value.status == 403
    assert "synthetic-token" not in str(caught.value)
    assert "sensitive-server-response" not in str(caught.value)


def test_redirects_are_not_followed():
    with pytest.raises(github.ApiError) as caught:
        github._NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://untrusted.invalid/collect"
        )
    assert caught.value.status == 302


def test_fetch_reads_only_expected_pull_ref_without_checkout(monkeypatch, context):
    calls = []

    def rev_parse(command, **kwargs):
        calls.append((command, kwargs))
        value = context.base_sha if command[-1] == "HEAD" else context.head_sha
        return subprocess.CompletedProcess(command, 0, (value + "\n").encode())

    def fetch(command, **kwargs):
        calls.append((command, kwargs))
        return 0

    monkeypatch.setattr(github.subprocess, "run", rev_parse)
    monkeypatch.setattr(github, "_run_isolated", fetch)
    github.fetch_pr_objects(Path("/trusted"), context, "synthetic-token")
    commands = [command for command, _ in calls]
    assert not any("checkout" in command for command in commands)
    assert commands[1][-2:] == [
        "https://github.com/example/project.git", "refs/pull/17/head"
    ]
    assert "--no-recurse-submodules" in commands[1]
    assert "--no-tags" in commands[1]
    assert all("synthetic-token" not in str(command) for command in commands)


@pytest.mark.parametrize("wrong_revision,expected_code", [("HEAD", 40), ("FETCH_HEAD", 20)])
def test_wrong_checked_out_or_fetched_revision_aborts(monkeypatch, context, wrong_revision,
                                                   expected_code):
    fetched = []

    def rev_parse(command, **kwargs):
        value = context.base_sha if command[-1] == "HEAD" else context.head_sha
        if command[-1] == wrong_revision:
            value = "c" * 40
        return subprocess.CompletedProcess(command, 0, value.encode())

    monkeypatch.setattr(github.subprocess, "run", rev_parse)
    monkeypatch.setattr(github, "_run_isolated", lambda *args, **kwargs: fetched.append(True) or 0)
    with pytest.raises(github.ExecutionError) as caught:
        github.fetch_pr_objects(Path("/trusted"), context, "synthetic-token")
    assert caught.value.code == expected_code
    if wrong_revision == "HEAD":
        assert not fetched


def test_scan_child_is_isolated_from_credentials_and_pr_imports(monkeypatch, context, tmp_path):
    monkeypatch.setenv("GUARD_GITHUB_TOKEN", "synthetic-secret")
    monkeypatch.setenv("PYTHONPATH", "/attacker")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "999")
    outputs = []

    def run_child(command, **kwargs):
        assert command[1:3] == ["-I", "-c"]
        assert command[4] == str(tmp_path / "src")
        assert set(kwargs["env"]) == {"PATH", "LC_ALL"}
        assert Path(kwargs["cwd"]) != tmp_path
        output = Path(command[command.index("--output") + 1])
        assert not output.exists()
        output.write_text(json.dumps(report(context)))
        outputs.append(output)
        return 0

    monkeypatch.setattr(github, "_run_isolated", run_child)
    result, code = github.execute_scan(tmp_path, context)
    assert result["status"] == "PASS" and code == 0
    assert not outputs[0].exists()


def test_stale_success_file_cannot_satisfy_new_scan(monkeypatch, context, tmp_path):
    outputs = []

    def run_child(command, **kwargs):
        output = Path(command[command.index("--output") + 1])
        outputs.append(output)
        if len(outputs) == 1:
            output.write_text(json.dumps(report(context)))
        return 0

    monkeypatch.setattr(github, "_run_isolated", run_child)
    assert github.execute_scan(tmp_path, context)[1] == 0
    with pytest.raises(github.ExecutionError) as caught:
        github.execute_scan(tmp_path, context)
    assert caught.value.code == 30
    assert outputs[0] != outputs[1]


def test_written_pass_then_process_crash_is_invalid(monkeypatch, context, tmp_path):
    def run_child(command, **kwargs):
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps(report(context)))
        return -9

    monkeypatch.setattr(github, "_run_isolated", run_child)
    with pytest.raises(github.ExecutionError) as caught:
        github.execute_scan(tmp_path, context)
    assert caught.value.code == 30


def test_scan_timeout_is_a_distinct_closed_outcome(monkeypatch, context, tmp_path):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("synthetic command", 240)

    monkeypatch.setattr(github, "_run_isolated", timeout)
    with pytest.raises(github.ExecutionError) as caught:
        github.execute_scan(tmp_path, context)
    assert caught.value.code == 22


def test_timeout_kills_the_whole_child_process_group(monkeypatch):
    waits = []
    kills = []

    class Process:
        pid = 12345

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def wait(self, timeout=None):
            waits.append(timeout)
            if timeout is not None:
                raise subprocess.TimeoutExpired("synthetic command", timeout)
            return -9

    def popen(command, **kwargs):
        assert kwargs["start_new_session"] is True
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        return Process()

    monkeypatch.setattr(github.subprocess, "Popen", popen)
    monkeypatch.setattr(github.os, "killpg", lambda pid, sig: kills.append((pid, sig)))
    with pytest.raises(subprocess.TimeoutExpired):
        github._run_isolated(["synthetic-command"], env={}, timeout=2)
    assert kills == [(12345, signal.SIGKILL)]
    assert waits == [2, None]
