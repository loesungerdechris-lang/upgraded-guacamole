"""Operator activation must never confuse a plan or incomplete evidence with a write."""

import base64
import copy
import json
import subprocess

import pytest

from integrity_guard import lockdown
from integrity_guard.protection import CI_CONTEXT, GUARD_CONTEXT


MAIN = "a" * 40
HEAD = "b" * 40
BOOTSTRAP = "c" * 40
MERGE = "d" * 40
LOCAL = "e" * 40
OWNERS = "f" * 40
VALIDATION = 101


def pull_request(number, *, merged=False):
    return {
        "number": number, "merged": merged, "state": "closed" if merged else "open",
        "draft": False, "merge_commit_sha": MERGE if merged else None,
        "merged_at": "2026-11-11T22:00:00Z" if merged else None,
        "user": {"login": "bootstrap-author" if number == 86 else "validation-author"},
        "base": {"ref": "main", "sha": MAIN, "repo": {"full_name": lockdown.REPOSITORY}},
        "head": {"sha": BOOTSTRAP if number == 86 else HEAD,
                 "repo": {"full_name": lockdown.REPOSITORY}},
    }


def required_check(name, number):
    check = {"id": number, "name": name, "head_sha": HEAD, "app": {"id": 15368},
             "status": "completed", "conclusion": "success"}
    if name == GUARD_CONTEXT:
        check.update(external_id="100", details_url=f"https://github.com/{lockdown.REPOSITORY}/actions/runs/100")
    else:
        check.update(check_suite={"id": 400}, details_url=f"https://github.com/{lockdown.REPOSITORY}/actions/runs/200/job/300")
    return check


class FakeGitHub:
    """Only this in-memory object accepts mutations in these tests."""

    def __init__(self):
        self.current = {
            "id": 27074079, "source": lockdown.REPOSITORY, "source_type": "Repository",
            "name": "Pre-Merge Integrity Protection (main)", "target": "branch",
            "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "rules": [{"type": "deletion"}, {"type": "non_fast_forward"},
                      {"type": "pull_request", "parameters": {
                          "required_approving_review_count": 1,
                          "required_review_thread_resolution": True,
                      }}],
        }
        contexts = ["codeql", "gitleaks", "govulncheck", "python-tests",
                    "receipt-verifier", "repository-hygiene", "test"]
        self.classic = {"required_status_checks": {
            "strict": False, "contexts": contexts,
            "checks": [{"context": name, "app_id": 15368} for name in contexts],
        }, "enforce_admins": {"enabled": True}}
        self.branch = {"commit": {"sha": MAIN}}
        self.bootstrap = pull_request(86, merged=True)
        self.validation = pull_request(VALIDATION)
        self.runs = [required_check(GUARD_CONTEXT, 1), required_check(CI_CONTEXT, 2)]
        self.actions_runs = {
            100: {"id": 100, "workflow_id": 10, "event": "pull_request_target",
                  "head_sha": MAIN, "status": "completed", "conclusion": "success",
                  "repository": {"full_name": lockdown.REPOSITORY},
                  "path": ".github/workflows/pre-merge-integrity-guard.yml@main",
                  "pull_requests": [copy.deepcopy(self.validation)]},
            200: {"id": 200, "workflow_id": 20, "event": "pull_request",
                  "head_sha": HEAD, "status": "completed", "conclusion": "success",
                  "repository": {"full_name": lockdown.REPOSITORY},
                  "path": ".github/workflows/ci.yml", "check_suite_id": 400,
                  "pull_requests": [copy.deepcopy(self.validation)]},
        }
        self.workflows = {
            10: {"id": 10, "path": ".github/workflows/pre-merge-integrity-guard.yml", "state": "active"},
            20: {"id": 20, "path": ".github/workflows/ci.yml", "state": "active"},
        }
        self.job = {"id": 300, "run_id": 200, "head_sha": HEAD, "name": CI_CONTEXT,
                    "status": "completed", "conclusion": "success",
                    "check_run_url": f"https://api.github.com{lockdown._BASE}/check-runs/2"}
        self.reviews = [{"id": 50, "user": {"login": "independent-reviewer"},
                         "state": "APPROVED", "commit_id": BOOTSTRAP,
                         "submitted_at": "2026-11-11T20:00:00Z"}]
        self.total = None
        self.deployment = {
            path: ["100644", f"{index:040x}"] for index, path in enumerate([
                ".github/workflows/pre-merge-integrity-guard.yml", ".github/workflows/ci.yml",
                "requirements/integrity-guard.txt", "src/integrity_guard/__init__.py",
                "src/integrity_guard/lockdown.py", "src/integrity_guard/protection.py",
            ], start=1)
        }
        self.remote_entries = {**copy.deepcopy(self.deployment), ".github/CODEOWNERS": ["100644", OWNERS]}
        self.owners = "/src/integrity_guard/ @independent-reviewer\n/.github/workflows/ @independent-reviewer\n"
        self.permission = "write"
        self.truncated = False
        self.clean = True
        self.calls = []
        self.collection = 0
        self.on_collect = None
        self.on_put = None
        self.fail_endpoint = None

    @property
    def writes(self):
        return [call for call in self.calls if call[0] != "GET"]

    def request(self, method, endpoint, payload=None):
        self.calls.append((method, endpoint, copy.deepcopy(payload)))
        if self.fail_endpoint == endpoint:
            raise lockdown.LockdownError("Do not reveal a synthetic credential")
        if endpoint == "/user":
            self.collection += 1
            if self.on_collect:
                self.on_collect(self)
            return {"login": "operator"}
        if method == "PUT":
            assert endpoint == lockdown._RULESET
            self.current = {**copy.deepcopy(payload), "id": 27074079,
                            "source": lockdown.REPOSITORY, "source_type": "Repository"}
            if self.on_put:
                self.on_put(self)
            return copy.deepcopy(self.current)
        if endpoint == lockdown._RULESET:
            return copy.deepcopy(self.current)
        if endpoint == lockdown._PROTECTION:
            return copy.deepcopy(self.classic)
        if endpoint.endswith("/branches/main"):
            return copy.deepcopy(self.branch)
        if endpoint.endswith("/pulls/86"):
            return copy.deepcopy(self.bootstrap)
        if endpoint.endswith(f"/pulls/{VALIDATION}"):
            return copy.deepcopy(self.validation)
        if endpoint.endswith("/pulls/86/reviews?per_page=100"):
            return copy.deepcopy(self.reviews)
        if "/actions/runs/" in endpoint:
            return copy.deepcopy(self.actions_runs[int(endpoint.split("/")[-1])])
        if "/actions/workflows/" in endpoint:
            return copy.deepcopy(self.workflows[int(endpoint.split("/")[-1])])
        if endpoint.endswith("/actions/jobs/300"):
            return copy.deepcopy(self.job)
        if "/check-runs?" in endpoint:
            assert endpoint.endswith("?per_page=100&filter=all")
            return {"total_count": len(self.runs) if self.total is None else self.total,
                    "check_runs": copy.deepcopy(self.runs)}
        if "/git/trees/" in endpoint:
            return {"truncated": self.truncated, "tree": [
                {"path": path, "type": "blob", "mode": metadata[0], "sha": metadata[1]}
                for path, metadata in self.remote_entries.items()
            ]}
        if endpoint.endswith(f"/git/blobs/{OWNERS}"):
            return {"sha": OWNERS, "encoding": "base64",
                    "content": base64.b64encode(self.owners.encode()).decode()}
        if "/collaborators/" in endpoint:
            return {"permission": self.permission,
                    "user": {"login": endpoint.split("/")[-2]}}
        raise AssertionError(f"Unexpected fake endpoint: {endpoint}")


@pytest.fixture
def fake(monkeypatch):
    client = FakeGitHub()
    monkeypatch.setattr(lockdown, "local_revision", lambda root: (
        LOCAL, copy.deepcopy(client.deployment), client.clean,
    ))
    return client


def plan(client, root):
    return lockdown.execute_live(client, root, VALIDATION)


def apply(client, root, digest):
    return lockdown.execute_live(client, root, VALIDATION, apply=True,
                                 expected_plan_sha256=digest)


def codes(report):
    return {item["code"] for item in report["blockers"]}


def test_live_plan_is_read_only_and_binds_nine_required_checks(fake, tmp_path):
    payload, report = plan(fake, tmp_path)
    assert report["status"] == "READY"
    assert report["exit_code"] == 0
    assert not report["write_attempted"]
    assert not fake.writes
    checks = next(rule for rule in payload["rules"] if rule["type"] == "required_status_checks")
    assert len(checks["parameters"]["required_status_checks"]) == 9
    assert len(report["plan_sha256"]) == 64


def test_offline_snapshot_is_only_a_plan_and_never_calls_api(fake, tmp_path, monkeypatch):
    snapshot = lockdown.collect_live(fake, VALIDATION, tmp_path)
    source = tmp_path / "snapshot.json"
    source.write_text(json.dumps(snapshot))
    monkeypatch.setattr(lockdown.GhClient, "request", lambda *a, **k: pytest.fail("offline network call"))
    output = tmp_path / "output"
    assert lockdown.main(["--snapshot", str(source), "--output", str(output)]) == 0
    report = json.loads((output / "readiness.json").read_text())
    assert report["status"] == "PLAN_ONLY"
    assert report["input_provenance"] == "unverified_offline_snapshot"
    assert not report["write_attempted"]
    assert (output / "sentinel_lockdown.json").is_file()


@pytest.mark.parametrize("extra", [
    ["--apply"], ["--apply", "--expected-plan-sha256", "0" * 64],
    ["--validation-pr", "101"], ["--expected-plan-sha256", "0" * 64],
])
def test_offline_mode_cannot_be_promoted_to_apply(tmp_path, extra):
    with pytest.raises(SystemExit) as error:
        lockdown.main(["--snapshot", str(tmp_path / "input.json"), "--output", str(tmp_path), *extra])
    assert error.value.code == 2


def test_apply_uses_exact_existing_id_and_verifies_unchanged_classic_protection(fake, tmp_path):
    classic = copy.deepcopy(fake.classic)
    payload, planned = plan(fake, tmp_path)
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert report["status"] == "APPLIED"
    assert report["readback_verified"] is True
    assert report["write_performed"] is True
    assert report["atomic_compare_and_swap"] is False
    assert fake.writes == [("PUT", lockdown._RULESET, payload)]
    assert fake.classic == classic
    assert fake.collection == 3  # reviewed plan, fresh apply input, prewrite refetch


def test_already_identical_ruleset_is_idempotent_without_put(fake, tmp_path):
    payload, _ = plan(fake, tmp_path)
    fake.current.update(payload)
    _, planned = plan(fake, tmp_path)
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert report["status"] == "UNCHANGED"
    assert report["readback_verified"] is True
    assert not fake.writes


@pytest.mark.parametrize("digest", [None, "", "0" * 64, "A" * 64, "credential"])
def test_apply_requires_exact_fresh_plan_digest(fake, tmp_path, digest):
    _, report = apply(fake, tmp_path, digest)
    assert "PLAN_DIGEST_MISMATCH" in codes(report)
    assert not fake.writes


def test_dirty_worktree_blocks_apply_even_when_committed_blobs_match(fake, tmp_path):
    fake.clean = False
    _, planned = plan(fake, tmp_path)
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert "LOCAL_WORKTREE_DIRTY" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("change", ["ruleset", "main", "validation", "classic", "checks", "local"])
def test_prewrite_refetch_rejects_drift(fake, tmp_path, change):
    _, planned = plan(fake, tmp_path)

    def drift(client):
        if client.collection != 3:
            return
        if change == "ruleset":
            client.current["name"] = "Changed protection"
        elif change == "main":
            client.branch["commit"]["sha"] = "1" * 40
        elif change == "validation":
            client.validation["head"]["sha"] = "2" * 40
        elif change == "classic":
            client.classic["enforce_admins"]["enabled"] = False
        elif change == "checks":
            client.runs[0]["conclusion"] = "failure"
        else:
            client.clean = False

    fake.on_collect = drift
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert "PREWRITE_DRIFT" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("field,value", [
    ("status", "queued"), ("conclusion", "neutral"), ("conclusion", "skipped"),
    ("conclusion", "failure"), ("head_sha", "0" * 40), ("app", {"id": 999}),
])
def test_check_must_explicitly_succeed_for_exact_head_and_app(fake, tmp_path, field, value):
    fake.runs[0][field] = value
    _, report = apply(fake, tmp_path, "0" * 64)
    assert report["status"] == "HOLD"
    assert any(code.startswith("GUARD_CHECK_") for code in codes(report))
    assert not fake.writes


@pytest.mark.parametrize("mode", ["missing", "duplicate", "truncated"])
def test_missing_ambiguous_or_incomplete_check_lists_hold(fake, tmp_path, mode):
    if mode == "missing":
        fake.runs.pop(0)
    elif mode == "duplicate":
        fake.runs.append(copy.deepcopy(fake.runs[0]))
    else:
        fake.total = 101
    _, report = plan(fake, tmp_path)
    assert report["status"] == "HOLD"
    assert "GUARD_CHECK_MISSING" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("change", ["base_sha", "base_ref", "repo", "closed", "bootstrap_head"])
def test_validation_pr_must_be_separate_open_and_current(fake, tmp_path, change):
    if change == "base_sha":
        fake.validation["base"]["sha"] = "0" * 40
    elif change == "base_ref":
        fake.validation["base"]["ref"] = "other"
    elif change == "repo":
        fake.validation["base"]["repo"]["full_name"] = "another/repository"
    elif change == "closed":
        fake.validation["state"] = "closed"
    else:
        fake.validation["head"]["sha"] = BOOTSTRAP
    _, report = plan(fake, tmp_path)
    assert report["status"] == "HOLD"
    assert not fake.writes


def test_open_bootstrap_cannot_be_declared_deployed_by_successful_checks(fake, tmp_path):
    fake.bootstrap.update(merged=False, state="open", draft=True)
    _, report = plan(fake, tmp_path)
    assert "BOOTSTRAP_NOT_MERGED" in codes(report)


def test_deployment_compares_all_committed_guard_files(fake, tmp_path):
    fake.remote_entries["src/integrity_guard/lockdown.py"][1] = "0" * 40
    _, report = plan(fake, tmp_path)
    assert "DEPLOYMENT_NOT_VERIFIED" in codes(report)


def test_truncated_remote_tree_is_unusable(fake, tmp_path):
    fake.truncated = True
    with pytest.raises(lockdown.LockdownError):
        plan(fake, tmp_path)


def test_naked_same_app_success_checks_do_not_prove_the_guard_executed(fake, tmp_path):
    for check in fake.runs:
        check.pop("external_id", None)
        check.pop("details_url", None)
    _, report = plan(fake, tmp_path)
    assert "CHECK_PROVENANCE_UNVERIFIED" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("change", [
    "wrong_event", "wrong_base", "different_pr", "different_head", "no_pr",
    "duplicate_pr", "other_workflow", "inactive_workflow", "skipped_run",
    "wrong_job", "wrong_job_check", "skipped_job", "wrong_ci_suite", "wrong_ci_head",
])
def test_check_provenance_requires_expected_successful_run_job_and_exact_pr(fake, tmp_path, change):
    guard = fake.actions_runs[100]
    if change == "wrong_event":
        guard["event"] = "push"
    elif change == "wrong_base":
        guard["head_sha"] = "0" * 40
    elif change == "different_pr":
        guard["pull_requests"][0]["number"] = 102
    elif change == "different_head":
        guard["pull_requests"][0]["head"]["sha"] = "0" * 40
    elif change == "no_pr":
        guard["pull_requests"] = []
    elif change == "duplicate_pr":
        guard["pull_requests"].append(copy.deepcopy(guard["pull_requests"][0]))
    elif change == "other_workflow":
        fake.workflows[10]["path"] = ".github/workflows/pretend.yml"
    elif change == "inactive_workflow":
        fake.workflows[10]["state"] = "disabled_manually"
    elif change == "skipped_run":
        guard["conclusion"] = "skipped"
    elif change == "wrong_job":
        fake.job["run_id"] = 999
    elif change == "wrong_job_check":
        fake.job["check_run_url"] = f"https://api.github.com{lockdown._BASE}/check-runs/999"
    elif change == "skipped_job":
        fake.job["conclusion"] = "skipped"
    elif change == "wrong_ci_suite":
        fake.runs[1]["check_suite"]["id"] = 999
    else:
        fake.actions_runs[200]["head_sha"] = "0" * 40
    _, report = plan(fake, tmp_path)
    assert "CHECK_PROVENANCE_UNVERIFIED" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("change", ["missing", "wrong_commit", "self_review", "stale", "truncated"])
def test_bootstrap_requires_actual_latest_independent_approval(fake, tmp_path, change):
    if change == "missing":
        fake.reviews = []
    elif change == "wrong_commit":
        fake.reviews[0]["commit_id"] = "0" * 40
    elif change == "self_review":
        fake.reviews[0]["user"]["login"] = "bootstrap-author"
    elif change == "stale":
        newer = {**copy.deepcopy(fake.reviews[0]), "id": 51, "state": "CHANGES_REQUESTED",
                 "submitted_at": "2026-11-11T21:00:00Z"}
        fake.reviews.insert(0, newer)  # do not trust response ordering
    else:
        fake.reviews *= 100
    _, report = plan(fake, tmp_path)
    assert "BOOTSTRAP_REVIEW_UNVERIFIED" in codes(report)
    assert not fake.writes


def test_latest_independent_approval_supersedes_older_changes_request(fake, tmp_path):
    older = {**copy.deepcopy(fake.reviews[0]), "id": 49, "state": "CHANGES_REQUESTED",
             "submitted_at": "2026-11-11T19:00:00Z"}
    fake.reviews.append(older)
    _, report = plan(fake, tmp_path)
    assert report["status"] == "READY"


@pytest.mark.parametrize("timestamp", [
    "2026-11-11T22:00:01Z", "2026-11-11T20:00:00", "invalid", None,
])
def test_bootstrap_approval_requires_valid_utc_timestamp_at_or_before_merge(fake, tmp_path, timestamp):
    fake.reviews[0]["submitted_at"] = timestamp
    _, report = plan(fake, tmp_path)
    assert "BOOTSTRAP_REVIEW_UNVERIFIED" in codes(report)
    assert not fake.writes


@pytest.mark.parametrize("timestamp", ["2026-11-11T22:00:00", "invalid", None])
def test_bootstrap_merge_timestamp_must_be_valid_utc(fake, tmp_path, timestamp):
    fake.bootstrap["merged_at"] = timestamp
    _, report = plan(fake, tmp_path)
    assert "BOOTSTRAP_REVIEW_UNVERIFIED" in codes(report)


def test_same_timestamp_approval_and_merge_is_accepted(fake, tmp_path):
    fake.reviews[0]["submitted_at"] = fake.bootstrap["merged_at"]
    _, report = plan(fake, tmp_path)
    assert report["status"] == "READY"


def test_contradictory_duplicate_review_identity_is_rejected(fake, tmp_path):
    fake.reviews.append({**copy.deepcopy(fake.reviews[0]), "state": "CHANGES_REQUESTED"})
    _, report = plan(fake, tmp_path)
    assert "BOOTSTRAP_REVIEW_UNVERIFIED" in codes(report)


@pytest.mark.parametrize("owners", [
    "/src/integrity_guard/ @bootstrap-author\n/.github/workflows/ @bootstrap-author\n",
    "/src/integrity_guard/ @validation-author\n/.github/workflows/ @validation-author\n",
    "/src/integrity_guard/ @org/team\n/.github/workflows/ @org/team\n",
    "/src/integrity_guard/ @reviewer\n/.github/workflows/ @other-reviewer\n",
    "* @independent-reviewer\n", "/src/integrity_guard/\n/.github/workflows/ @reviewer\n",
])
def test_codeowners_require_independent_common_user_and_explicit_coverage(fake, tmp_path, owners):
    fake.owners = owners
    _, report = plan(fake, tmp_path)
    assert "INDEPENDENT_CODEOWNER_REQUIRED" in codes(report)


@pytest.mark.parametrize("permission", ["read", "none", "triage"])
def test_codeowner_must_have_observed_write_permission(fake, tmp_path, permission):
    fake.permission = permission
    _, report = plan(fake, tmp_path)
    assert "INDEPENDENT_CODEOWNER_REQUIRED" in codes(report)


@pytest.mark.parametrize("change", ["ruleset", "classic", "read_error"])
def test_postwrite_mismatch_or_error_never_reports_applied(fake, tmp_path, change):
    _, planned = plan(fake, tmp_path)

    def alter(client):
        if change == "ruleset":
            client.current["enforcement"] = "disabled"
        elif change == "classic":
            client.classic["required_status_checks"]["checks"] = []
        else:
            client.fail_endpoint = lockdown._RULESET

    fake.on_put = alter
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert report["status"] == "HOLD"
    assert report["exit_code"] == 50
    assert report["write_attempted"] is True
    assert report["readback_verified"] is False
    assert len(fake.writes) == 1  # no blind retry and no rollback


def test_unavailable_authentication_yields_sanitized_hold50(tmp_path, monkeypatch, capsys):
    def failed(*args, **kwargs):
        raise lockdown.LockdownError("synthetic-credential-must-not-appear")

    monkeypatch.setattr(lockdown.GhClient, "request", failed)
    output = tmp_path / "out"
    assert lockdown.main(["--live", "--validation-pr", "101", "--output", str(output)]) == 50
    report = (output / "readiness.json").read_text()
    assert "synthetic-credential" not in report + capsys.readouterr().out
    assert not json.loads(report)["write_attempted"]


def test_unexpected_failure_after_put_preserves_attempt_evidence(fake, tmp_path):
    _, planned = plan(fake, tmp_path)

    def fail_after_write(client):
        raise ValueError("synthetic-adapter-error-not-for-output")

    fake.on_put = fail_after_write
    _, report = apply(fake, tmp_path, planned["plan_sha256"])
    assert report["write_attempted"] is True
    assert report["write_performed"] is None  # a failed response cannot prove no write
    assert report["exit_code"] == 50
    assert "WRITE_OUTCOME_UNVERIFIED" in codes(report)
    assert "synthetic-adapter" not in json.dumps(report)
    assert len(fake.writes) == 1


def test_output_failure_after_apply_preserves_observed_write_status(fake, tmp_path, monkeypatch, capsys):
    _, planned = plan(fake, tmp_path)
    monkeypatch.setattr(lockdown, "GhClient", lambda: fake)

    def unavailable(*args, **kwargs):
        raise OSError("private-path-must-not-appear")

    monkeypatch.setattr(lockdown, "write_result", unavailable)
    assert lockdown.main([
        "--live", "--validation-pr", "101", "--apply",
        "--expected-plan-sha256", planned["plan_sha256"], "--output", str(tmp_path / "output"),
    ]) == 50
    output = json.loads(capsys.readouterr().out)
    assert output["code"] == "OUTPUT_UNAVAILABLE"
    assert output["operation_status"] == "APPLIED"
    assert output["write_performed"] is True
    assert output["readback_verified"] is True
    assert "private-path" not in json.dumps(output)


def test_gh_transport_never_starts_login_and_uses_fixed_host_stdin_and_suppressed_errors(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        kwargs["stdout"].write(b'{"id":27074079}')
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    lockdown.GhClient().request("PUT", lockdown._RULESET, {"enforcement": "active"})
    command, kwargs = calls[0]
    assert command[:5] == ["gh", "api", "--hostname", "github.com", "--method"]
    assert "login" not in command
    assert command[-2:] == ["--input", "-"]
    assert json.loads(kwargs["input"]) == {"enforcement": "active"}
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["env"]["GH_PROMPT_DISABLED"] == "1"


@pytest.mark.parametrize("method,endpoint", [
    ("POST", lockdown._RULESET), ("DELETE", lockdown._RULESET),
    ("PUT", lockdown._BASE + "/rulesets/1"), ("GET", "https://attacker.invalid/"),
])
def test_transport_rejects_other_mutations_and_hosts(method, endpoint):
    with pytest.raises(lockdown.LockdownError):
        lockdown.GhClient().request(method, endpoint)
