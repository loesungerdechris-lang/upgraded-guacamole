"""Conservative operator CLI for one existing main-branch ruleset.

Offline snapshots produce review material only. A write always collects fresh
authenticated evidence, binds a reviewed plan digest, checks for drift, updates
the existing ID, and verifies read-back. This is not an atomic compare-and-swap.
Neither mode merges PRs, creates reviews, installs bypasses, or executes PR code.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .io import MAX_RESULT_BYTES, InvalidResult, decode_json, read_result, write_result
from .protection import (
    CI_CONTEXT,
    GUARD_CONTEXT,
    ProtectionValidationError,
    build_ruleset_payload,
    evaluate_readiness,
    fingerprint_ruleset,
)

REPOSITORY = "loesungerdechris-lang/upgraded-guacamole"
RULESET_ID = 27074079
BOOTSTRAP_PR = 86
SOURCE_APP_ID = 15368
_BASE = f"/repos/{REPOSITORY}"
_RULESET = f"{_BASE}/rulesets/{RULESET_ID}"
_PROTECTION = f"{_BASE}/branches/main/protection"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,18}\Z")
_SAFE_COLLECTOR_CODES = frozenset({
    "ADMIN_PROTECTION_UNAVAILABLE", "VALIDATION_PR_INVALID", "CHECK_LIST_INCOMPLETE",
    "CHECK_IDENTITY_AMBIGUOUS", "CHECK_PROVENANCE_UNVERIFIED", "BOOTSTRAP_REVIEW_UNVERIFIED",
})
_FIXED_DEPLOYMENT = frozenset({
    ".github/workflows/pre-merge-integrity-guard.yml", ".github/workflows/ci.yml",
    "requirements/integrity-guard.txt",
})


class LockdownError(RuntimeError):
    """A bounded operation failed; exception messages never include input."""


def _digest(value) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _block(code: str, message: str) -> dict:
    return {"code": code, "message": message}


def _sha(value) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _login(value) -> bool:
    return type(value) is str and _LOGIN.fullmatch(value) is not None


def _positive_id(value) -> bool:
    return type(value) is int and 0 < value < 2**63


class GhClient:
    """Use existing gh authentication; suppress prompts and all raw diagnostics."""

    def request(self, method: str, endpoint: str, payload: dict | None = None):
        if method not in {"GET", "PUT"} or not endpoint.startswith((_BASE + "/", "/user")):
            raise LockdownError("Unsupported API operation.")
        if method == "PUT" and endpoint != _RULESET:
            raise LockdownError("Unsupported mutation target.")
        command = [
            "gh", "api", "--hostname", "github.com", "--method", method,
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint,
        ]
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
            command.extend(["--input", "-"])
        try:
            with tempfile.TemporaryFile() as output:
                completed = subprocess.run(
                    command, input=data, stdout=output, stderr=subprocess.DEVNULL,
                    timeout=30, check=False,
                    env={**os.environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"},
                )
                if completed.returncode != 0:
                    raise LockdownError("Authenticated API access is unavailable.")
                output.seek(0)
                return decode_json(output.read(MAX_RESULT_BYTES + 1))
        except (OSError, subprocess.TimeoutExpired, InvalidResult, ValueError):
            raise LockdownError("Authenticated API access is unavailable.") from None


def _git(root: Path, *args: str) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false",
             "-C", str(root), *args],
            env=environment, capture_output=True, check=True, timeout=15,
        ).stdout
        if len(result) > MAX_RESULT_BYTES:
            raise LockdownError("Local repository inspection exceeded its limit.")
        return result
    except (OSError, subprocess.SubprocessError):
        raise LockdownError("Local committed repository is unavailable.") from None


def _deployment_entries(entries: dict) -> dict:
    selected = {
        path: value for path, value in entries.items()
        if path in _FIXED_DEPLOYMENT or path.startswith("src/integrity_guard/")
    }
    required = _FIXED_DEPLOYMENT | {
        "src/integrity_guard/__init__.py", "src/integrity_guard/lockdown.py",
        "src/integrity_guard/protection.py",
    }
    if not required.issubset(selected):
        raise LockdownError("Deployment manifest is incomplete.")
    if any(value[0] not in {"100644", "100755"} for value in selected.values()):
        raise LockdownError("Deployment manifest contains an unsupported object.")
    return selected


def local_revision(root: Path) -> tuple[str, dict, bool]:
    """Read committed blobs and cleanliness without importing repository code."""
    try:
        head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
        if not _sha(head):
            raise LockdownError("Local revision is invalid.")
        entries = {}
        for record in _git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
            name = path.decode("utf-8")
            if kind not in {"blob", "commit"} or not _sha(oid) or name in entries:
                raise LockdownError("Local tree is invalid.")
            entries[name] = [mode, oid]
        clean = not _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        return head, _deployment_entries(entries), clean
    except (UnicodeError, ValueError):
        raise LockdownError("Local committed tree is invalid.") from None


def _remote_tree(client: GhClient, main_sha: str) -> dict:
    tree = client.request("GET", f"{_BASE}/git/trees/{main_sha}?recursive=1")
    if (type(tree) is not dict or tree.get("truncated") is not False
            or type(tree.get("tree")) is not list):
        raise LockdownError("The deployed tree is incomplete.")
    entries = {}
    for item in tree["tree"]:
        if type(item) is not dict or type(item.get("path")) is not str:
            raise LockdownError("The deployed tree is invalid.")
        path, oid = item["path"], item.get("sha")
        if not _sha(oid) or path in entries:
            raise LockdownError("The deployed tree is invalid.")
        if item.get("type") == "tree":
            continue
        if item.get("type") not in {"blob", "commit"}:
            raise LockdownError("The deployed tree is invalid.")
        entries[path] = [item.get("mode"), oid]
    return entries


def independent_codeowners(
    client: GhClient, entries: dict, excluded_authors: set[str],
) -> tuple[list[str], str | None]:
    """A deliberately narrow CODEOWNERS subset; unsupported evidence holds.

    A candidate must own every operative line, cover both protected directories,
    differ from both PR authors, and have observed write/maintain/admin access.
    Team names, emails, escaped patterns and ownerless rules are not inferred.
    """
    path = next((p for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
                 if p in entries), None)
    if path is None or entries[path][0] != "100644":
        return [], None
    oid = entries[path][1]
    blob = client.request("GET", f"{_BASE}/git/blobs/{oid}")
    try:
        if (type(blob) is not dict or blob.get("sha") != oid
                or blob.get("encoding") != "base64" or type(blob.get("content")) is not str):
            return [], oid
        content = base64.b64decode("".join(blob["content"].splitlines()), validate=True)
        if len(content) > 65536:
            return [], oid
        candidates = None
        patterns = set()
        for raw in content.decode("utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split(" #", 1)[0].strip()
            parts = line.split()
            if len(parts) < 2 or any(c in parts[0] for c in "![]\\"):
                return [], oid
            if not parts[0].startswith(("/", "*")) or not parts[0].isascii():
                return [], oid
            owners = set()
            for owner in parts[1:]:
                if not owner.startswith("@") or not _login(owner[1:]):
                    return [], oid
                owners.add(owner[1:].lower())
            candidates = owners if candidates is None else candidates & owners
            patterns.add(parts[0])
        if not {"/src/integrity_guard/", "/.github/workflows/"}.issubset(patterns):
            return [], oid
        candidates = (candidates or set()) - {name.lower() for name in excluded_authors}
        if len(candidates) > 10:
            return [], oid
        eligible = []
        for name in sorted(candidates):
            permission = client.request("GET", f"{_BASE}/collaborators/{name}/permission")
            if (type(permission) is dict
                    and permission.get("permission") in {"write", "maintain", "admin"}
                    and type(permission.get("user")) is dict
                    and str(permission["user"].get("login", "")).lower() == name):
                eligible.append(name)
        return eligible, oid
    except (UnicodeError, ValueError):
        return [], oid


def _validation_identity(pr: dict, number: int, main_sha: str, bootstrap: dict) -> bool:
    try:
        return (
            pr["number"] == number and type(pr["number"]) is int and number != BOOTSTRAP_PR
            and pr["state"] == "open" and pr["base"]["ref"] == "main"
            and pr["base"]["repo"]["full_name"] == REPOSITORY
            and pr["base"]["sha"] == main_sha and _sha(pr["head"]["sha"])
            and pr["head"]["sha"] != bootstrap["head"]["sha"]
            and _login(pr["user"]["login"]) and _login(bootstrap["user"]["login"])
        )
    except (KeyError, TypeError):
        return False


def check_provenance(
    client: GhClient, check: dict, validation: dict, main_sha: str, *, guard: bool,
) -> bool:
    """Verify an actual successful Actions execution, not just mutable labels.

    Custom guard checks do not share the base controller's check suite. Its
    successful trusted run must instead identify this exact PR, head and base.
    The native CI job additionally binds its server-provided check_run_url.
    GitHub Actions remains a shared publisher, not a cryptographic attestation.
    """
    try:
        if not _positive_id(check.get("id")):
            return False
        if guard:
            external = check.get("external_id")
            if type(external) is not str or not _NUMBER.fullmatch(external):
                return False
            run_id = int(external)
            if check.get("details_url") != f"https://github.com/{REPOSITORY}/actions/runs/{run_id}":
                return False
            expected_path = ".github/workflows/pre-merge-integrity-guard.yml"
            event, run_sha = "pull_request_target", main_sha
        else:
            url = check.get("details_url")
            prefix = f"https://github.com/{REPOSITORY}/actions/runs/"
            if type(url) is not str or not url.startswith(prefix):
                return False
            parts = url[len(prefix):].split("/")
            if (len(parts) != 3 or parts[1] != "job"
                    or not _NUMBER.fullmatch(parts[0]) or not _NUMBER.fullmatch(parts[2])):
                return False
            run_id, job_id = int(parts[0]), int(parts[2])
            job = client.request("GET", f"{_BASE}/actions/jobs/{job_id}")
            if (type(job) is not dict or not _positive_id(job.get("id"))
                    or not _positive_id(job.get("run_id"))
                    or job.get("id") != job_id or job.get("run_id") != run_id
                    or job.get("head_sha") != validation["head"]["sha"]
                    or job.get("name") != CI_CONTEXT or job.get("status") != "completed"
                    or job.get("conclusion") != "success"
                    or job.get("check_run_url") != f"https://api.github.com{_BASE}/check-runs/{check['id']}"):
                return False
            expected_path = ".github/workflows/ci.yml"
            event, run_sha = "pull_request", validation["head"]["sha"]
        if not _positive_id(run_id):
            return False
        run = client.request("GET", f"{_BASE}/actions/runs/{run_id}")
        if (type(run) is not dict or not _positive_id(run.get("id")) or run.get("id") != run_id
                or run.get("status") != "completed" or run.get("conclusion") != "success"
                or run.get("event") != event or run.get("head_sha") != run_sha
                or run.get("repository", {}).get("full_name") != REPOSITORY
                or not _positive_id(run.get("workflow_id"))):
            return False
        path = run.get("path")
        if type(path) is not str or path.split("@", 1)[0] != expected_path:
            return False
        associations = run.get("pull_requests")
        if type(associations) is not list or len(associations) != 1:
            return False
        association = associations[0]
        if (not _positive_id(association["number"]) or association["number"] != validation["number"]
                or association["head"]["sha"] != validation["head"]["sha"]
                or association["base"]["sha"] != main_sha
                or association["base"]["ref"] != "main"):
            return False
        workflow = client.request("GET", f"{_BASE}/actions/workflows/{run['workflow_id']}")
        if (type(workflow) is not dict or not _positive_id(workflow.get("id"))
                or workflow.get("id") != run["workflow_id"]
                or workflow.get("path") != expected_path or workflow.get("state") != "active"):
            return False
        if not guard:
            suite = check.get("check_suite")
            if (type(suite) is not dict or not _positive_id(suite.get("id"))
                    or suite["id"] != run.get("check_suite_id")):
                return False
        return True
    except (KeyError, TypeError, AttributeError, ValueError):
        return False


def approved_bootstrap_reviewers(
    client: GhClient, bootstrap: dict, candidates: list[str],
) -> tuple[list[str], str | None]:
    """Require the latest review at the exact bootstrap head, before its merge.

    Distinct eligible GitHub users establish the available review trail, not
    that the accounts are controlled by different natural persons.
    """
    if not candidates:
        return [], None
    reviews = client.request("GET", f"{_BASE}/pulls/{BOOTSTRAP_PR}/reviews?per_page=100")
    if type(reviews) is not list or len(reviews) >= 100:
        return [], None
    latest = {}
    try:
        merged_at = datetime.fromisoformat(bootstrap["merged_at"].replace("Z", "+00:00"))
        if merged_at.tzinfo is None or merged_at.utcoffset() != timezone.utc.utcoffset(merged_at):
            return [], None
        seen = set()
        for review in reviews:
            name = review["user"]["login"]
            if (not _login(name) or not _positive_id(review.get("id"))
                    or review["id"] in seen):
                return [], None
            seen.add(review["id"])
            if name.lower() not in candidates:
                continue
            submitted = datetime.fromisoformat(review["submitted_at"].replace("Z", "+00:00"))
            if submitted.tzinfo is None or submitted.utcoffset() != timezone.utc.utcoffset(submitted):
                return [], None
            key = (submitted, review["id"])
            if name.lower() not in latest or key > latest[name.lower()][0]:
                latest[name.lower()] = (key, review)
        approved = sorted(name for name, (key, review) in latest.items()
                          if review.get("state") == "APPROVED"
                          and review.get("commit_id") == bootstrap["head"]["sha"]
                          and key[0] <= merged_at)
        return approved, _digest(reviews)
    except (KeyError, TypeError, AttributeError, ValueError):
        return [], None


def collect_live(client: GhClient, validation_pr: int, root: Path) -> dict:
    """Every invocation reads fresh GitHub state; no supplied attestations enter."""
    if type(validation_pr) is not int or not 0 < validation_pr < 2**63 or validation_pr == BOOTSTRAP_PR:
        raise LockdownError("A separate validation pull request is required.")
    identity = client.request("GET", "/user")
    if type(identity) is not dict or not _login(identity.get("login")):
        raise LockdownError("Authenticated GitHub identity is unavailable.")
    current = client.request("GET", _RULESET)
    classic = client.request("GET", _PROTECTION)
    branch = client.request("GET", f"{_BASE}/branches/main")
    bootstrap = client.request("GET", f"{_BASE}/pulls/{BOOTSTRAP_PR}")
    validation = client.request("GET", f"{_BASE}/pulls/{validation_pr}")
    try:
        main_sha = branch["commit"]["sha"]
        if not _sha(main_sha) or bootstrap["number"] != BOOTSTRAP_PR:
            raise LockdownError("Live branch or bootstrap identity is invalid.")
    except (KeyError, TypeError):
        raise LockdownError("Live branch or bootstrap identity is invalid.") from None
    blockers = []
    valid_pr = _validation_identity(validation, validation_pr, main_sha, bootstrap)
    if not valid_pr:
        blockers.append(_block("VALIDATION_PR_INVALID", "A separate open PR on the current main revision is required."))
    head_data = validation.get("head") if type(validation) is dict else None
    head = head_data.get("sha") if type(head_data) is dict else None
    checks = {GUARD_CONTEXT: None, CI_CONTEXT: None}
    if valid_pr:
        runs = client.request("GET", f"{_BASE}/commits/{head}/check-runs?per_page=100&filter=all")
        if (type(runs) is not dict or type(runs.get("check_runs")) is not list
                or type(runs.get("total_count")) is not int
                or runs["total_count"] != len(runs["check_runs"]) or runs["total_count"] > 100):
            blockers.append(_block("CHECK_LIST_INCOMPLETE", "The complete check-run list could not be verified."))
        else:
            for name in checks:
                matches = [item for item in runs["check_runs"]
                           if type(item) is dict and item.get("name") == name]
                if len(matches) == 1:
                    checks[name] = matches[0]
                elif len(matches) > 1:
                    blockers.append(_block("CHECK_IDENTITY_AMBIGUOUS", "A required context has multiple check runs."))
            for name, check in checks.items():
                if check is not None and not check_provenance(
                    client, check, validation, main_sha, guard=name == GUARD_CONTEXT,
                ):
                    blockers.append(_block("CHECK_PROVENANCE_UNVERIFIED", "A required check is not linked to the expected successful workflow and PR revision."))
    entries = _remote_tree(client, main_sha)
    local_sha, local_entries, clean = local_revision(root)
    try:
        deployed = _deployment_entries(entries) == local_entries
    except LockdownError:
        deployed = False
    owners, owners_sha = ([], None)
    if valid_pr:
        owners, owners_sha = independent_codeowners(
            client, entries, {bootstrap["user"]["login"], validation["user"]["login"]},
        )
    reviewers, reviews_digest = approved_bootstrap_reviewers(client, bootstrap, owners)
    if not reviewers:
        blockers.append(_block("BOOTSTRAP_REVIEW_UNVERIFIED", "No current bootstrap-head approval by an eligible independent code owner is verified."))
    return {
        "repository": REPOSITORY, "current_ruleset": current, "branch_protection": classic,
        "bootstrap_pr": bootstrap, "validation_pr": validation,
        "deployed_files_match": deployed, "guard_check": checks[GUARD_CONTEXT],
        "ci_check": checks[CI_CONTEXT], "current_head_sha": head,
        "source_app_id": SOURCE_APP_ID, "independent_codeowner_verified": bool(owners and reviewers),
        "collector_blockers": blockers,
        "live_evidence": {
            "main_sha": main_sha, "local_head_sha": local_sha, "local_clean": clean,
            "deployment_sha256": _digest(local_entries), "codeowners_blob_sha": owners_sha,
            "independent_codeowners": owners,
            "approved_bootstrap_reviewers": reviewers, "bootstrap_reviews_sha256": reviews_digest,
        },
    }


def prepare(snapshot: dict, *, live: bool) -> tuple[dict, dict]:
    """Produce payload and a sanitized report; offline booleans are only inputs."""
    current = snapshot.get("current_ruleset")
    if (snapshot.get("repository") != REPOSITORY
            or type(snapshot.get("source_app_id")) is not int
            or snapshot["source_app_id"] != SOURCE_APP_ID
            or type(current) is not dict or type(current.get("id")) is not int
            or current["id"] != RULESET_ID
            or current.get("source") != REPOSITORY or current.get("source_type") != "Repository"):
        raise ProtectionValidationError("Fixed repository or ruleset identity is invalid.")
    payload = build_ruleset_payload(current, snapshot["branch_protection"], source_app_id=SOURCE_APP_ID)
    blockers = evaluate_readiness(**{key: snapshot.get(key) for key in (
        "repository", "bootstrap_pr", "deployed_files_match", "guard_check", "ci_check",
        "current_head_sha", "source_app_id", "independent_codeowner_verified",
    )})
    supplied = snapshot.get("collector_blockers", [])
    if type(supplied) is not list or len(supplied) > 100:
        raise ProtectionValidationError("Collector blocker metadata is invalid.")
    for item in supplied:
        # Preserve only known codes; never reflect arbitrary messages or secrets.
        code = item.get("code") if type(item) is dict else None
        code = code if type(code) is str and code in _SAFE_COLLECTOR_CODES else "COLLECTOR_HOLD"
        if not any(blocker["code"] == code for blocker in blockers):
            blockers.append(_block(code, "The evidence collector reported an unresolved prerequisite."))
    binding = {key: value for key, value in snapshot.items() if key != "current_ruleset"}
    binding["current_ruleset_sha256"] = fingerprint_ruleset(current)
    plan_digest = _digest({"binding": binding, "payload": payload})
    report = {
        "schema_version": "1.0", "repository": REPOSITORY, "ruleset_id": RULESET_ID,
        "source_app_id": SOURCE_APP_ID, "mode": "live" if live else "offline",
        "input_provenance": "authenticated_live_reads" if live else "unverified_offline_snapshot",
        "status": "HOLD" if blockers else ("READY" if live else "PLAN_ONLY"),
        "exit_code": 20 if blockers else 0, "blockers": blockers,
        "plan_sha256": plan_digest, "payload_sha256": fingerprint_ruleset(payload),
        "current_ruleset_sha256": fingerprint_ruleset(current),
        "write_attempted": False, "write_performed": False, "readback_verified": False,
        "atomic_compare_and_swap": False,
    }
    return payload, report


def _hold(report: dict, code: str, message: str, exit_code: int = 20) -> dict:
    report.update(status="HOLD", exit_code=exit_code)
    report["blockers"].append(_block(code, message))
    return report


def execute_live(
    client: GhClient, root: Path, validation_pr: int, *, apply: bool = False,
    expected_plan_sha256: str | None = None,
) -> tuple[dict, dict]:
    snapshot = collect_live(client, validation_pr, root)
    payload, report = prepare(snapshot, live=True)
    if not apply or report["blockers"]:
        return payload, report
    if (type(expected_plan_sha256) is not str or not _DIGEST.fullmatch(expected_plan_sha256)
            or expected_plan_sha256 != report["plan_sha256"]):
        return payload, _hold(report, "PLAN_DIGEST_MISMATCH", "The freshly collected plan does not match the reviewed digest.")
    if snapshot["live_evidence"]["local_clean"] is not True:
        return payload, _hold(report, "LOCAL_WORKTREE_DIRTY", "Apply requires a clean committed local worktree.")
    refreshed = collect_live(client, validation_pr, root)
    new_payload, new_report = prepare(refreshed, live=True)
    if new_report["blockers"] or new_report["plan_sha256"] != report["plan_sha256"]:
        return payload, _hold(report, "PREWRITE_DRIFT", "Rules, main, test PR, checks or deployment evidence changed before writing.")
    if fingerprint_ruleset(refreshed["current_ruleset"]) == fingerprint_ruleset(new_payload):
        report.update(status="UNCHANGED", readback_verified=True)
        return payload, report
    report["write_attempted"] = True
    # The server may accept a PUT before the response/transport fails. Until
    # acknowledgement, null means unknown; false would incorrectly imply no write.
    report["write_performed"] = None
    try:
        client.request("PUT", _RULESET, new_payload)
        report["write_performed"] = True
        observed = client.request("GET", _RULESET)
        classic = client.request("GET", _PROTECTION)
        if (type(observed) is not dict or observed.get("id") != RULESET_ID
                or fingerprint_ruleset(observed) != fingerprint_ruleset(new_payload)
                or _digest(classic) != _digest(refreshed["branch_protection"])):
            return payload, _hold(report, "READBACK_MISMATCH", "The ruleset or unchanged classic protection could not be verified.", 50)
        report.update(status="APPLIED", readback_verified=True)
        return payload, report
    except Exception:
        return payload, _hold(report, "WRITE_OUTCOME_UNVERIFIED", "A write was attempted but its final outcome is unverified; inspect fresh state.", 50)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", type=Path)
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validation-pr", type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args(argv)
    if args.snapshot and (args.apply or args.expected_plan_sha256 or args.validation_pr is not None):
        parser.error("Offline snapshots cannot authorize live operations.")
    if args.snapshot and args.output is None:
        parser.error("Offline planning requires --output.")
    if args.live and (args.validation_pr is None or args.validation_pr <= 0 or args.validation_pr == BOOTSTRAP_PR):
        parser.error("Live mode requires a separate positive --validation-pr.")
    if args.apply and not args.expected_plan_sha256:
        parser.error("Apply requires the digest from the reviewed live plan.")
    if args.expected_plan_sha256 and not args.apply:
        parser.error("A plan digest is used only together with --apply.")
    output = args.output
    payload = None
    try:
        if args.live:
            payload, report = execute_live(
                GhClient(), Path.cwd(), args.validation_pr, apply=args.apply,
                expected_plan_sha256=args.expected_plan_sha256,
            )
        else:
            payload, report = prepare(read_result(args.snapshot), live=False)
    except (LockdownError, OSError):
        report = {"status": "HOLD", "exit_code": 50, "write_attempted": False,
                  "write_performed": False, "readback_verified": False,
                  "blockers": [_block("EVIDENCE_UNAVAILABLE", "Authenticated evidence or a local prerequisite is unavailable.")]}
    except (InvalidResult, ProtectionValidationError, KeyError, TypeError, ValueError):
        report = {"status": "HOLD", "exit_code": 30, "write_attempted": False,
                  "write_performed": False, "readback_verified": False,
                  "blockers": [_block("INPUT_INVALID", "The supplied evidence is invalid or incomplete.")]}
    try:
        output = output or Path(tempfile.mkdtemp(prefix="sentinel-lockdown-"))
        output.mkdir(parents=True, exist_ok=True)
        if payload is not None:
            write_result(output / "sentinel_lockdown.json", payload)
        write_result(output / "readiness.json", report)
    except (OSError, InvalidResult):
        print(json.dumps({"status": "HOLD", "exit_code": 50, "code": "OUTPUT_UNAVAILABLE",
                          "operation_status": report["status"],
                          **{key: report[key] for key in (
                              "write_attempted", "write_performed", "readback_verified",
                          )}}))
        return 50
    print(json.dumps({key: report[key] for key in ("status", "exit_code", "plan_sha256") if key in report}))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
