"""Pure planning for a guarded update of an existing repository ruleset.

This module never calls GitHub and never treats a plan as an applied protection.
Its caller must obtain snapshots and evidence through authenticated, trusted
reads, bind the repository/ruleset identities, and recheck before any mutation.
Fingerprints use explicit local JSON serialization, not JCS or signatures.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from fnmatch import fnmatchcase
from typing import Any

GUARD_CONTEXT = "Pre-Merge Integrity Guard"
CI_CONTEXT = "SENTINEL Required CI"
_WRITE_FIELDS = ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_RULE_TYPE = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
_MAX_SNAPSHOT_BYTES = 1024 * 1024


class ProtectionValidationError(ValueError):
    """Invalid/incomplete protection input; never contains raw input values."""


def _invalid() -> None:
    raise ProtectionValidationError("Protection snapshot is invalid or incomplete.") from None


def _json_copy(value: Any) -> Any:
    """Require actual JSON types and bounded depth before making a detached copy."""
    def visit(item: Any, depth: int) -> None:
        if depth > 32:
            _invalid()
        kind = type(item)
        if kind is dict:
            if any(type(key) is not str for key in item):
                _invalid()
            for child in item.values():
                visit(child, depth + 1)
        elif kind is list:
            for child in item:
                visit(child, depth + 1)
        elif kind is float:
            if not math.isfinite(item):
                _invalid()
        elif kind not in {str, int, bool, type(None)}:
            _invalid()

    try:
        visit(value, 0)
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)
        if len(encoded) > _MAX_SNAPSHOT_BYTES:
            _invalid()
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError, OverflowError):
        _invalid()


def _text(value: Any, *, maximum: int = 255) -> bool:
    return (
        type(value) is str and 0 < len(value) <= maximum and value == value.strip()
        and value.isprintable()
    )


def _positive_id(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**63


def _source_id(value: Any, *, classic: bool = False) -> int | None:
    if value is None or (classic and type(value) is int and value == -1):
        return None
    if not _positive_id(value):
        _invalid()
    return value


def _add_check(checks: dict[str, int | None], context: str, source: int | None) -> None:
    if context in checks:
        existing = checks[context]
        if existing is not None and source is not None and existing != source:
            # Choosing either known source would silently discard a constraint.
            raise ProtectionValidationError("Required check sources conflict.") from None
        if existing is not None:
            return
    checks[context] = source


def _check_entries(entries: Any, *, classic: bool = False) -> dict[str, int | None]:
    if type(entries) is not list or len(entries) > 1000:
        _invalid()
    sources: dict[str, int | None] = {}
    field = "app_id" if classic else "integration_id"
    for entry in entries:
        if type(entry) is not dict or set(entry) - {"context", field}:
            _invalid()
        context = entry.get("context")
        if not _text(context) or context in sources:
            _invalid()
        sources[context] = _source_id(entry.get(field), classic=classic)
    return sources


def _snapshot(current: Any) -> dict:
    data = _json_copy(current)
    if type(data) is not dict or any(key not in data for key in _WRITE_FIELDS):
        _invalid()
    result = {key: data[key] for key in _WRITE_FIELDS}
    if not _text(result["name"]) or result["target"] != "branch":
        _invalid()
    if (type(result["enforcement"]) is not str
            or result["enforcement"] not in {"active", "evaluate", "disabled"}):
        _invalid()
    if type(result["bypass_actors"]) is not list:
        _invalid()
    conditions = result["conditions"]
    if type(conditions) is not dict or type(conditions.get("ref_name")) is not dict:
        _invalid()
    refs = conditions["ref_name"]
    for key in ("include", "exclude"):
        values = refs.get(key)
        if (type(values) is not list or any(not _text(value) for value in values)
                or len(values) != len(set(values))):
            _invalid()
    if not refs["include"]:
        _invalid()
    # The operation is explicitly for main. Broad wildcard resolution belongs
    # to GitHub; this planner requires a direct main/default-branch selector.
    if not {"refs/heads/main", "~DEFAULT_BRANCH"}.intersection(refs["include"]):
        _invalid()
    # Refuse exclusions that could omit main. fnmatchcase may overmatch slash
    # boundaries compared with GitHub; conservatively refusing that plan is
    # safer than removing an existing condition or claiming it protects main.
    if any(
        selector in {"~DEFAULT_BRANCH", "~ALL"}
        or fnmatchcase("refs/heads/main", selector)
        for selector in refs["exclude"]
    ):
        _invalid()
    rules = result["rules"]
    if type(rules) is not list or len(rules) > 100:
        _invalid()
    seen: set[str] = set()
    for rule in rules:
        if type(rule) is not dict or set(rule) - {"type", "parameters"}:
            _invalid()
        kind = rule.get("type")
        if type(kind) is not str or _RULE_TYPE.fullmatch(kind) is None or kind in seen:
            _invalid()
        seen.add(kind)
        params = rule.get("parameters", {})
        if type(params) is not dict or "require_review_thread_resolution" in params:
            _invalid()
        if kind == "pull_request":
            count = params.get("required_approving_review_count")
            if type(count) is not int or not 0 <= count <= 100:
                _invalid()
            for key in (
                "require_code_owner_review", "require_last_push_approval",
                "dismiss_stale_reviews_on_push", "required_review_thread_resolution",
                "require_extra_approval_for_unattributed_changes",
            ):
                if key in params and type(params[key]) is not bool:
                    _invalid()
        elif kind == "required_status_checks":
            _check_entries(params.get("required_status_checks"))
            for key in ("strict_required_status_checks_policy", "do_not_enforce_on_create"):
                if key in params and type(params[key]) is not bool:
                    _invalid()
    return result


def _classic_checks(protection: Any) -> dict[str, int | None]:
    data = _json_copy(protection)
    if type(data) is not dict or "required_status_checks" not in data:
        _invalid()
    required = data["required_status_checks"]
    if required is None:
        return {}
    if type(required) is not dict or not ({"contexts", "checks"} & set(required)):
        _invalid()
    sources = _check_entries(required.get("checks", []), classic=True)
    contexts = required.get("contexts", [])
    if (type(contexts) is not list or any(not _text(context) for context in contexts)
            or len(contexts) != len(set(contexts))):
        _invalid()
    for context in contexts:
        _add_check(sources, context, None)
    return sources


def build_ruleset_payload(
    current_ruleset: dict, branch_protection: dict, *, source_app_id: int
) -> dict:
    """Build the PUT body for the same ruleset; preserve every existing constraint.

    Metadata such as id/source/timestamps is excluded from the write body. The
    caller binds the unchanged ruleset ID in its URL. Existing ordinary checks
    keep their source; conflicting known sources require human resolution.
    """
    if not _positive_id(source_app_id):
        _invalid()
    payload = _snapshot(current_ruleset)
    rules = {rule["type"]: rule for rule in payload["rules"]}
    for kind in ("deletion", "non_fast_forward"):
        if kind not in rules:
            rules[kind] = {"type": kind}
    pr = rules.setdefault("pull_request", {"type": "pull_request", "parameters": {}})
    params = pr.setdefault("parameters", {})
    params.update({
        "required_approving_review_count": max(1, params.get("required_approving_review_count", 0)),
        "require_code_owner_review": True,
        "require_last_push_approval": True,
        "dismiss_stale_reviews_on_push": True,
        "required_review_thread_resolution": True,
    })
    required = rules.setdefault("required_status_checks", {
        "type": "required_status_checks", "parameters": {},
    })
    check_params = required.setdefault("parameters", {})
    sources = _check_entries(check_params.get("required_status_checks", []))
    for context, source in _classic_checks(branch_protection).items():
        _add_check(sources, context, source)
    for context in (GUARD_CONTEXT, CI_CONTEXT):
        _add_check(sources, context, source_app_id)
    check_params.update({
        "strict_required_status_checks_policy": True,
        "do_not_enforce_on_create": False,
        "required_status_checks": [
            {"context": context, **({"integration_id": source} if source is not None else {})}
            for context, source in sorted(sources.items())
        ],
    })
    payload.update(enforcement="active", bypass_actors=[], rules=list(rules.values()))
    return payload


def fingerprint_ruleset(current: dict) -> str:
    """Fingerprint write-relevant fields for drift detection, not authentication."""
    payload = _snapshot(current)
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_readiness(
    *,
    repository: str,
    bootstrap_pr: dict,
    deployed_files_match: bool,
    guard_check: dict | None,
    ci_check: dict | None,
    current_head_sha: str,
    source_app_id: int,
    independent_codeowner_verified: bool,
) -> list[dict]:
    """Return fixed HOLD reasons; an empty list means the supplied evidence fits.

    Inputs are trusted observations, not PR-supplied attestations. bootstrap_pr
    uses the raw GET /repos/{owner}/{repo}/pulls/{number} response, not a connector
    summary. The caller must separately verify that current_head_sha belongs to
    an open test PR after deployment, and that both checks came from its current
    head and the expected controller/CI execution. This function cannot establish
    that provenance from a pair of arbitrary JSON objects.
    """
    blockers: list[dict] = []

    def block(code: str, message: str) -> None:
        blockers.append({"code": code, "message": message})

    valid_repo = type(repository) is str and _REPOSITORY.fullmatch(repository) is not None
    valid_sha = type(current_head_sha) is str and _SHA.fullmatch(current_head_sha) is not None
    if not valid_repo or not valid_sha or not _positive_id(source_app_id):
        block("INPUT_INVALID", "Expected repository, revision or source identity is invalid.")
        return blockers
    try:
        pr = _json_copy(bootstrap_pr)
    except ProtectionValidationError:
        pr = None
    if type(pr) is not dict:
        block("BOOTSTRAP_INVALID", "A raw authenticated bootstrap PR snapshot is required.")
    else:
        if pr.get("merged") is not True or pr.get("state") != "closed" or pr.get("draft") is not False:
            block("BOOTSTRAP_NOT_MERGED", "The bootstrap PR has not been verified as merged.")
        base, head = pr.get("base"), pr.get("head")
        valid_target = (
            type(base) is dict and base.get("ref") == "main"
            and type(base.get("repo")) is dict
            and base["repo"].get("full_name") == repository
            and type(head) is dict and type(head.get("repo")) is dict
            and head["repo"].get("full_name") == repository
            and type(head.get("sha")) is str and _SHA.fullmatch(head["sha"]) is not None
        )
        if not valid_target:
            block("BOOTSTRAP_TARGET_INVALID", "Bootstrap identity does not match the intended repository.")
        elif current_head_sha == head["sha"]:
            block("BOOTSTRAP_REVISION_REUSED", "The bootstrap revision cannot be its own activation test.")
        merge_sha = pr.get("merge_commit_sha")
        if pr.get("merged") is True and (
            type(merge_sha) is not str or _SHA.fullmatch(merge_sha) is None
        ):
            block("MERGE_RECEIPT_INVALID", "A concrete merged revision is required.")
        elif merge_sha == current_head_sha:
            block("BOOTSTRAP_REVISION_REUSED", "A separate post-bootstrap test PR is required.")
    if deployed_files_match is not True:
        block("DEPLOYMENT_NOT_VERIFIED", "Protected-base files do not match the reviewed implementation.")
    if independent_codeowner_verified is not True:
        block("INDEPENDENT_CODEOWNER_REQUIRED", "An eligible independent code owner must be verified.")
    for prefix, name, check in (
        ("GUARD", GUARD_CONTEXT, guard_check), ("CI", CI_CONTEXT, ci_check),
    ):
        if check is None:
            block(prefix + "_CHECK_MISSING", "A required current-revision check has not been observed.")
            continue
        try:
            checked = _json_copy(check)
        except ProtectionValidationError:
            checked = None
        if (
            type(checked) is not dict or checked.get("name") != name
            or checked.get("head_sha") != current_head_sha
            or type(checked.get("app")) is not dict
            or not _positive_id(checked["app"].get("id"))
            or checked["app"]["id"] != source_app_id
        ):
            block(prefix + "_CHECK_IDENTITY_INVALID", "A check is not bound to the expected revision and source.")
        elif checked.get("status") != "completed" or checked.get("conclusion") != "success":
            block(prefix + "_CHECK_NOT_SUCCESSFUL", "A required check did not explicitly complete successfully.")
    return blockers
